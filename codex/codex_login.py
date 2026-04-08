import atexit
import base64
import hashlib
import imaplib
import json
import os
import random
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import uuid
import email as email_lib
from datetime import datetime, timedelta, timezone
from email.header import decode_header
from urllib.parse import quote, urlparse, parse_qs, urlencode

from curl_cffi import requests as curl_requests

AUTH = "https://auth.openai.com"
SENTINEL = "https://sentinel.openai.com"

CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_REDIRECT_URI = "http://localhost:1455/auth/callback"
CODEX_SCOPE = "openid email profile offline_access"

DEFAULT_CONFIG = {
    "proxy": "",
    "max_workers": 1,
    "outlook_input_file": "emails.txt",
    "output_dir": "output",
}

_CHROME_PROFILES = [
    {
        "major": 136,
        "impersonate": "chrome136",
        "build": 7103,
        "patch_range": (48, 175),
        "brands": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    },
    {
        "major": 133,
        "impersonate": "chrome133a",
        "build": 7000,
        "patch_range": (30, 150),
        "brands": '"Chromium";v="133", "Google Chrome";v="133", "Not_A Brand";v="99"',
    },
]

_print_lock = threading.Lock()
_file_lock = threading.Lock()
_proxy_chain_lock = threading.Lock()
_proxy_chain_map = {}


def _safe_print(msg: str):
    with _print_lock:
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            print(f"[{ts}] {msg}")
        except UnicodeEncodeError:
            print(f"[{ts}] {msg.encode('utf-8', errors='replace').decode('utf-8')}", file=sys.stderr)


def mask_proxy(proxy: str) -> str:
    if not proxy:
        return ""
    try:
        p = urlparse(proxy)
        if p.username is None and p.password is None:
            return proxy
        host = p.hostname or ""
        if p.port:
            host = f"{host}:{p.port}"
        safe_user = (p.username[:2] + "***") if p.username and len(p.username) > 2 else ("***" if p.username else "")
        auth = f"{safe_user}:***@" if safe_user else ""
        return f"{p.scheme}://{auth}{host}"
    except Exception:
        return proxy


def _wait_port_ready(port: int, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def detect_local_proxy() -> str:
    candidates = [
        ("socks5://127.0.0.1:10808", 10808),
        ("http://127.0.0.1:10809", 10809),
        ("http://127.0.0.1:7890", 7890),
        ("http://127.0.0.1:7897", 7897),
    ]
    for url, port in candidates:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return url
        except OSError:
            continue
    return ""


def parse_proxy_url(raw_proxy: str) -> dict:
    value = (raw_proxy or "").strip()
    if not value:
        return {"protocol": "", "host": "", "port": 0, "username": "", "password": "", "url": ""}

    if "://" in value:
        p = urlparse(value)
        return {
            "protocol": p.scheme.lower(),
            "host": p.hostname or "",
            "port": p.port or 0,
            "username": p.username or "",
            "password": p.password or "",
            "url": value,
        }

    parts = value.split(":")
    port_idx = -1
    for i in range(1, len(parts)):
        if parts[i].isdigit():
            port_idx = i
            break
    if port_idx <= 0:
        return {"protocol": "http", "host": value, "port": 0, "username": "", "password": "", "url": f"http://{value}"}

    host = ":".join(parts[:port_idx])
    port = int(parts[port_idx])
    rest = parts[port_idx + 1:]
    username = rest[0] if len(rest) >= 1 else ""
    password = ":".join(rest[1:]) if len(rest) >= 2 else ""
    auth = f"{quote(username, safe='')}:{quote(password, safe='')}@" if username else ""
    return {
        "protocol": "http",
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "url": f"http://{auth}{host}:{port}",
    }


def _detect_proxy_protocol(parsed: dict, timeout: float = 6.0) -> str:
    """通过代理链（本地代理 -> 上游）探测上游代理的协议类型"""
    host, port = parsed["host"], parsed["port"]
    user, pwd = parsed["username"], parsed["password"]
    auth = f"{quote(user, safe='')}:{quote(pwd, safe='')}@" if user else ""

    local_upstream = detect_local_proxy()
    xray_exe = _find_xray_exe() if local_upstream else ""

    for proto in ("socks5", "http"):
        test_url = f"{proto}://{auth}{host}:{port}"

        # 如果有本地代理和 xray，通过代理链测试（还原真实链路）
        if local_upstream and xray_exe:
            test_port = random.randint(20000, 29999)
            parsed_local = parse_proxy_url(local_upstream)
            xray_config = {
                "log": {"loglevel": "warning"},
                "inbounds": [{"port": test_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}],
                "outbounds": [
                    {
                        "tag": "to_upstream",
                        "protocol": proto,
                        "settings": {"servers": [{
                            "address": host, "port": port,
                            **({"users": [{"user": user, "pass": pwd}]} if user else {}),
                        }]},
                        "proxySettings": {"tag": "to_local"},
                    },
                    {
                        "tag": "to_local",
                        "protocol": "socks" if parsed_local["protocol"].startswith("socks") else "http",
                        "settings": {"servers": [{"address": parsed_local["host"], "port": parsed_local["port"]}]},
                    },
                ],
                "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"type": "field", "outboundTag": "to_upstream", "port": "0-65535"}]},
            }
            base_dir = os.path.dirname(os.path.abspath(__file__))
            chain_dir = os.path.join(base_dir, "output", "proxy-chains")
            os.makedirs(chain_dir, exist_ok=True)
            config_path = os.path.join(chain_dir, f"detect_{test_port}.json")
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(xray_config, f, ensure_ascii=False)
            try:
                proc = subprocess.Popen(
                    [xray_exe, "run", "-c", config_path],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                )
                if _wait_port_ready(test_port, timeout=5.0):
                    try:
                        r = curl_requests.get(
                            "https://httpbin.org/ip",
                            proxy=f"socks5://127.0.0.1:{test_port}",
                            timeout=timeout,
                            impersonate="chrome136",
                        )
                        if r.status_code == 200:
                            _safe_print(f"[Proxy] 自动识别成功 (代理链): {proto}://{host}:{port}")
                            proc.kill()
                            try: os.remove(config_path)
                            except Exception: pass
                            return test_url
                        _safe_print(f"[Proxy] 探测失败 (代理链): {proto}://{host}:{port} -> HTTP {r.status_code}")
                    except Exception as e:
                        _safe_print(f"[Proxy] 探测失败 (代理链): {proto}://{host}:{port} -> {str(e)[:100]}")
                proc.kill()
            except Exception:
                pass
            try: os.remove(config_path)
            except Exception: pass
        else:
            # 无本地代理，直连探测
            try:
                r = curl_requests.get(
                    "https://httpbin.org/ip",
                    proxy=test_url,
                    timeout=timeout,
                    impersonate="chrome136",
                )
                if r.status_code == 200:
                    _safe_print(f"[Proxy] 自动识别成功: {proto}://{host}:{port}")
                    return test_url
                _safe_print(f"[Proxy] 探测失败: {proto}://{host}:{port} -> HTTP {r.status_code}")
            except Exception as e:
                _safe_print(f"[Proxy] 探测失败: {proto}://{host}:{port} -> {str(e)[:100]}")

    _safe_print(f"[Proxy] 自动识别失败，回退默认 socks5://{host}:{port}")
    # 回退 socks5 而非 http，因为多数住宅代理是 socks5
    return f"socks5://{auth}{host}:{port}"


def _find_xray_exe() -> str:
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "xray.exe"),
        "F:/geekz/GeekEZ Browser/resources/bin/win32-x64/xray.exe",
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return ""


def _cleanup_proxy_chains():
    with _proxy_chain_lock:
        items = list(_proxy_chain_map.items())
        _proxy_chain_map.clear()
    for _, info in items:
        proc = info.get("process")
        config_path = info.get("config_path")
        try:
            if proc and proc.poll() is None:
                proc.kill()
        except Exception:
            pass
        try:
            if config_path and os.path.exists(config_path):
                os.remove(config_path)
        except Exception:
            pass


atexit.register(_cleanup_proxy_chains)


def ensure_proxy_chain(proxy: str) -> str:
    if not proxy:
        return proxy
    proxy = proxy.strip()
    if not proxy or "127.0.0.1" in proxy or "localhost" in proxy:
        return proxy

    with _proxy_chain_lock:
        cached = _proxy_chain_map.get(proxy)
        if cached and _wait_port_ready(cached["port"], timeout=1.0):
            local_proxy = f"socks5://127.0.0.1:{cached['port']}"
            _safe_print(f"[ProxyChain] 复用链路: {mask_proxy(proxy)} -> {local_proxy}")
            return local_proxy

    local_upstream = detect_local_proxy()
    if not local_upstream:
        _safe_print(f"[ProxyChain] 未检测到本地代理，直接使用: {mask_proxy(proxy)}")
        return proxy

    xray_exe = _find_xray_exe()
    if not xray_exe:
        _safe_print(f"[ProxyChain] 未找到 xray.exe，直接使用: {mask_proxy(proxy)}")
        return proxy

    parsed_proxy = parse_proxy_url(proxy)
    parsed_local = parse_proxy_url(local_upstream)
    if not parsed_proxy["host"] or not parsed_proxy["port"] or not parsed_local["host"] or not parsed_local["port"]:
        _safe_print(f"[ProxyChain] 代理解析失败，直接使用: {mask_proxy(proxy)}")
        return proxy

    chain_port = random.randint(20000, 29999)
    xray_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"port": chain_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [
            {
                "tag": "to_upstream",
                "protocol": "socks" if parsed_proxy["protocol"].startswith("socks") else "http",
                "settings": {"servers": [{
                    "address": parsed_proxy["host"],
                    "port": parsed_proxy["port"],
                    **({"users": [{"user": parsed_proxy["username"], "pass": parsed_proxy["password"]}]} if parsed_proxy["username"] else {}),
                }]},
                "proxySettings": {"tag": "to_local"},
            },
            {
                "tag": "to_local",
                "protocol": "socks" if parsed_local["protocol"].startswith("socks") else "http",
                "settings": {"servers": [{"address": parsed_local["host"], "port": parsed_local["port"]}]},
            },
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"type": "field", "outboundTag": "to_upstream", "port": "0-65535"}]},
    }

    base_dir = os.path.dirname(os.path.abspath(__file__))
    chain_dir = os.path.join(base_dir, "output", "proxy-chains")
    os.makedirs(chain_dir, exist_ok=True)
    config_path = os.path.join(chain_dir, f"chain_{chain_port}.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(xray_config, f, ensure_ascii=False)

    try:
        proc = subprocess.Popen(
            [xray_exe, "run", "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
    except Exception as e:
        _safe_print(f"[ProxyChain] xray 启动失败，直接使用 {mask_proxy(proxy)}: {e}")
        return proxy

    if _wait_port_ready(chain_port, timeout=8.0):
        local_proxy = f"socks5://127.0.0.1:{chain_port}"
        with _proxy_chain_lock:
            _proxy_chain_map[proxy] = {"port": chain_port, "process": proc, "config_path": config_path}
        _safe_print(f"[ProxyChain] 链路就绪: {local_proxy} -> {local_upstream} -> {mask_proxy(proxy)}")
        return local_proxy

    _safe_print(f"[ProxyChain] 链路启动超时，直接使用: {mask_proxy(proxy)}")
    try:
        proc.kill()
    except Exception:
        pass
    return proxy


def generate_pkce() -> tuple:
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class Fingerprint:
    def __init__(self):
        profile = random.choice(_CHROME_PROFILES)
        self.major = profile["major"]
        self.impersonate = profile["impersonate"]
        build = profile["build"]
        patch = random.randint(*profile["patch_range"])
        self.chrome_full = f"{self.major}.0.{build}.{patch}"
        self.user_agent = (
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            f"AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Chrome/{self.chrome_full} Safari/537.36"
        )
        self.sec_ch_ua = profile["brands"]
        self.sec_ch_ua_mobile = "?0"
        self.sec_ch_ua_platform = '"Windows"'
        self.device_id = str(uuid.uuid4())

    def headers(self) -> dict:
        return {
            "User-Agent": self.user_agent,
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": self.sec_ch_ua_mobile,
            "sec-ch-ua-platform": self.sec_ch_ua_platform,
        }


class SentinelToken:
    MAX_ATTEMPTS = 500_000

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= (h >> 16)
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= (h >> 13)
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= (h >> 16)
        h &= 0xFFFFFFFF
        return format(h, "08x")

    @staticmethod
    def _base64_encode(data) -> str:
        raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    @classmethod
    def _get_config(cls, fp: Fingerprint) -> list:
        now_str = time.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)", time.gmtime())
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        nav_props = ["vendorSub", "productSub", "vendor", "maxTouchPoints", "hardwareConcurrency", "cookieEnabled"]
        screen = random.choice([(1920, 1080), (1536, 864), (1440, 900), (2560, 1440)])
        return [
            f"{screen[0]}x{screen[1]}", now_str, 4294705152, random.random(),
            fp.user_agent, "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
            None, None, "en-US", "en-US,en", random.random(),
            f"{random.choice(nav_props)}-undefined",
            random.choice(["location", "URL", "documentURI"]),
            random.choice(["Object", "Function", "Array"]),
            perf_now, str(uuid.uuid4()), "", random.choice([4, 8, 12, 16]), time_origin,
        ]

    @classmethod
    def generate_requirements_token(cls, fp: Fingerprint) -> str:
        config = cls._get_config(fp)
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + cls._base64_encode(config)

    @classmethod
    def generate_pow_token(cls, fp: Fingerprint, seed: str, difficulty: str = "0") -> str:
        config = cls._get_config(fp)
        start_time = time.time()
        for i in range(cls.MAX_ATTEMPTS):
            config[3] = i
            config[9] = round((time.time() - start_time) * 1000)
            data = cls._base64_encode(config)
            hash_hex = cls._fnv1a_32(seed + data)
            if hash_hex[:len(difficulty)] <= difficulty:
                return "gAAAAAB" + data + "~S"
        return "gAAAAAB" + cls._base64_encode(str(None))


def fetch_sentinel_token(session, fp: Fingerprint, flow: str, log_fn=None) -> str:
    _log = log_fn or _safe_print
    req_body = {"p": SentinelToken.generate_requirements_token(fp), "id": fp.device_id, "flow": flow}
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": f"{SENTINEL}/backend-api/sentinel/frame.html",
        "Origin": SENTINEL,
    }
    headers.update(fp.headers())
    try:
        resp = session.post(
            f"{SENTINEL}/backend-api/sentinel/req",
            data=json.dumps(req_body),
            headers=headers,
            timeout=20,
            impersonate=fp.impersonate,
        )
        if resp.status_code != 200:
            _log(f"  Sentinel req -> {resp.status_code}")
            return None
        challenge = resp.json()
    except Exception as e:
        _log(f"  Sentinel req 异常: {e}")
        return None

    c_value = challenge.get("token", "")
    pow_data = challenge.get("proofofwork") or {}
    if pow_data.get("required") and pow_data.get("seed"):
        p_value = SentinelToken.generate_pow_token(fp, seed=pow_data["seed"], difficulty=str(pow_data.get("difficulty", "0")))
    else:
        p_value = SentinelToken.generate_requirements_token(fp)
    return json.dumps({"p": p_value, "t": "", "c": c_value, "id": fp.device_id, "flow": flow}, separators=(",", ":"))


def _get_imap_access_token(client_id: str, refresh_token: str, impersonate: str = "chrome131"):
    methods = [
        {
            "url": "https://login.live.com/oauth20_token.srf",
            "data": {"client_id": client_id, "grant_type": "refresh_token", "refresh_token": refresh_token},
            "imap_server": "outlook.office365.com",
        },
        {
            "url": "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
            "data": {
                "client_id": client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
            },
            "imap_server": "outlook.live.com",
        },
    ]
    last_error = ""
    for method in methods:
        try:
            r = curl_requests.post(
                method["url"],
                data=method["data"],
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30,
                impersonate=impersonate,
            )
            resp = r.json()
            token = resp.get("access_token")
            if token:
                return token, method["imap_server"]
            last_error = resp.get("error_description", resp.get("error", str(resp)))
        except Exception as e:
            last_error = str(e)
    raise Exception(f"IMAP access token 获取失败: {last_error[:150]}")


def _imap_connect(email_addr, access_token, imap_server):
    imap = imaplib.IMAP4_SSL(imap_server, 993)
    auth_string = f"user={email_addr}\x01auth=Bearer {access_token}\x01\x01"
    imap.authenticate("XOAUTH2", lambda x: auth_string.encode("utf-8"))
    return imap


def _get_openai_mail_ids(imap) -> set:
    imap.select("INBOX")
    all_ids = set()
    for sender in ('(FROM "noreply@tm.openai.com")', '(FROM "openai.com")'):
        try:
            status, msg_ids = imap.search(None, sender)
            if status == "OK" and msg_ids[0]:
                all_ids.update(msg_ids[0].split())
        except Exception:
            pass
    return all_ids


def _extract_otp_from_mail(imap, mid) -> tuple:
    status, msg_data = imap.fetch(mid, "(RFC822)")
    if status != "OK":
        return None, None

    raw_email = msg_data[0][1]
    msg = email_lib.message_from_bytes(raw_email)

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                try:
                    charset = part.get_content_charset() or "utf-8"
                    body += part.get_payload(decode=True).decode(charset, errors="ignore")
                except Exception:
                    body += str(part.get_payload(decode=True))
    else:
        try:
            charset = msg.get_content_charset() or "utf-8"
            body = msg.get_payload(decode=True).decode(charset, errors="ignore")
        except Exception:
            body = str(msg.get_payload(decode=True))

    subject = ""
    raw_subject = msg.get("Subject", "")
    if raw_subject:
        decoded = decode_header(raw_subject)
        subject = "".join(part.decode(enc or "utf-8") if isinstance(part, bytes) else part for part, enc in decoded)

    text_lower = (subject + " " + body[:2000]).lower()
    otp_keywords = ["verification", "verify", "code", "otp", "验证", "login", "sign in", "sign-in", "one-time"]
    invite_keywords = ["invite", "invitation", "join", "team", "workspace", "accepted", "welcome to"]
    is_otp_mail = any(kw in text_lower for kw in otp_keywords)
    is_invite_mail = any(kw in text_lower for kw in invite_keywords)
    if is_invite_mail and not is_otp_mail:
        return None, subject

    patterns = [r'>\s*(\d{6})\s*<', r'(\d{6})\s*\n', r'code[:\s]+(\d{6})', r'verify.*?(\d{6})', r'(\d{6})']
    for pattern in patterns:
        match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1), subject
    return None, subject


def get_known_mail_ids(email_addr, client_id, refresh_token, impersonate="chrome131", log_fn=None):
    try:
        access_token, imap_server = _get_imap_access_token(client_id, refresh_token, impersonate)
        imap = _imap_connect(email_addr, access_token, imap_server)
        try:
            known = _get_openai_mail_ids(imap)
            if log_fn:
                log_fn(f"[OTP] 已有 {len(known)} 封 OpenAI 邮件 (标记为旧邮件)")
            return known
        finally:
            try:
                imap.logout()
            except Exception:
                pass
    except Exception as e:
        if log_fn:
            log_fn(f"[OTP] 获取旧邮件 ID 失败: {e}")
        return set()


def fetch_otp(email_addr, client_id, refresh_token, known_ids=None, timeout=120, impersonate="chrome131", log_fn=None) -> str:
    try:
        access_token, imap_server = _get_imap_access_token(client_id, refresh_token, impersonate)
    except Exception as e:
        if log_fn:
            log_fn(f"[OTP] access token 失败: {e}")
        return None

    if known_ids is None:
        known_ids = set()
    if log_fn:
        log_fn(f"[OTP] 轮询收件箱 (最多 {timeout}s, 过滤 {len(known_ids)} 封旧邮件)...")

    start_time = time.time()
    check_count = 0
    fallback_tried = False
    while time.time() - start_time < timeout:
        check_count += 1
        elapsed = int(time.time() - start_time)
        try:
            imap = _imap_connect(email_addr, access_token, imap_server)
            try:
                all_ids = _get_openai_mail_ids(imap)
                new_ids = all_ids - known_ids
                if new_ids:
                    sorted_new = sorted(new_ids, key=lambda x: int(x), reverse=True)
                    for mid in sorted_new:
                        otp, subject = _extract_otp_from_mail(imap, mid)
                        if otp:
                            if log_fn:
                                log_fn(f"[OTP] ✅ 验证码: {otp} (主题: {subject})")
                            return otp
                if not fallback_tried and elapsed >= 50 and known_ids:
                    fallback_tried = True
                    if log_fn:
                        log_fn("[OTP] 50s 无新邮件, 回退尝试已有邮件中最新一封...")
                    sorted_known = sorted(known_ids, key=lambda x: int(x), reverse=True)
                    for mid in sorted_known[:3]:
                        otp, subject = _extract_otp_from_mail(imap, mid)
                        if otp:
                            if log_fn:
                                log_fn(f"[OTP] ✅ 验证码 (回退): {otp} (主题: {subject})")
                            return otp
            finally:
                try:
                    imap.logout()
                except Exception:
                    pass
        except Exception as e:
            if log_fn:
                log_fn(f"[OTP] IMAP 轮询出错: {e}")
        if log_fn:
            log_fn(f"[OTP] 第 {check_count} 次, 无新验证码 ({elapsed}s/{timeout}s)")
        time.sleep(3)

    if log_fn:
        log_fn(f"[OTP] ⚠️ 超时 ({timeout}s)")
    return None


def decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


class CodexLogin:
    def __init__(self, email: str, proxy: str = None, tag: str = ""):
        self.email = email
        self.tag = tag or email.split("@")[0]
        self.fp = Fingerprint()
        self.session = curl_requests.Session()
        if proxy:
            self.session.proxies = {"https": proxy, "http": proxy}
        self.code_verifier, self.code_challenge = generate_pkce()
        self.state = secrets.token_hex(16)
        self._login_challenge = None
        self._login_verifier = None
        self._auth_code = None
        self._sentinel_token_1 = None

    def _log(self, msg):
        _safe_print(f"[{self.tag}] {msg}")

    def _delay(self, lo=0.3, hi=1.0):
        time.sleep(random.uniform(lo, hi))

    def step1_oauth_init(self):
        self._log("[Step 1] OAuth 初始化...")
        params = {
            "client_id": CODEX_CLIENT_ID,
            "code_challenge": self.code_challenge,
            "code_challenge_method": "S256",
            "codex_cli_simplified_flow": "true",
            "id_token_add_organizations": "true",
            "prompt": "login",
            "redirect_uri": CODEX_REDIRECT_URI,
            "response_type": "code",
            "scope": CODEX_SCOPE,
            "state": self.state,
        }
        url = f"{AUTH}/oauth/authorize"
        for step in range(5):
            r = self.session.get(
                url,
                params=params if step == 0 else None,
                headers={"Accept": "text/html,*/*;q=0.8", "User-Agent": self.fp.user_agent},
                allow_redirects=False,
                impersonate=self.fp.impersonate,
            )
            self._log(f"  [{step}] {r.status_code} {urlparse(url).path}")
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("location", "")
                if "login_challenge=" in location:
                    m = re.search(r"login_challenge=([^&]+)", location)
                    if m:
                        self._login_challenge = m.group(1)
                        self._log("  login_challenge 提取成功")
                if location.startswith("/"):
                    p = urlparse(url)
                    location = f"{p.scheme}://{p.netloc}{location}"
                url = location
                params = None
            else:
                break
        self._delay(1.0, 2.0)

    def step2_sentinel_probe(self):
        self._log("[Step 2] Sentinel 风控探针 #1...")
        self._sentinel_token_1 = fetch_sentinel_token(self.session, self.fp, "login_passwordless", self._log)
        self._log("  Sentinel #1 " + ("OK" if self._sentinel_token_1 else "⚠️ 失败"))
        self._delay(0.5, 1.5)

    def step3_authorize_continue(self) -> bool:
        self._log("[Step 3] authorize/continue 提交邮箱...")
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Origin": AUTH, "Referer": f"{AUTH}/log-in"}
        headers.update(self.fp.headers())
        if self._sentinel_token_1:
            headers["openai-sentinel-token"] = self._sentinel_token_1

        r = self.session.post(
            f"{AUTH}/api/accounts/authorize/continue",
            json={"username": {"kind": "email", "value": self.email}},
            headers=headers, timeout=30, impersonate=self.fp.impersonate)
        self._log(f"  authorize/continue -> {r.status_code}")
        if r.status_code != 200:
            self._log(f"  ⚠️ 失败: {r.text[:300]}")
            return False
        try:
            data = r.json()
            self._log(f"  响应: {json.dumps(data, ensure_ascii=False)[:200]}")
        except Exception:
            pass
        self._delay(0.5, 1.0)
        return True

    def step4_sentinel_probe2(self):
        self._log("[Step 4] Sentinel 风控探针 #2...")
        self._sentinel_token_2 = fetch_sentinel_token(
            self.session, self.fp, "login_passwordless", self._log)
        self._log("  Sentinel #2 " + ("OK" if self._sentinel_token_2 else "⚠️ 失败"))
        self._delay(0.3, 0.8)

    def step5_send_otp(self) -> bool:
        self._log("[Step 5] 发送 OTP (passwordless)...")
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Origin": AUTH, "Referer": f"{AUTH}/log-in"}
        headers.update(self.fp.headers())
        if self._sentinel_token_2:
            headers["openai-sentinel-token"] = self._sentinel_token_2

        r = self.session.post(
            f"{AUTH}/api/accounts/passwordless/send-otp",
            json={}, headers=headers, timeout=30, impersonate=self.fp.impersonate)
        self._log(f"  send-otp -> {r.status_code}")
        if r.status_code != 200:
            self._log(f"  ⚠️ 失败: {r.text[:200]}")
            return False
        return True

    def step6_validate_otp(self, code: str) -> bool:
        self._log(f"[Step 6] 验证 OTP: {code}")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": AUTH,
            "Referer": f"{AUTH}/email-verification",
        }
        headers.update(self.fp.headers())
        r = self.session.post(
            f"{AUTH}/api/accounts/email-otp/validate",
            json={"code": code},
            headers=headers,
            timeout=30,
            impersonate=self.fp.impersonate,
        )
        self._log(f"  validate-otp -> {r.status_code}")
        if r.status_code != 200:
            self._log(f"  ⚠️ 验证失败: {r.text[:200]}")
            return False

        try:
            data = r.json()
            self._log(f"  响应: {json.dumps(data, ensure_ascii=False)[:300]}")
            self._consent_url = data.get("continue_url", "")
        except Exception:
            self._consent_url = ""
        return True

    # ── Step 6b: 完善个人资料 (about-you) ──
    def step6b_about_you(self) -> bool:
        consent_url = getattr(self, "_consent_url", "") or ""
        if "about-you" not in consent_url and "about_you" not in consent_url:
            return True

        self._log("[Step 6b] 完善个人资料 (about-you)...")

        name_part = self.email.split("@")[0]
        name_clean = re.sub(r'\d+$', '', name_part)
        parts = re.findall(r'[A-Z][a-z]+', name_clean)
        if len(parts) >= 2:
            full_name = f"{parts[0]} {parts[1]}"
        elif parts:
            full_name = f"{parts[0]} Smith"
        else:
            full_name = f"{name_clean} Smith"

        age = random.randint(20, 35)
        birth_year = datetime.now().year - age
        birth_month = random.randint(1, 12)
        birth_day = random.randint(1, 28)
        birthdate = f"{birth_year}-{birth_month:02d}-{birth_day:02d}"

        self._log(f"  姓名: {full_name}, 生日: {birthdate}")

        sentinel = fetch_sentinel_token(
            self.session, self.fp, "oauth_create_account", self._log)

        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Origin": AUTH, "Referer": f"{AUTH}/about-you"}
        headers.update(self.fp.headers())
        if sentinel:
            headers["openai-sentinel-token"] = sentinel

        r = self.session.post(
            f"{AUTH}/api/accounts/create_account",
            json={"name": full_name, "birthdate": birthdate},
            headers=headers, timeout=30, impersonate=self.fp.impersonate)
        self._log(f"  create_account -> {r.status_code}")

        if r.status_code != 200:
            # user_already_exists 不算真正失败，账号已创建过
            try:
                err_code = r.json().get("error", {}).get("code", "")
            except Exception:
                err_code = ""
            if err_code == "user_already_exists":
                self._log("  账号已存在，跳过 create_account")
                return True
            self._log(f"  ⚠️ 失败: {r.text[:300]}")
            return False

        try:
            data = r.json()
            self._log(f"  响应: {json.dumps(data, ensure_ascii=False)[:300]}")
            new_url = data.get("continue_url", "")
            if new_url:
                self._consent_url = new_url
        except Exception:
            pass

        consent_url = getattr(self, "_consent_url", "") or ""
        self._log(f"  about-you 后 continue_url: {consent_url[:200]}")

        # 从 continue_url 中提取 login_verifier
        lv = re.search(r'login_verifier=([A-Za-z0-9_\-]{20,})', consent_url)
        if lv:
            self._login_verifier = lv.group(1)
            self._log(f"  ✅ login_verifier 从 continue_url 提取!")

        # add-phone 页面：GET 它然后跳过，获取下一步 URL
        if "add-phone" in consent_url:
            self._log("  检测到 add-phone, 尝试跳过...")
            try:
                r_phone = self.session.get(
                    consent_url,
                    headers={"Accept": "text/html,*/*;q=0.8", "User-Agent": self.fp.user_agent},
                    timeout=30, impersonate=self.fp.impersonate, allow_redirects=False)
                self._log(f"  add-phone GET -> {r_phone.status_code}")
                if r_phone.status_code in (301, 302, 303, 307, 308):
                    loc = r_phone.headers.get("location", "")
                    if loc:
                        if loc.startswith("/"):
                            loc = f"{AUTH}{loc}"
                        self._consent_url = loc
                        self._log(f"  add-phone 重定向 → {loc[:150]}")
                else:
                    # 尝试 POST skip
                    r_skip = self.session.post(
                        f"{AUTH}/api/accounts/phone/skip",
                        json={},
                        headers={"Content-Type": "application/json", "Accept": "application/json",
                                 "Origin": AUTH, "Referer": consent_url,
                                 "User-Agent": self.fp.user_agent},
                        timeout=15, impersonate=self.fp.impersonate)
                    self._log(f"  phone/skip -> {r_skip.status_code}: {r_skip.text[:300]}")
                    try:
                        skip_data = r_skip.json()
                        skip_url = skip_data.get("continue_url", "")
                        if skip_url:
                            self._consent_url = skip_url
                            self._log(f"  skip 后 continue_url: {skip_url[:150]}")
                            lv2 = re.search(r'login_verifier=([A-Za-z0-9_\-]{20,})', skip_url)
                            if lv2:
                                self._login_verifier = lv2.group(1)
                                self._log(f"  ✅ login_verifier 从 skip 提取!")
                    except Exception:
                        pass
                    if not getattr(self, "_login_verifier", None):
                        self._consent_url = f"{AUTH}/sign-in-with-chatgpt/codex/consent"
            except Exception as e:
                self._log(f"  add-phone 处理异常: {e}")
                self._consent_url = f"{AUTH}/sign-in-with-chatgpt/codex/consent"

        self._delay(0.5, 1.0)
        return True

    # ── 静默重登录：create_account 后清 cookie，用密码重新登录拿 token ──
    def relogin_with_password(self, password: str, client_id: str = "", ms_refresh_token: str = "", _depth: int = 0) -> dict:
        """注册完成后，清除 cookie 重新用密码登录，绕过 add-phone 等中间步骤，直接拿 token"""
        self._log(f"[Relogin] 静默重登录...{' (第%d次重试)' % _depth if _depth else ''}")

        # 1. 清除 cookies，重新生成 PKCE
        self.session.cookies.clear()
        self.code_verifier, self.code_challenge = generate_pkce()
        self.state = secrets.token_hex(16)
        self._login_verifier = None
        self._auth_code = None

        # 2. 重新 OAuth 初始化
        self._log("[Relogin] 重新 OAuth 初始化...")
        params = {
            "client_id": CODEX_CLIENT_ID,
            "code_challenge": self.code_challenge,
            "code_challenge_method": "S256",
            "codex_cli_simplified_flow": "true",
            "id_token_add_organizations": "true",
            "prompt": "login",
            "redirect_uri": CODEX_REDIRECT_URI,
            "response_type": "code",
            "scope": CODEX_SCOPE,
            "state": self.state,
        }
        url = f"{AUTH}/oauth/authorize"
        for step in range(5):
            r = self.session.get(
                url,
                params=params if step == 0 else None,
                headers={"Accept": "text/html,*/*;q=0.8", "User-Agent": self.fp.user_agent},
                allow_redirects=False,
                impersonate=self.fp.impersonate,
            )
            self._log(f"  [init-{step}] {r.status_code} {urlparse(url).path}")
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("location", "")
                if location.startswith("/"):
                    p = urlparse(url)
                    location = f"{p.scheme}://{p.netloc}{location}"
                url = location
                params = None
            else:
                break
        self._delay(0.5, 1.0)

        # 3. Sentinel for authorize_continue
        self._log("[Relogin] Sentinel #2...")
        sentinel2 = fetch_sentinel_token(self.session, self.fp, "authorize_continue", self._log)
        self._log("  Sentinel #2 " + ("OK" if sentinel2 else "⚠️ 失败"))

        # 4. authorize/continue (login)
        self._log("[Relogin] authorize/continue (login)...")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": AUTH,
        }
        headers.update(self.fp.headers())
        if sentinel2:
            headers["openai-sentinel-token"] = sentinel2
        r = self.session.post(
            f"{AUTH}/api/accounts/authorize/continue",
            json={"username": {"value": self.email, "kind": "email"}, "screen_hint": "login"},
            headers=headers, timeout=30, impersonate=self.fp.impersonate,
        )
        self._log(f"  authorize/continue -> {r.status_code}")

        # 5. 密码登录前先快照已有邮件（为二次 OTP 做准备）
        known_ids_before_pwd = set()
        if client_id and ms_refresh_token:
            known_ids_before_pwd = get_known_mail_ids(
                self.email, client_id, ms_refresh_token,
                impersonate=self.fp.impersonate, log_fn=self._log,
            )

        self._log("[Relogin] 密码验证...")
        headers2 = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": AUTH,
        }
        headers2.update(self.fp.headers())
        if sentinel2:
            headers2["openai-sentinel-token"] = sentinel2
        r = self.session.post(
            f"{AUTH}/api/accounts/password/verify",
            json={"password": password},
            headers=headers2, timeout=30, impersonate=self.fp.impersonate,
        )
        self._log(f"  password/verify -> {r.status_code}")
        if r.status_code != 200:
            self._log(f"  ⚠️ 密码登录失败: {r.text[:300]}")
            return None

        # 检查是否触发二次 OTP
        try:
            pwd_json = r.json()
            pwd_page = (pwd_json.get("page") or {}).get("type", "")
            if "otp" in pwd_page or "verify" in str(pwd_json.get("continue_url", "")):
                self._log("  登录触发二次 OTP 验证，自动获取验证码...")
                if not client_id or not ms_refresh_token:
                    self._log("  ⚠️ 无 IMAP 凭据，无法处理二次 OTP")
                    return None

                # 先主动触发发送 OTP 邮件（OpenAI 不会自动发送）
                self._log("  主动触发发送二次 OTP 邮件...")
                try:
                    send_headers = {"Accept": "application/json", "Referer": f"{AUTH}/email-verification"}
                    send_headers.update(self.fp.headers())
                    r_send = self.session.get(
                        f"{AUTH}/api/accounts/email-otp/send",
                        headers=send_headers,
                        timeout=15, impersonate=self.fp.impersonate,
                    )
                    self._log(f"  email-otp/send -> {r_send.status_code}")
                except Exception as send_err:
                    self._log(f"  email-otp/send 异常: {send_err}")

                # 发送后重新快照邮箱
                known_ids_before_pwd = get_known_mail_ids(
                    self.email, client_id, ms_refresh_token,
                    impersonate=self.fp.impersonate, log_fn=self._log,
                )

                # 等待新验证码，失败则尝试 resend
                code2 = None
                for otp2_attempt in range(3):
                    if otp2_attempt > 0:
                        self._log(f"  二次 OTP 重试 {otp2_attempt}/3，重新发送...")
                        try:
                            resend_headers = {"Content-Type": "application/json", "Accept": "application/json", "Origin": AUTH}
                            resend_headers.update(self.fp.headers())
                            if sentinel2:
                                resend_headers["openai-sentinel-token"] = sentinel2
                            self.session.post(
                                f"{AUTH}/api/accounts/email-otp/resend",
                                json={}, headers=resend_headers,
                                timeout=15, impersonate=self.fp.impersonate,
                            )
                        except Exception:
                            pass
                        # resend 后重新快照
                        known_ids_before_pwd = get_known_mail_ids(
                            self.email, client_id, ms_refresh_token,
                            impersonate=self.fp.impersonate, log_fn=self._log,
                        )

                    self._delay(3.0, 6.0)
                    code2 = fetch_otp(
                        self.email, client_id, ms_refresh_token,
                        known_ids=known_ids_before_pwd, timeout=45,
                        impersonate=self.fp.impersonate, log_fn=self._log,
                    )
                    if code2:
                        break

                if not code2:
                    self._log("  ⚠️ 二次 OTP 获取超时")
                    return None

                self._log(f"  二次 OTP: {code2}, 验证中...")
                otp2_headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Origin": AUTH,
                }
                otp2_headers.update(self.fp.headers())
                if sentinel2:
                    otp2_headers["openai-sentinel-token"] = sentinel2
                r2 = self.session.post(
                    f"{AUTH}/api/accounts/email-otp/validate",
                    json={"code": code2},
                    headers=otp2_headers, timeout=30, impersonate=self.fp.impersonate,
                )
                self._log(f"  二次 OTP validate -> {r2.status_code}")
                if r2.status_code != 200:
                    self._log(f"  ⚠️ 二次 OTP 验证失败: {r2.text[:200]}")
                    return None
        except Exception as otp_err:
            self._log(f"  二次 OTP 处理异常: {otp_err}")
            return None

        # 5.5 检查是否需要 about-you（新账号首次登录）
        #     和参考项目一致：做 create_account 后必须重新走完整登录
        try:
            last_json = (r2.json() if 'r2' in dir() and r2 is not None else pwd_json) if 'pwd_json' in dir() else {}
            last_page = (last_json.get("page") or {}).get("type", "")
            if last_page:
                self._log(f"  当前页面类型: {last_page}")
            if ("about_you" in last_page or "about-you" in str(last_json.get("continue_url", ""))) and _depth < 2:
                self._log("  新账号需要完成 about-you (create_account)...")
                self._consent_url = last_json.get("continue_url", "") or "about-you"
                self.step6b_about_you()
                # create_account 成功或 user_already_exists 都继续重新登录
                self._log("  create_account 完成，重新走完整登录流程...")
                return self.relogin_with_password(password, client_id, ms_refresh_token, _depth=_depth + 1)
        except Exception as e:
            self._log(f"  about-you 检查异常: {e}")

        # 6-9. workspace → redirect → token
        return self._finish_login()

    # ── 公共后半段：workspace 解析 → redirect 拿 code → token 交换 ──
    def _finish_login(self) -> dict:
        """从 cookie 解析 workspace，走 workspace/select → redirect → code → token 交换"""
        import urllib.parse as _up

        # 6. 从 cookie 中提取 workspace_id
        self._log("[Relogin] 解析 workspace...")
        auth_cookie = self.session.cookies.get("oai-client-auth-session")
        if not auth_cookie:
            all_cookies = [c.name for c in self.session.cookies]
            self._log(f"  ⚠️ 未获取到 oai-client-auth-session cookie, 当前cookies: {all_cookies[:20]}")
            return None

        auth_json = {}
        raw_val = auth_cookie.strip()
        try:
            decoded_val = _up.unquote(raw_val)
            if decoded_val != raw_val:
                raw_val = decoded_val
        except Exception:
            pass

        for part in raw_val.split("."):
            decoded = decode_jwt_payload("x." + part + ".x")
            if isinstance(decoded, dict) and "workspaces" in decoded:
                auth_json = decoded
                break

        workspaces = auth_json.get("workspaces") or []
        if not workspaces:
            self._log("  ⚠️ Cookie 中无 workspace 信息")
            return None

        workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
        if not workspace_id:
            self._log("  ⚠️ 无法解析 workspace_id")
            return None
        self._log(f"  workspace_id: {workspace_id[:12]}...")

        # 7. workspace/select
        self._log("[Relogin] workspace/select...")
        r = self.session.post(
            f"{AUTH}/api/accounts/workspace/select",
            json={"workspace_id": workspace_id},
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "Origin": AUTH, "Referer": f"{AUTH}/sign-in-with-chatgpt/codex/consent",
                     "User-Agent": self.fp.user_agent},
            timeout=30, impersonate=self.fp.impersonate,
        )
        self._log(f"  workspace/select -> {r.status_code}")
        if r.status_code != 200:
            self._log(f"  ⚠️ 失败: {r.text[:300]}")
            return None

        continue_url = ""
        try:
            select_data = r.json()
            continue_url = select_data.get("continue_url", "")
        except Exception:
            pass
        if not continue_url:
            self._log("  ⚠️ workspace/select 无 continue_url")
            return None
        self._log(f"  continue_url: {continue_url[:100]}...")

        # 8. 跟随重定向拿 code
        self._log("[Relogin] 跟随重定向拿 code...")
        current_url = continue_url
        for step in range(15):
            try:
                r = self.session.get(
                    current_url,
                    headers={"Accept": "text/html,*/*;q=0.8", "User-Agent": self.fp.user_agent},
                    allow_redirects=False, timeout=30, impersonate=self.fp.impersonate,
                )
            except Exception as e:
                err_msg = str(e)
                m = re.search(r'code=([A-Za-z0-9_.\-]+)', err_msg)
                if m:
                    self._auth_code = m.group(1)
                    self._log(f"  ✅ code 从异常提取: {self._auth_code[:30]}...")
                    break
                self._log(f"  [{step}] 异常: {err_msg[:100]}")
                return None

            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("location", "")
                loc_p = urlparse(location)
                self._log(f"  [{step}] {r.status_code} → {loc_p.path or location[:80]}")

                if loc_p.hostname in ("localhost", "127.0.0.1"):
                    code = parse_qs(loc_p.query).get("code", [None])[0]
                    if code:
                        self._auth_code = code
                        self._log(f"  ✅ code: {code[:30]}...")
                        break
                    return None

                if "code=" in location and "state=" in location:
                    code = parse_qs(urlparse(location).query).get("code", [None])[0]
                    if code:
                        self._auth_code = code
                        self._log(f"  ✅ code: {code[:30]}...")
                        break

                if location.startswith("/"):
                    p = urlparse(current_url)
                    location = f"{p.scheme}://{p.netloc}{location}"
                current_url = location
            elif r.status_code == 200:
                if "consent_challenge=" in current_url:
                    self._log(f"  [{step}] consent_challenge, POST accept...")
                    c_resp = self.session.post(
                        current_url,
                        data={"action": "accept"},
                        headers={"User-Agent": self.fp.user_agent},
                        allow_redirects=False, timeout=15, impersonate=self.fp.impersonate,
                    )
                    if c_resp.status_code in (301, 302, 303, 307, 308):
                        loc = c_resp.headers.get("location", "")
                        if loc.startswith("/"):
                            p = urlparse(current_url)
                            loc = f"{p.scheme}://{p.netloc}{loc}"
                        current_url = loc
                        continue
                meta = re.search(r'content=["\']?\d+;\s*url=([^"\'>\s]+)', r.text, re.IGNORECASE)
                if meta:
                    next_url = meta.group(1)
                    if next_url.startswith("/"):
                        p = urlparse(current_url)
                        next_url = f"{p.scheme}://{p.netloc}{next_url}"
                    current_url = next_url
                    continue
                self._log(f"  [{step}] 200 (停止)")
                break
            else:
                self._log(f"  [{step}] {r.status_code} (停止)")
                break
            self._delay(0.2, 0.5)

        if not self._auth_code:
            self._log("  ⚠️ 重登录未获取到 code")
            return None

        # 9. Token 交换
        return self.step9_exchange_token()

    # ── OTP 登录：不需要密码，直接用邮箱验证码登录拿 token ──
    def relogin_with_otp(self, client_id: str, ms_refresh_token: str) -> dict:
        """用邮箱 OTP 验证码登录，不需要密码"""
        self._log("[OTP Login] 开始 OTP 登录...")

        if not client_id or not ms_refresh_token:
            self._log("  ⚠️ 无 IMAP 凭据，无法进行 OTP 登录")
            return None

        # 1. 清除 cookies，重新生成 PKCE
        self.session.cookies.clear()
        self.code_verifier, self.code_challenge = generate_pkce()
        self.state = secrets.token_hex(16)
        self._login_verifier = None
        self._auth_code = None

        # 2. OAuth 初始化
        self._log("[OTP Login] OAuth 初始化...")
        params = {
            "client_id": CODEX_CLIENT_ID,
            "code_challenge": self.code_challenge,
            "code_challenge_method": "S256",
            "codex_cli_simplified_flow": "true",
            "id_token_add_organizations": "true",
            "prompt": "login",
            "redirect_uri": CODEX_REDIRECT_URI,
            "response_type": "code",
            "scope": CODEX_SCOPE,
            "state": self.state,
        }
        url = f"{AUTH}/oauth/authorize"
        for step in range(5):
            r = self.session.get(
                url,
                params=params if step == 0 else None,
                headers={"Accept": "text/html,*/*;q=0.8", "User-Agent": self.fp.user_agent},
                allow_redirects=False,
                impersonate=self.fp.impersonate,
            )
            self._log(f"  [init-{step}] {r.status_code} {urlparse(url).path}")
            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("location", "")
                if location.startswith("/"):
                    p = urlparse(url)
                    location = f"{p.scheme}://{p.netloc}{location}"
                url = location
                params = None
            else:
                break
        self._delay(0.5, 1.0)

        # 3. Sentinel
        self._log("[OTP Login] Sentinel...")
        sentinel = fetch_sentinel_token(self.session, self.fp, "authorize_continue", self._log)

        # 4. authorize/continue (signup hint，已注册账号会进入 OTP 验证)
        self._log("[OTP Login] authorize/continue (signup)...")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": AUTH,
            "Referer": f"{AUTH}/create-account",
        }
        headers.update(self.fp.headers())
        if sentinel:
            headers["openai-sentinel-token"] = sentinel
        r = self.session.post(
            f"{AUTH}/api/accounts/authorize/continue",
            json={"username": {"value": self.email, "kind": "email"}, "screen_hint": "signup"},
            headers=headers, timeout=30, impersonate=self.fp.impersonate,
        )
        self._log(f"  authorize/continue -> {r.status_code}")
        if r.status_code != 200:
            self._log(f"  ⚠️ 失败: {r.text[:300]}")
            return None

        # 检查响应，获取 continue_url（用作 OTP 发送地址）
        otp_continue_url = ""
        try:
            ac_json = r.json()
            ac_page = (ac_json.get("page") or {}).get("type", "")
            otp_continue_url = ac_json.get("continue_url", "")
            self._log(f"  页面类型: {ac_page}, continue_url: {otp_continue_url[:100]}")
        except Exception:
            ac_page = ""

        # 5. 快照已有邮件
        known_ids = get_known_mail_ids(
            self.email, client_id, ms_refresh_token,
            impersonate=self.fp.impersonate, log_fn=self._log,
        )

        # 6. 触发发送 OTP（用 continue_url，和参考项目一致）
        self._log("[OTP Login] 触发发送 OTP...")
        if otp_continue_url:
            otp_send_url = otp_continue_url
            if not otp_send_url.startswith("http"):
                otp_send_url = f"{AUTH}{otp_send_url}"
            send_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Referer": f"{AUTH}/create-account/password",
            }
            send_headers.update(self.fp.headers())
            if sentinel:
                send_headers["openai-sentinel-token"] = sentinel
            r = self.session.post(
                otp_send_url,
                json={}, headers=send_headers,
                timeout=30, impersonate=self.fp.impersonate,
            )
            self._log(f"  OTP send ({otp_send_url[-40:]}) -> {r.status_code}")
        else:
            # fallback: 直接调 email-otp/send
            send_headers = {"Accept": "application/json", "Referer": f"{AUTH}/email-verification"}
            send_headers.update(self.fp.headers())
            r = self.session.get(
                f"{AUTH}/api/accounts/email-otp/send",
                headers=send_headers,
                timeout=15, impersonate=self.fp.impersonate,
            )
            self._log(f"  email-otp/send -> {r.status_code}")

        # 7. 等待验证码
        self._log("[OTP Login] 等待验证码...")
        code = None
        for otp_attempt in range(3):
            if otp_attempt > 0:
                self._log(f"  OTP 重试 {otp_attempt}/3，重新发送...")
                try:
                    resend_headers = {"Content-Type": "application/json", "Accept": "application/json", "Origin": AUTH}
                    resend_headers.update(self.fp.headers())
                    if sentinel:
                        resend_headers["openai-sentinel-token"] = sentinel
                    self.session.post(
                        f"{AUTH}/api/accounts/email-otp/resend",
                        json={}, headers=resend_headers,
                        timeout=15, impersonate=self.fp.impersonate,
                    )
                except Exception:
                    pass
                known_ids = get_known_mail_ids(
                    self.email, client_id, ms_refresh_token,
                    impersonate=self.fp.impersonate, log_fn=self._log,
                )

            self._delay(3.0, 6.0)
            code = fetch_otp(
                self.email, client_id, ms_refresh_token,
                known_ids=known_ids, timeout=60,
                impersonate=self.fp.impersonate, log_fn=self._log,
            )
            if code:
                break

        if not code:
            self._log("  ⚠️ OTP 获取超时")
            return None

        # 8. 验证 OTP
        self._log(f"[OTP Login] OTP: {code}, 验证中...")
        otp_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": AUTH,
        }
        otp_headers.update(self.fp.headers())
        if sentinel:
            otp_headers["openai-sentinel-token"] = sentinel
        r = self.session.post(
            f"{AUTH}/api/accounts/email-otp/validate",
            json={"code": code},
            headers=otp_headers, timeout=30, impersonate=self.fp.impersonate,
        )
        self._log(f"  OTP validate -> {r.status_code}")
        if r.status_code != 200:
            self._log(f"  ⚠️ OTP 验证失败: {r.text[:200]}")
            return None

        # 检查是否需要 about-you
        try:
            val_json = r.json()
            val_page = (val_json.get("page") or {}).get("type", "")
            if "about_you" in val_page:
                self._log("  需要完成 about-you...")
                self._consent_url = val_json.get("continue_url", "") or "about-you"
                self.step6b_about_you()
                # create_account 后重新走 OTP 登录
                self._log("  create_account 完成，重新登录...")
                return self.relogin_with_otp(client_id, ms_refresh_token)
        except Exception:
            pass

        # 9-12. workspace → redirect → token
        return self._finish_login()

    # ── Step 7: 获取 authorization code ──
    def step7_get_auth_code(self) -> bool:
        self._log("[Step 7] 获取 authorization code...")

        consent_url = getattr(self, "_consent_url", "") or ""
        if "add-phone" in consent_url:
            self._log("  检测到 add-phone, 强制跳转 consent")
            consent_url = f"{AUTH}/sign-in-with-chatgpt/codex/consent"
        if not consent_url:
            consent_url = f"{AUTH}/sign-in-with-chatgpt/codex/consent"

        # 7a: GET consent 页面
        self._log(f"  [7a] GET consent 页面")
        ws_candidates = []
        try:
            r = self.session.get(
                consent_url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                    "User-Agent": self.fp.user_agent,
                    "Referer": f"{AUTH}/email-verification",
                },
                timeout=30, impersonate=self.fp.impersonate)
            self._log(f"  consent -> {r.status_code}, {len(r.text)} bytes")
            body = r.text

            scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL)
            for i, script in enumerate(scripts):
                script = script.strip()
                if not script or script.startswith('//'):
                    continue
                json_match = re.search(r'(?:window\.__\w+__|__NEXT_DATA__)\s*=\s*({.*})', script, re.DOTALL)
                if json_match:
                    try:
                        data = json.loads(json_match.group(1))
                        raw = json.dumps(data)
                        ws_ids = re.findall(r'"workspace_id"\s*:\s*"([^"]+)"', raw)
                        ws_candidates.extend(ws_ids)
                    except json.JSONDecodeError:
                        pass

            ws_pattern = re.findall(r'"workspace_id"\s*:\s*"([^"]+)"', body)
            ws_candidates.extend(ws_pattern)
            org_pattern = re.findall(r'"organization_id"\s*:\s*"([^"]+)"', body)
            ws_candidates.extend(org_pattern)

            lv = re.search(r'login_verifier["\s:=]+([A-Za-z0-9_\-]{20,})', body)
            if lv:
                self._login_verifier = lv.group(1)
                self._log(f"  login_verifier 从页面提取!")
        except Exception as e:
            self._log(f"  consent 页面异常: {e}")

        # 7b: workspace/select
        ws_candidates = list(dict.fromkeys(ws_candidates))
        self._log(f"  workspace 候选: {ws_candidates}")

        if not getattr(self, "_login_verifier", None):
            self._log(f"  [7b] 尝试 workspace/select 空 body ...")
            try:
                r = self.session.post(
                    f"{AUTH}/api/accounts/workspace/select",
                    json={},
                    headers={"Content-Type": "application/json", "Accept": "application/json",
                             "Origin": AUTH, "User-Agent": self.fp.user_agent,
                             "Referer": f"{AUTH}/sign-in-with-chatgpt/codex/consent"},
                    timeout=15, impersonate=self.fp.impersonate)
                self._log(f"  workspace/select(empty) -> {r.status_code}: {r.text[:500]}")
                if r.status_code == 200:
                    m = re.search(r'login_verifier["\s:=]+([A-Za-z0-9_\-]{20,})', r.text)
                    if m:
                        self._login_verifier = m.group(1)
                        self._log(f"  ✅ login_verifier 提取成功!")
            except Exception as e:
                self._log(f"  workspace/select(empty) 异常: {e}")

        if not getattr(self, "_login_verifier", None):
            for ws_id in ws_candidates:
                self._log(f"  [7b] 尝试 workspace/select({ws_id[:12]}...) ...")
                try:
                    r = self.session.post(
                        f"{AUTH}/api/accounts/workspace/select",
                        json={"workspace_id": ws_id},
                        headers={"Content-Type": "application/json", "Accept": "application/json",
                                 "Origin": AUTH, "User-Agent": self.fp.user_agent,
                                 "Referer": f"{AUTH}/sign-in-with-chatgpt/codex/consent"},
                        timeout=15, impersonate=self.fp.impersonate)
                    self._log(f"    -> {r.status_code} ({len(r.text)} bytes)")
                    if r.status_code == 200:
                        self._log(f"    响应: {r.text[:600]}")
                        m = re.search(r'login_verifier["\s:=]+([A-Za-z0-9_\-]{20,})', r.text)
                        if m:
                            self._login_verifier = m.group(1)
                            self._log(f"    ✅ login_verifier 提取成功!")
                            try:
                                ws_data = r.json()
                                self._continue_url = ws_data.get("continue_url", "")
                            except Exception:
                                pass
                            break
                    elif r.status_code == 500:
                        continue
                except Exception as e:
                    self._log(f"    异常: {e}")
                    continue

        # 7d: OAuth 重定向链
        self._log(f"  [7d] OAuth 重定向链...")

        headers = {
            "Accept": "text/html,*/*;q=0.8",
            "User-Agent": self.fp.user_agent,
            "Referer": f"{AUTH}/sign-in-with-chatgpt/codex/consent",
        }

        continue_url = getattr(self, "_continue_url", None)
        if continue_url:
            url = continue_url
            self._log(f"  使用 continue_url (已含 login_verifier)")
        else:
            login_verifier = getattr(self, "_login_verifier", None)
            params = {
                "client_id": CODEX_CLIENT_ID,
                "code_challenge": self.code_challenge,
                "code_challenge_method": "S256",
                "codex_cli_simplified_flow": "true",
                "id_token_add_organizations": "true",
                "prompt": "login" if login_verifier else "none",
                "redirect_uri": CODEX_REDIRECT_URI,
                "response_type": "code",
                "scope": CODEX_SCOPE,
                "state": self.state,
            }
            if login_verifier:
                params["login_verifier"] = login_verifier
            url = f"{AUTH}/api/oauth/oauth2/auth?{urlencode(params)}"
            self._log(f"  自行构建 URL (prompt={'login' if login_verifier else 'none'})")

        for step in range(20):
            try:
                r = self.session.get(
                    url, headers=headers,
                    allow_redirects=False, timeout=30,
                    impersonate=self.fp.impersonate)
            except Exception as e:
                err_msg = str(e)
                m = re.search(r'code=([A-Za-z0-9_.\-]+)', err_msg)
                if m:
                    self._auth_code = m.group(1)
                    self._log(f"  ✅ code 从异常提取: {self._auth_code[:30]}...")
                    return True
                self._log(f"  [{step}] 异常: {err_msg[:100]}")
                break

            if r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("location", "")
                loc_p = urlparse(location)
                self._log(f"  [{step}] {r.status_code} → {loc_p.path or location[:80]}")

                if loc_p.hostname in ("localhost", "127.0.0.1"):
                    code = parse_qs(loc_p.query).get("code", [None])[0]
                    if code:
                        self._auth_code = code
                        self._log(f"  ✅ code: {code[:30]}...")
                        return True
                    error = parse_qs(loc_p.query).get("error", [None])[0]
                    if error:
                        desc = parse_qs(loc_p.query).get("error_description",
                               parse_qs(loc_p.query).get("error_desscription", [""]))[0]
                        self._log(f"  ⚠️ OAuth error: {error} - {desc[:100]}")
                    return False

                if location.startswith("/"):
                    p = urlparse(url)
                    location = f"{p.scheme}://{p.netloc}{location}"
                url = location
            else:
                cur_path = urlparse(url).path
                self._log(f"  [{step}] {r.status_code} at {cur_path} (停止)")
                # 如果停在 /log-in 页面，尝试从页面提取 login_verifier 重试
                if r.status_code == 200 and "/log-in" in cur_path:
                    self._log("  检测到 /log-in 200, 尝试从页面重新提取...")
                    body = r.text
                    lv = re.search(r'login_verifier["\s:=]+([A-Za-z0-9_\-]{20,})', body)
                    if lv:
                        self._login_verifier = lv.group(1)
                        self._log(f"  login_verifier 从 /log-in 页面提取, 重试...")
                        params2 = {
                            "client_id": CODEX_CLIENT_ID,
                            "code_challenge": self.code_challenge,
                            "code_challenge_method": "S256",
                            "codex_cli_simplified_flow": "true",
                            "id_token_add_organizations": "true",
                            "prompt": "login",
                            "redirect_uri": CODEX_REDIRECT_URI,
                            "response_type": "code",
                            "scope": CODEX_SCOPE,
                            "state": self.state,
                            "login_verifier": self._login_verifier,
                        }
                        url = f"{AUTH}/api/oauth/oauth2/auth?{urlencode(params2)}"
                        continue
                break

        self._log("  ⚠️ 未获取到 code")
        return False

    # ── Step 9: Token 交换 ──
    def step9_exchange_token(self) -> dict:
        self._log("[Step 8] Token 交换...")
        if not self._auth_code:
            return None
        body = {
            "grant_type": "authorization_code",
            "code": self._auth_code,
            "client_id": CODEX_CLIENT_ID,
            "redirect_uri": CODEX_REDIRECT_URI,
            "code_verifier": self.code_verifier,
        }
        r = self.session.post(
            f"{AUTH}/oauth/token",
            data=urlencode(body),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json", "Origin": AUTH,
                     "User-Agent": self.fp.user_agent},
            timeout=30, impersonate=self.fp.impersonate)
        self._log(f"  token exchange -> {r.status_code}")
        if r.status_code != 200:
            self._log(f"  ⚠️ 失败: {r.text[:500]}")
            return None
        return r.json()

    def fetch_chatgpt_session(self, access_token: str) -> dict:
        """获取 https://chatgpt.com/api/auth/session 的全部字段"""
        self._log("[Session] 获取 ChatGPT session 信息...")
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "User-Agent": self.fp.user_agent,
        }
        headers.update(self.fp.headers())
        try:
            r = self.session.get(
                "https://chatgpt.com/api/auth/session",
                headers=headers,
                timeout=30,
                impersonate=self.fp.impersonate,
            )
            self._log(f"  session -> {r.status_code}")
            if r.status_code != 200:
                self._log(f"  ⚠️ 失败: {r.text[:300]}")
                return None
            data = r.json()
            self._log(f"  ✅ session 字段: {list(data.keys())}")
            return data
        except Exception as e:
            self._log(f"  ⚠️ session 异常: {e}")
            return None

    def _build_output(self, token_data: dict) -> dict:
        access_token = token_data.get("access_token", "")
        id_token = token_data.get("id_token", "")
        refresh_token = token_data.get("refresh_token", "")
        expires_in = token_data.get("expires_in", 864000)

        payload = decode_jwt_payload(access_token)
        auth_info = payload.get("https://api.openai.com/auth", {})
        account_id = auth_info.get("chatgpt_account_id", "")

        now = datetime.now(timezone(timedelta(hours=8)))
        expired = now + timedelta(seconds=expires_in)

        return {
            "access_token": access_token,
            "account_id": account_id,
            "email": self.email,
            "expired": expired.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
            "id_token": id_token,
            "last_refresh": now.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
            "refresh_token": refresh_token,
            "type": "codex",
        }


def _load_config() -> dict:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, "config.json")
    config = dict(DEFAULT_CONFIG)
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config.update(json.load(f))
    return config


def _load_proxies(proxy_file: str) -> list:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isabs(proxy_file):
        proxy_file = os.path.join(base_dir, proxy_file)
    if not os.path.exists(proxy_file):
        return []

    with open(proxy_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    proto_cache = {}
    proxies = []
    for line in lines:
        try:
            parsed = parse_proxy_url(line)
            if "://" in line:
                proxies.append(parsed["url"])
                continue
            key = (parsed["host"], parsed["port"])
            if key in proto_cache:
                proto = proto_cache[key]
                auth = f"{quote(parsed['username'], safe='')}:{quote(parsed['password'], safe='')}@" if parsed["username"] else ""
                _safe_print(f"[Proxy] 复用已识别协议: {proto}://{parsed['host']}:{parsed['port']}")
                proxies.append(f"{proto}://{auth}{parsed['host']}:{parsed['port']}")
            else:
                detected = _detect_proxy_protocol(parsed)
                proxies.append(detected)
                proto_cache[key] = detected.split("://")[0] if "://" in detected else "http"
        except Exception:
            _safe_print(f"[Warn] 代理格式错误，跳过: {line[:50]}...")
    return [p for p in proxies if p]


def _load_emails(input_file: str) -> list:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isabs(input_file):
        input_file = os.path.join(base_dir, input_file)
    if not os.path.exists(input_file):
        _safe_print(f"[Error] 文件不存在: {input_file}")
        return []

    with open(input_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    tasks = []
    for line in lines:
        parts = line.split("----")
        if len(parts) != 4:
            _safe_print(f"[Warn] 格式错误，跳过: {line[:50]}...")
            continue
        tasks.append([p.strip() for p in parts])
    return tasks
