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
from datetime import datetime
from email.header import decode_header
from urllib.parse import quote, urlparse

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
        return True


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
