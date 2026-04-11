"""
Codex 协议登录工具

基于 HAR 分析的完整 Codex 认证登录流程:

1. PKCE 初始化 (client_id=app_EMoamEEZ73f0CkXaXp7hrann)
2. OAuth 授权链 → 获取 login_challenge
3. Sentinel 风控探针
4. authorize/continue 提交邮箱
5. passwordless/send-otp 发送 OTP
6. email-otp/validate 验证 OTP
7. workspace/select 选择工作区
8. OAuth consent 重定向 → 获取 authorization code
9. Token 交换 → access_token / id_token / refresh_token
10. 输出 JSON 文件

用法:
  # 批量登录 (从 emails.txt 读取)
  python codex_login.py

  # 单个登录
  python codex_login.py --email xxx@hotmail.com

邮箱文件格式 (emails.txt):
  email----outlook_password----client_id----refresh_token
"""

import argparse
import atexit
import base64
import hashlib
import json
import os
import random
import re
import secrets
import socket
import subprocess
import sys
import time
import uuid
import imaplib
import email as email_lib
import threading
import traceback
from datetime import datetime, timedelta, timezone
from email.header import decode_header
from urllib.parse import urlparse, parse_qs, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

from curl_cffi import requests as curl_requests, CurlOpt


# ── 常量 ──
AUTH = "https://auth.openai.com"
SENTINEL = "https://sentinel.openai.com"

# HAR 确认: Codex 使用固定 client_id 和 redirect_uri
CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
CODEX_REDIRECT_URI = "http://localhost:1455/auth/callback"
CODEX_SCOPE = "openid email profile offline_access"

# 默认配置
DEFAULT_CONFIG = {
    "proxy": "",
    "pre_proxy": "",
    "max_workers": 2,
    "outlook_input_file": "emails.txt",
    "output_dir": "output",
}

# 浏览器配置
_CHROME_PROFILES = [
    {"major": 136, "impersonate": "chrome136",
     "build": 7103, "patch_range": (48, 175),
     "brands": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"'},
    {"major": 133, "impersonate": "chrome133a",
     "build": 7000, "patch_range": (30, 150),
     "brands": '"Chromium";v="133", "Google Chrome";v="133", "Not_A Brand";v="99"'},
]
_EDGE_PROFILES = [
    {"major": 136, "impersonate": "chrome136",
     "build": 7103, "patch_range": (50, 180),
     "brands": '"Chromium";v="136", "Microsoft Edge";v="136", "Not/A)Brand";v="99"',
     "edge": True},
]

# 线程锁
_print_lock = threading.Lock()
_file_lock = threading.Lock()
_proxy_chain_lock = threading.Lock()
_proxy_chain_map = {}


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
                    **({"users": [{"user": parsed_proxy["username"], "pass": parsed_proxy["password"]}]} if parsed_proxy["username"] else {})
                }]},
                "proxySettings": {"tag": "to_local"},
            },
            {
                "tag": "to_local",
                "protocol": "socks" if parsed_local["protocol"].startswith("socks") else "http",
                "settings": {"servers": [{"address": parsed_local["host"], "port": parsed_local["port"]}]},
            },
            {"protocol": "freedom", "tag": "direct"},
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


def _enable_pre_proxy(session, pre_proxy: str):
    """给 curl_cffi Session 注入 PRE_PROXY (代理链支持)

    原理: curl.reset() 会清除所有选项, 所以在 perform() 前注入 PRE_PROXY
    链路: pre_proxy (本地 V2Ray SOCKS5) → proxy (远程 HTTP) → 目标
    """
    if not pre_proxy:
        return
    original_perform = session.curl.perform
    pre_proxy_bytes = pre_proxy.encode() if isinstance(pre_proxy, str) else pre_proxy

    def patched_perform(*args, **kwargs):
        session.curl.setopt(CurlOpt.PRE_PROXY, pre_proxy_bytes)
        return original_perform(*args, **kwargs)

    session.curl.perform = patched_perform


def _safe_print(msg: str):
    with _print_lock:
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            print(f"[{ts}] {msg}")
        except UnicodeEncodeError:
            print(f"[{ts}] {msg.encode('utf-8', errors='replace').decode('utf-8')}", file=sys.stderr)


# ══════════════════════════════════════════════════════════
# PKCE
# ══════════════════════════════════════════════════════════

def generate_pkce() -> tuple:
    """生成 PKCE code_verifier 和 code_challenge (S256)"""
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


# ══════════════════════════════════════════════════════════
# 浏览器指纹 (轻量版)
# ══════════════════════════════════════════════════════════

class Fingerprint:
    def __init__(self):
        pool = _CHROME_PROFILES + _EDGE_PROFILES
        profile = random.choice(pool)
        self.is_edge = profile.get("edge", False)
        self.major = profile["major"]
        self.impersonate = profile["impersonate"]

        build = profile["build"]
        patch = random.randint(*profile["patch_range"])
        self.chrome_full = f"{self.major}.0.{build}.{patch}"

        if self.is_edge:
            self.user_agent = (
                f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                f"AppleWebKit/537.36 (KHTML, like Gecko) "
                f"Chrome/{self.chrome_full} Safari/537.36 "
                f"Edg/{self.chrome_full}"
            )
        else:
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


# ══════════════════════════════════════════════════════════
# Sentinel PoW
# ══════════════════════════════════════════════════════════

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
        now_str = time.strftime(
            "%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)", time.gmtime())
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        nav_props = ["vendorSub", "productSub", "vendor", "maxTouchPoints",
                     "hardwareConcurrency", "cookieEnabled", "wakeLock", "speechSynthesis"]
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
    """向 sentinel.openai.com 发送探针并生成 JSON token"""
    _log = log_fn or _safe_print

    req_body = {
        "p": SentinelToken.generate_requirements_token(fp),
        "id": fp.device_id,
        "flow": flow,
    }
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": f"{SENTINEL}/backend-api/sentinel/frame.html",
        "Origin": SENTINEL,
    }
    headers.update(fp.headers())

    try:
        resp = session.post(
            f"{SENTINEL}/backend-api/sentinel/req",
            data=json.dumps(req_body), headers=headers,
            timeout=20, impersonate=fp.impersonate,
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
        p_value = SentinelToken.generate_pow_token(
            fp, seed=pow_data["seed"], difficulty=str(pow_data.get("difficulty", "0")))
    else:
        p_value = SentinelToken.generate_requirements_token(fp)

    return json.dumps({
        "p": p_value, "t": "", "c": c_value,
        "id": fp.device_id, "flow": flow,
    }, separators=(",", ":"))


# ══════════════════════════════════════════════════════════
# Outlook IMAP OTP 获取 (复用 chatgpt-signup 逻辑)
# ══════════════════════════════════════════════════════════

def _get_imap_access_token(client_id: str, refresh_token: str, impersonate: str = "chrome131"):
    """双端点尝试获取 IMAP access_token"""
    methods = [
        {
            "url": "https://login.live.com/oauth20_token.srf",
            "data": {"client_id": client_id, "grant_type": "refresh_token",
                     "refresh_token": refresh_token},
            "imap_server": "outlook.office365.com",
        },
        {
            "url": "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
            "data": {"client_id": client_id, "grant_type": "refresh_token",
                     "refresh_token": refresh_token,
                     "scope": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"},
            "imap_server": "outlook.live.com",
        },
    ]
    last_error = ""
    for method in methods:
        try:
            r = curl_requests.post(
                method["url"], data=method["data"],
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30, impersonate=impersonate)
            resp = r.json()
            token = resp.get("access_token")
            if token:
                return token, method["imap_server"]
            last_error = resp.get("error_description", resp.get("error", str(resp)))
        except Exception as e:
            last_error = str(e)
    raise Exception(f"IMAP access token 获取失败: {last_error[:150]}")


def _strip_plus_alias(email_addr: str) -> str:
    """去掉邮箱中的 + 别名部分, 如 foo+bar@hotmail.com -> foo@hotmail.com"""
    local, _, domain = email_addr.partition("@")
    if "+" in local:
        local = local.split("+", 1)[0]
    return f"{local}@{domain}" if domain else email_addr


def _imap_connect(email_addr, access_token, imap_server):
    """XOAUTH2 认证连接 IMAP"""
    # Outlook IMAP 认证需要用主邮箱地址 (不带 + 别名)
    clean_email = _strip_plus_alias(email_addr)
    imap = imaplib.IMAP4_SSL(imap_server, 993)
    auth_string = f"user={clean_email}\x01auth=Bearer {access_token}\x01\x01"
    imap.authenticate("XOAUTH2", lambda x: auth_string.encode("utf-8"))
    return imap


def _get_openai_mail_ids(imap) -> set:
    """获取收件箱中 OpenAI 发件人的邮件 ID (合并所有 OpenAI 地址)"""
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
    """从单封邮件中提取 6 位 OTP 验证码 (仅处理验证码邮件)"""
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
        subject = "".join(
            part.decode(enc or "utf-8") if isinstance(part, bytes) else part
            for part, enc in decoded)

    # 先确认这是一封验证码邮件, 避免从邀请/通知邮件中误提取数字
    text_lower = (subject + " " + body[:2000]).lower()
    otp_keywords = ["verification", "verify", "code", "otp", "验证",
                     "login", "sign in", "sign-in", "one-time"]
    invite_keywords = ["invite", "invitation", "join", "team", "workspace",
                        "accepted", "welcome to"]
    is_otp_mail = any(kw in text_lower for kw in otp_keywords)
    is_invite_mail = any(kw in text_lower for kw in invite_keywords)

    # 如果是邀请邮件且不含 OTP 关键词, 跳过
    if is_invite_mail and not is_otp_mail:
        return None, subject

    patterns = [
        r'>\s*(\d{6})\s*<', r'(\d{6})\s*\n',
        r'code[:\s]+(\d{6})', r'verify.*?(\d{6})', r'(\d{6})',
    ]
    for pattern in patterns:
        match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1), subject
    return None, subject


def get_known_mail_ids(email_addr, client_id, refresh_token, impersonate="chrome131", log_fn=None):
    """获取当前所有 OpenAI 邮件 ID (用于过滤旧邮件)"""
    try:
        access_token, imap_server = _get_imap_access_token(client_id, refresh_token, impersonate)
        imap = _imap_connect(email_addr, access_token, imap_server)
        try:
            known = _get_openai_mail_ids(imap)
            if log_fn:
                log_fn(f"[OTP] 已有 {len(known)} 封 OpenAI 邮件 (标记为旧邮件)")
            return known
        finally:
            try: imap.logout()
            except Exception: pass
    except Exception as e:
        if log_fn:
            log_fn(f"[OTP] 获取旧邮件 ID 失败: {e}")
        return set()


def fetch_otp(email_addr, client_id, refresh_token, known_ids=None,
              timeout=120, impersonate="chrome131", log_fn=None) -> str:
    """
    轮询 IMAP 获取最新 OpenAI OTP 验证码

    策略:
    - 只看 new_ids = all_ids - known_ids, 确保不会拿到注册时的旧验证码
    - 50 秒内无新邮件, 回退尝试已有邮件中最新一封
    """
    try:
        access_token, imap_server = _get_imap_access_token(client_id, refresh_token, impersonate)
    except Exception as e:
        if log_fn: log_fn(f"[OTP] access token 失败: {e}")
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
                    # 按邮件 ID 倒序 (最新的优先)
                    sorted_new = sorted(new_ids, key=lambda x: int(x), reverse=True)
                    for mid in sorted_new:
                        otp, subject = _extract_otp_from_mail(imap, mid)
                        if otp:
                            if log_fn:
                                log_fn(f"[OTP] ✅ 验证码: {otp} (主题: {subject})")
                            return otp

                # 50 秒无新邮件 → 回退尝试已有邮件中最新一封
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
                try: imap.logout()
                except Exception: pass
        except Exception as e:
            if log_fn: log_fn(f"[OTP] IMAP 轮询出错: {e}")

        if log_fn:
            log_fn(f"[OTP] 第 {check_count} 次, 无新验证码 ({elapsed}s/{timeout}s)")
        time.sleep(3)

    if log_fn: log_fn(f"[OTP] ⚠️ 超时 ({timeout}s)")
    return None


# ══════════════════════════════════════════════════════════
# JWT 解析
# ══════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════
# Codex 登录器
# ══════════════════════════════════════════════════════════

class CodexLogin:
    """Codex 协议登录器"""

    def __init__(self, email: str, proxy: str = None, pre_proxy: str = None, tag: str = ""):
        self.email = email
        self.tag = tag or email.split("@")[0]
        self.fp = Fingerprint()
        self.session = curl_requests.Session()
        if proxy:
            self.session.proxies = {"https": proxy, "http": proxy}
        # 代理链: pre_proxy (本地) → proxy (远程) → 目标
        if pre_proxy:
            _enable_pre_proxy(self.session, pre_proxy)
        self.code_verifier, self.code_challenge = generate_pkce()
        self.state = secrets.token_hex(16)
        self._login_challenge = None
        self._login_verifier = None
        self._auth_code = None
        self._sentinel_token_1 = None
        self._sentinel_token_2 = None
        self._next_page_type = ""

    def _log(self, msg):
        _safe_print(f"[{self.tag}] {msg}")

    def _delay(self, lo=0.3, hi=1.0):
        time.sleep(random.uniform(lo, hi))

    # ── Step 1: OAuth 初始化 ──
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
                url, params=params if step == 0 else None,
                headers={"Accept": "text/html,*/*;q=0.8", "User-Agent": self.fp.user_agent},
                allow_redirects=False, impersonate=self.fp.impersonate)
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

    # ── Step 2: Sentinel 探针 #1 ──
    def step2_sentinel_probe(self):
        self._log("[Step 2] Sentinel 风控探针 #1...")
        self._sentinel_token_1 = fetch_sentinel_token(
            self.session, self.fp, "login_passwordless", self._log)
        self._log("  Sentinel #1 " + ("OK" if self._sentinel_token_1 else "⚠️ 失败"))
        self._delay(0.5, 1.5)

    # ── Step 3: authorize/continue 提交邮箱 ──
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
            # 保存服务端期望的下一步类型 (password / passwordless 等)
            self._next_page_type = (data.get("page") or {}).get("type", "")
            if self._next_page_type:
                self._log(f"  下一步类型: {self._next_page_type}")
        except Exception:
            self._next_page_type = ""
        self._delay(0.5, 1.0)
        return True

    # ── Step 4: Sentinel 探针 #2 ──
    def step4_sentinel_probe2(self):
        self._log("[Step 4] Sentinel 风控探针 #2...")
        self._sentinel_token_2 = fetch_sentinel_token(
            self.session, self.fp, "login_passwordless", self._log)
        self._log("  Sentinel #2 " + ("OK" if self._sentinel_token_2 else "⚠️ 失败"))
        self._delay(0.3, 0.8)

    # ── Step 5: 发送 OTP ──
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

    # ── Step 5b: 密码验证 (当 authorize/continue 返回 password 类型时) ──
    def step5_password_verify(self, password: str) -> bool:
        """
        当 authorize/continue 指示需要密码登录时, 用密码验证代替 OTP。
        成功后服务端 session 进入已认证状态, 可直接获取 auth code。
        """
        self._log("[Step 5b] 密码验证 (password/verify)...")
        sentinel = fetch_sentinel_token(
            self.session, self.fp, "login_password", self._log)

        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Origin": AUTH, "Referer": f"{AUTH}/log-in/password"}
        headers.update(self.fp.headers())
        if sentinel:
            headers["openai-sentinel-token"] = sentinel

        r = self.session.post(
            f"{AUTH}/api/accounts/password/verify",
            json={"password": password},
            headers=headers, timeout=30, impersonate=self.fp.impersonate)
        self._log(f"  password/verify -> {r.status_code}")
        if r.status_code != 200:
            self._log(f"  ⚠️ 密码验证失败: {r.text[:300]}")
            return False

        try:
            data = r.json()
            self._log(f"  响应: {json.dumps(data, ensure_ascii=False)[:300]}")
            self._consent_url = data.get("continue_url", "")
        except Exception:
            self._consent_url = ""
        return True

    # ── Step 6: 验证 OTP ──
    def step6_validate_otp(self, code: str) -> bool:
        """
        HAR #157: POST email-otp/validate → 200
        响应: {"continue_url": ".../sign-in-with-chatgpt/codex/consent", ...}
        """
        self._log(f"[Step 6] 验证 OTP: {code}")
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                    "Origin": AUTH, "Referer": f"{AUTH}/email-verification"}
        headers.update(self.fp.headers())
        r = self.session.post(
            f"{AUTH}/api/accounts/email-otp/validate",
            json={"code": code}, headers=headers,
            timeout=30, impersonate=self.fp.impersonate)
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

    # ── Step 6b: 完善个人资料 (about-you / create_account) ──
    def step6b_about_you(self) -> bool:
        """
        处理 about-you 页面 (新账号需要填写姓名和生日)

        API: POST /api/accounts/create_account
        Body: {"name": "Full Name", "birthdate": "1995-06-15"}
        需要 sentinel token (flow: oauth_create_account)
        """
        consent_url = getattr(self, "_consent_url", "") or ""
        if "about-you" not in consent_url and "about_you" not in consent_url:
            return True  # 不需要此步骤

        self._log("[Step 6b] 完善个人资料 (about-you)...")

        # 从邮箱前缀提取名字 (CamelCase 拆分)
        name_part = self.email.split("@")[0]
        # 去掉末尾数字
        name_clean = re.sub(r'\d+$', '', name_part)
        parts = re.findall(r'[A-Z][a-z]+', name_clean)
        if len(parts) >= 2:
            full_name = f"{parts[0]} {parts[1]}"
        elif parts:
            full_name = f"{parts[0]} Smith"
        else:
            full_name = f"{name_clean} Smith"

        # 生成随机生日 (20-35 岁)
        age = random.randint(20, 35)
        birth_year = datetime.now().year - age
        birth_month = random.randint(1, 12)
        birth_day = random.randint(1, 28)
        birthdate = f"{birth_year}-{birth_month:02d}-{birth_day:02d}"

        self._log(f"  姓名: {full_name}, 生日: {birthdate}")

        # 获取 sentinel token
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

        # 处理后续中间页 (add-phone 等): 直接跳到 consent
        consent_url = getattr(self, "_consent_url", "") or ""
        if "add-phone" in consent_url:
            self._log("  检测到 add-phone, 跳过 -> consent")
            self._consent_url = f"{AUTH}/sign-in-with-chatgpt/codex/consent"

        self._delay(0.5, 1.0)
        return True

    # ── Step 7: 获取 authorization code (合并 consent + workspace + oauth) ──
    def step7_get_auth_code(self) -> bool:
        """
        OTP 验证成功后, 需要获取 authorization code.
        
        CLIProxyAPI 的做法: 启动本地 HTTP server, 打开浏览器, 浏览器处理所有中间步骤.
        
        我们的纯协议做法:
        1. GET consent 页面 (设置 cookies, 尝试提取 workspace_id)
        2. 各种方式获取 workspace_id
        3. POST workspace/select → 获取 login_verifier
        4. GET /api/oauth/oauth2/auth?login_verifier=xxx → 重定向链 → code
        
        如果以上都失败, 尝试降级策略.
        """
        print(f"  [DEBUG] step7_get_auth_code 开始执行")
        self._log("[Step 7] 获取 authorization code...")

        # ─── 检测 add-phone 并强制跳转 consent ───
        consent_url = getattr(self, "_consent_url", "") or ""
        if "add-phone" in consent_url:
            self._log("  检测到 add-phone, 强制跳转 consent (session 已认证)")
            consent_url = f"{AUTH}/sign-in-with-chatgpt/codex/consent"
        
        if not consent_url:
            consent_url = f"{AUTH}/sign-in-with-chatgpt/codex/consent"

        # ─── 7a: GET consent 页面 ───
        self._log(f"  [7a] GET consent 页面: {consent_url}")
        ws_candidates = []  # 候选 workspace_id 列表
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
            
            # 打印页面结构 (前1500字符) 用于调试
            self._log(f"  [页面内容前1500字符]:")
            for line in body[:1500].split('\n'):
                line_s = line.strip()
                if line_s:
                    self._log(f"    {line_s[:200]}")
            
            # 方法1: 从 <script> 标签中提取嵌入的 JSON 数据
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL)
            for i, script in enumerate(scripts):
                script = script.strip()
                if not script or script.startswith('//'):
                    continue
                # 检查是否包含 workspace 相关数据
                if 'workspace' in script.lower() or 'organization' in script.lower():
                    self._log(f"  [script #{i}] 包含 workspace 数据: {script[:300]}")
                # 检查 JSON 数据 (window.__xxx = {...})
                json_match = re.search(r'(?:window\.__\w+__|__NEXT_DATA__)\s*=\s*({.*})', script, re.DOTALL)
                if json_match:
                    try:
                        data = json.loads(json_match.group(1))
                        raw = json.dumps(data)
                        self._log(f"  [script #{i}] JSON 数据 ({len(raw)} bytes): {raw[:500]}")
                        # 从嵌入数据提取 workspace_id
                        ws_ids = re.findall(r'"workspace_id"\s*:\s*"([^"]+)"', raw)
                        ws_candidates.extend(ws_ids)
                    except json.JSONDecodeError:
                        pass
            
            # 方法2: 查找 serverProps / __PROPS__ 等
            props_match = re.search(r'data-props=["\']({[^"\']*})["\']', body)
            if props_match:
                try:
                    data = json.loads(props_match.group(1))
                    self._log(f"  data-props: {json.dumps(data)[:300]}")
                except Exception:
                    pass
            
            # 方法3: 直接搜索 workspace_id 模式
            ws_pattern = re.findall(r'"workspace_id"\s*:\s*"([^"]+)"', body)
            ws_candidates.extend(ws_pattern)
            
            # 方法4: 搜索 organization_id 模式  
            org_pattern = re.findall(r'"organization_id"\s*:\s*"([^"]+)"', body)
            ws_candidates.extend(org_pattern)
            
            # 方法5: 从 UUIDs 中过滤 (排除明显的资源hash)
            all_uuids = re.findall(
                r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', body)
            if all_uuids:
                unique = list(dict.fromkeys(all_uuids))
                self._log(f"  页面所有 UUIDs: {unique}")
                # 这些 UUID 作为候选添加到末尾 (优先级最低)
                ws_candidates.extend(unique)
            
            # 检查 login_verifier
            lv = re.search(r'login_verifier["\s:=]+([A-Za-z0-9_\-]{20,})', body)
            if lv:
                self._login_verifier = lv.group(1)
                self._log(f"  login_verifier 从页面提取!")
                
        except Exception as e:
            self._log(f"  consent 页面异常: {e}")

        # ─── 7b: 尝试 workspace/select ───
        # 去重候选列表
        ws_candidates = list(dict.fromkeys(ws_candidates))
        self._log(f"  workspace 候选: {ws_candidates}")
        
        if not getattr(self, "_login_verifier", None):
            # 先尝试空 body
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

        # 逐个尝试候选 workspace_id
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
                            # 保存 continue_url (已包含 login_verifier)
                            try:
                                ws_data = r.json()
                                self._continue_url = ws_data.get("continue_url", "")
                                if self._continue_url:
                                    self._log(f"    continue_url 已保存")
                            except Exception:
                                pass
                            break
                    elif r.status_code == 500:
                        self._log(f"    500 跳过 (非有效 workspace)")
                        continue
                    else:
                        self._log(f"    {r.text[:200]}")
                except Exception as e:
                    self._log(f"    异常: {e}")
                    continue

        # ─── 7d: 跟随重定向获取 code ───
        self._log(f"  [7d] OAuth 重定向链...")

        headers = {
            "Accept": "text/html,*/*;q=0.8",
            "User-Agent": self.fp.user_agent,
            "Referer": f"{AUTH}/sign-in-with-chatgpt/codex/consent",
        }

        # 优先使用 workspace/select 返回的 continue_url (已包含 login_verifier)
        continue_url = getattr(self, "_continue_url", None)
        if continue_url:
            url = continue_url
            self._log(f"  使用 continue_url (已含 login_verifier)")
        else:
            # 降级: 自行构建 URL
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
            login_verifier = getattr(self, "_login_verifier", None)
            if login_verifier:
                params["login_verifier"] = login_verifier
            url = f"{AUTH}/api/oauth/oauth2/auth?{urlencode(params)}"
            self._log(f"  降级: 自行构建 URL")

        # 手动跟随重定向
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
                    # 检查 error
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
                self._log(f"  [{step}] {r.status_code} (停止)")
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
        # CLIProxyAPI 确认: TokenURL = "https://auth.openai.com/oauth/token"
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

    # ── 主流程 ──
    def run(self, otp_fn=None, password: str = None) -> dict:
        """
        执行完整登录流程

        Args:
            otp_fn: OTP 获取回调函数, 签名: fn() -> str
            password: 密码 (当服务端要求密码登录时使用)
        Returns:
            输出 JSON dict, 或 None
        """
        self.step1_oauth_init()
        self.step2_sentinel_probe()
        if not self.step3_authorize_continue():
            return None

        if self._next_page_type == "password":
            # 服务端要求密码登录
            pwd = password or self.email.split("@")[0]
            self._log(f"服务端要求密码登录, 使用密码验证...")
            if not self.step5_password_verify(pwd):
                return None
        else:
            self.step4_sentinel_probe2()
            if not self.step5_send_otp():
                return None
            self._delay(2.0, 5.0)

            # 获取 OTP
            self._log("等待验证码...")
            if not otp_fn:
                code = input(f"[{self.tag}] 请输入验证码: ").strip()
            else:
                code = otp_fn()
            if not code:
                self._log("⚠️ 未获取到验证码")
                return None

            if not self.step6_validate_otp(code):
                return None

        if not self.step6b_about_you():
            return None
        self._delay(0.5, 1.5)
        if not self.step7_get_auth_code():
            return None
        token_data = self.step9_exchange_token()
        if not token_data:
            return None
        return self._build_output(token_data)

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


# ══════════════════════════════════════════════════════════
# 批量登录 (从 emails.txt 读取)
# ══════════════════════════════════════════════════════════

def _load_config() -> dict:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, "config.json")
    config = dict(DEFAULT_CONFIG)
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            config.update(json.load(f))
    return config


def _detect_proxy_protocol(parsed: dict, timeout: float = 6.0) -> str:
    """通过代理链（本地代理 -> 上游）探测上游代理的协议类型"""
    host, port = parsed["host"], parsed["port"]
    user, pwd = parsed["username"], parsed["password"]
    auth = f"{quote(user, safe='')}:{quote(pwd, safe='')}@" if user else ""

    local_upstream = detect_local_proxy()
    xray_exe = _find_xray_exe() if local_upstream else ""

    for proto in ("socks5", "http"):
        test_url = f"{proto}://{auth}{host}:{port}"

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
    return f"socks5://{auth}{host}:{port}"


def _load_proxies(proxy_file: str) -> list:
    """
    加载代理列表

    格式: host:port:user:pass 或 socks5://user:pass@host:port（每行一个）
    无协议前缀时自动探测 socks5/http（同一 host:port 只探测一次）
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isabs(proxy_file):
        proxy_file = os.path.join(base_dir, proxy_file)

    if not os.path.exists(proxy_file):
        return []

    with open(proxy_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    # 对同一 host:port 只探测一次协议
    _proto_cache = {}  # (host, port) -> "socks5" | "http"

    proxies = []
    for line in lines:
        try:
            parsed = parse_proxy_url(line)
            # 已有协议前缀 (socks5://... http://...) 直接用
            if "://" in line:
                proxies.append(parsed["url"])
                continue
            # 无前缀: 自动探测
            key = (parsed["host"], parsed["port"])
            if key in _proto_cache:
                proto = _proto_cache[key]
                auth = f"{quote(parsed['username'], safe='')}:{quote(parsed['password'], safe='')}@" if parsed["username"] else ""
                _safe_print(f"[Proxy] 复用已识别协议: {proto}://{parsed['host']}:{parsed['port']}")
                proxies.append(f"{proto}://{auth}{parsed['host']}:{parsed['port']}")
            else:
                detected = _detect_proxy_protocol(parsed)
                proxies.append(detected)
                # 缓存探测结果
                det_proto = detected.split("://")[0] if "://" in detected else "http"
                _proto_cache[key] = det_proto
        except Exception:
            _safe_print(f"[Warn] 代理格式错误，跳过: {line[:50]}...")
    return [p for p in proxies if p]


def _load_emails(input_file: str) -> list:
    """
    加载邮箱列表

    格式: email----outlook_password----client_id----refresh_token
    """
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


def _login_one(idx: int, total: int, email: str, outlook_pwd: str,
               client_id: str, ms_refresh_token: str,
               proxy: str, pre_proxy: str, output_dir: str) -> tuple:
    """单个账号登录任务"""
    tag = email.split("@")[0]

    _safe_print(f"\n{'='*60}")
    _safe_print(f"  [{idx}/{total}] 登录: {email}")
    _safe_print(f"  代理: {proxy or '无'}")
    _safe_print(f"{'='*60}")

    try:
        login = CodexLogin(email=email, proxy=proxy, pre_proxy=pre_proxy, tag=tag)

        # ★ 关键: 在 send-otp 之前获取已有邮件 ID
        # 这样只会捕获登录时发送的新 OTP, 不会拿到注册时的旧验证码
        def _fetch_otp():
            # 先快照当前所有 OpenAI 邮件 ID
            known_ids = get_known_mail_ids(
                email, client_id, ms_refresh_token,
                impersonate=login.fp.impersonate, log_fn=login._log)
            # 然后轮询新邮件
            return fetch_otp(
                email, client_id, ms_refresh_token,
                known_ids=known_ids, timeout=120,
                impersonate=login.fp.impersonate, log_fn=login._log)

        # 自定义 run 流程, 在 send-otp 之前才快照
        login.step1_oauth_init()
        login.step2_sentinel_probe()
        if not login.step3_authorize_continue():
            return False, email, "authorize/continue failed"

        # ── 检查服务端期望的登录方式 ──
        next_page = getattr(login, "_next_page_type", "")
        password = email.split("@")[0].split("+")[0]

        if next_page == "password":
            login._log(f"服务端要求密码登录, 使用密码验证...")
            if not login.step5_password_verify(password):
                return False, email, "password verify failed"
        else:
            login.step4_sentinel_probe2()

            # ★ 在 send-otp 之前快照旧邮件
            known_ids = get_known_mail_ids(
                email, client_id, ms_refresh_token,
                impersonate=login.fp.impersonate, log_fn=login._log)

            if not login.step5_send_otp():
                return False, email, "send-otp failed"

            login._delay(2.0, 5.0)

            # ★ 从新邮件中获取 OTP
            login._log("等待验证码...")
            code = fetch_otp(
                email, client_id, ms_refresh_token,
                known_ids=known_ids, timeout=120,
                impersonate=login.fp.impersonate, log_fn=login._log)

            if not code:
                return False, email, "OTP 超时"

            if not login.step6_validate_otp(code):
                return False, email, "OTP validate failed"

        if not login.step6b_about_you():
            return False, email, "about-you failed"

        login._delay(0.5, 1.5)

        if not login.step7_get_auth_code():
            return False, email, "get auth code failed"

        token_data = login.step9_exchange_token()
        if not token_data:
            return False, email, "token exchange failed"

        result = login._build_output(token_data)

        # 保存 JSON
        plan = "free"
        payload = decode_jwt_payload(result.get("access_token", ""))
        auth_info = payload.get("https://api.openai.com/auth", {})
        plan = auth_info.get("chatgpt_plan_type", "free")

        out_path = os.path.join(output_dir, f"codex-{email}-{plan}.json")
        with _file_lock:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False)

        _safe_print(f"\n[{tag}] ✅ 登录成功! → {out_path}")
        _safe_print(f"[{tag}]    account_id: {result.get('account_id')}")
        _safe_print(f"[{tag}]    expired: {result.get('expired')}")
        return True, email, None

    except Exception as e:
        _safe_print(f"\n[{tag}] ❌ 登录失败: {e}")
        traceback.print_exc()
        return False, email, str(e)


def run_batch(config: dict):
    """并发批量登录"""
    proxy = config.get("proxy", "")
    pre_proxy = config.get("pre_proxy", "")
    max_workers = config.get("max_workers", 2)
    output_dir = config.get("output_dir", "output")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(base_dir, output_dir)
    os.makedirs(output_dir, exist_ok=True)

    tasks = _load_emails(config.get("outlook_input_file", "emails.txt"))
    if not tasks:
        _safe_print("[Error] 无有效邮箱, 请检查 emails.txt")
        return

    # 加载独立代理列表
    proxies = _load_proxies(config.get("proxy_file", "proxies.txt"))

    total = len(tasks)
    _safe_print(f"\n{'#'*60}")
    _safe_print(f"  Codex 协议登录工具")
    _safe_print(f"  账号数: {total}")
    _safe_print(f"  并发数: {min(max_workers, total)}")
    _safe_print(f"  全局代理: {proxy or '无'}")
    _safe_print(f"  前置代理: {pre_proxy or '无'}")
    _safe_print(f"  独立代理: {len(proxies)} 条（来自 proxies.txt）")
    _safe_print(f"  输出: {output_dir}")
    _safe_print(f"{'#'*60}\n")

    success = 0
    fail = 0
    start = time.time()

    actual_workers = min(max_workers, total)
    with ThreadPoolExecutor(max_workers=actual_workers) as executor:
        futures = {}
        for idx, (email, pwd, cid, rt) in enumerate(tasks, 1):
            # 优先从 proxies.txt 按顺序分配，不够则循环，没有则用全局代理
            if proxies:
                raw_proxy = proxies[(idx - 1) % len(proxies)]
            else:
                raw_proxy = proxy
            use_proxy = ensure_proxy_chain(raw_proxy) if raw_proxy else raw_proxy
            f = executor.submit(_login_one, idx, total, email, pwd, cid, rt, use_proxy, pre_proxy, output_dir)
            futures[f] = email

        for f in as_completed(futures):
            try:
                ok, _, _ = f.result()
                if ok: success += 1
                else: fail += 1
            except Exception as ex:
                fail += 1
                _safe_print(f"[FAIL] 线程异常: {ex}")

    elapsed = time.time() - start
    _safe_print(f"\n{'#'*60}")
    _safe_print(f"  登录完成! 耗时 {elapsed:.1f}s")
    _safe_print(f"  总数: {total} | 成功: {success} | 失败: {fail}")
    _safe_print(f"  输出目录: {output_dir}")
    _safe_print(f"{'#'*60}")


# ══════════════════════════════════════════════════════════
# CLI 入口
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Codex 协议登录工具")
    parser.add_argument("--email", "-e", default=None, help="单个登录邮箱 (不传则从 emails.txt 批量)")
    parser.add_argument("--proxy", "-p", default=None, help="代理 (socks5://...)")
    parser.add_argument("--pre-proxy", default=None, help="前置代理/代理链 (本地 V2Ray 等)")
    parser.add_argument("--output", "-o", default=None, help="输出目录 (默认: output)")
    parser.add_argument("--workers", "-w", type=int, default=None, help="并发数")
    parser.add_argument("--input", "-i", default=None, help="邮箱列表文件 (默认: emails.txt)")
    args = parser.parse_args()

    config = _load_config()
    if args.proxy: config["proxy"] = args.proxy
    if args.pre_proxy: config["pre_proxy"] = args.pre_proxy
    if args.output: config["output_dir"] = args.output
    if args.workers: config["max_workers"] = args.workers
    if args.input: config["outlook_input_file"] = args.input

    if args.email:
        # 单个登录 (手动输入验证码)
        _safe_print(f"Codex 单个登录: {args.email}")
        effective_proxy = ensure_proxy_chain(config.get("proxy", "")) if config.get("proxy", "") else ""
        login = CodexLogin(email=args.email, proxy=effective_proxy,
                           pre_proxy=config.get("pre_proxy", ""))
        result = login.run()
        if result:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            out_dir = config.get("output_dir", "output")
            if not os.path.isabs(out_dir):
                out_dir = os.path.join(base_dir, out_dir)
            os.makedirs(out_dir, exist_ok=True)

            payload = decode_jwt_payload(result.get("access_token", ""))
            plan = payload.get("https://api.openai.com/auth", {}).get("chatgpt_plan_type", "free")
            out_path = os.path.join(out_dir, f"codex-{args.email}-{plan}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False)
            _safe_print(f"✅ 登录成功! → {out_path}")
        else:
            _safe_print("❌ 登录失败")
            sys.exit(1)
    else:
        # 批量登录
        run_batch(config)


if __name__ == "__main__":
    main()
