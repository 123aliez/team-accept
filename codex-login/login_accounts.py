#!/usr/bin/env python3
"""
已注册账号 OTP 登录取 Token
用邮箱验证码登录（和接受邀请相同的流程），不需要密码。
遇到 add-phone 时自动切换为密码重登录绕过。
"""

import argparse
import base64
import json
import os
import re
import traceback
from urllib.parse import urlparse, parse_qs, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

from codex_login import (
    CodexLogin,
    _file_lock,
    _load_config,
    _load_emails,
    _load_proxies,
    _safe_print,
    ensure_proxy_chain,
    get_known_mail_ids,
    fetch_otp,
    fetch_sentinel_token,
    generate_pkce,
    decode_jwt_payload,
    AUTH,
    SENTINEL,
    CODEX_CLIENT_ID,
    CODEX_REDIRECT_URI,
    CODEX_SCOPE,
)


def _save_token_file(out_dir, email_addr, plan, token_output):
    """根据 plan_type 保存 token 文件，返回文件路径"""
    if plan == "team":
        fname = f"codex-{email_addr}-team.json"
    else:
        fname = f"token-{email_addr}.json"
    path = os.path.join(out_dir, fname)
    with _file_lock:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(token_output, f, ensure_ascii=False, indent=2)
    return path


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _decode_jwt_segment(seg: str) -> dict:
    """解码 JWT 的一个 segment"""
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode((raw + pad).encode("ascii")))
    except Exception:
        return {}


def _password_relogin(login, password, log_fn):
    """
    add-phone 绕过: 清 cookie 重新走 OAuth + 密码登录。
    参考项目验证过的方案：密码登录不触发 add-phone。
    成功返回 (token_data, code_verifier, state)，失败返回 None。
    """
    import time

    log_fn("🔄 add-phone 绕过: 密码重登录...")

    # 清 cookie，重新开始
    login.session.cookies.clear()

    # 新的 PKCE
    code_verifier, code_challenge = generate_pkce()
    import secrets as _secrets
    state = _secrets.token_urlsafe(24)

    # 1. OAuth init
    log_fn("  [pwd-relogin] OAuth init...")
    params = {
        "client_id": CODEX_CLIENT_ID,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "codex_cli_simplified_flow": "true",
        "id_token_add_organizations": "true",
        "prompt": "login",
        "redirect_uri": CODEX_REDIRECT_URI,
        "response_type": "code",
        "scope": CODEX_SCOPE,
        "state": state,
    }
    url = f"{AUTH}/oauth/authorize"
    for step in range(5):
        r = login.session.get(
            url, params=params if step == 0 else None,
            headers={"Accept": "text/html,*/*;q=0.8", "User-Agent": login.fp.user_agent},
            allow_redirects=False, impersonate=login.fp.impersonate)
        log_fn(f"    [{step}] {r.status_code} {urlparse(url).path}")
        if r.status_code in (301, 302, 303, 307, 308):
            location = r.headers.get("location", "")
            if location.startswith("/"):
                p = urlparse(url)
                location = f"{p.scheme}://{p.netloc}{location}"
            url = location
            params = None
        else:
            break

    new_did = login.session.cookies.get("oai-did") or ""

    # 2. Sentinel
    log_fn("  [pwd-relogin] Sentinel...")
    sentinel_token = fetch_sentinel_token(
        login.session, login.fp, "authorize_continue", login._log)

    # 3. authorize/continue (screen_hint: login)
    log_fn("  [pwd-relogin] authorize/continue (login)...")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": AUTH,
        "User-Agent": login.fp.user_agent,
    }
    headers.update(login.fp.headers())
    if sentinel_token:
        headers["openai-sentinel-token"] = sentinel_token

    r = login.session.post(
        f"{AUTH}/api/accounts/authorize/continue",
        json={"username": {"value": login.email, "kind": "email"}, "screen_hint": "login"},
        headers=headers, timeout=30, impersonate=login.fp.impersonate)
    log_fn(f"    authorize/continue -> {r.status_code}")
    if r.status_code != 200:
        log_fn(f"    ⚠️ 失败: {r.text[:300]}")
        return None

    # 4. password/verify
    log_fn(f"  [pwd-relogin] password/verify...")
    sentinel_token2 = fetch_sentinel_token(
        login.session, login.fp, "authorize_continue", login._log)

    pwd_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": AUTH,
        "User-Agent": login.fp.user_agent,
    }
    pwd_headers.update(login.fp.headers())
    if sentinel_token2:
        pwd_headers["openai-sentinel-token"] = sentinel_token2

    r = login.session.post(
        f"{AUTH}/api/accounts/password/verify",
        json={"password": password},
        headers=pwd_headers, timeout=30, impersonate=login.fp.impersonate)
    log_fn(f"    password/verify -> {r.status_code}")

    if r.status_code != 200:
        log_fn(f"    ⚠️ 密码验证失败: {r.text[:300]}")
        return None

    # 检查是否需要二次 OTP
    try:
        pwd_data = r.json()
        page_type = (pwd_data.get("page") or {}).get("type", "")
        if "otp" in page_type or "verify" in str(pwd_data.get("continue_url", "")):
            log_fn("    密码登录触发二次 OTP，等待...")
            # 需要调用方传入邮件参数来获取 OTP，这里先返回 None
            # 后续可扩展
            log_fn("    ⚠️ 二次 OTP 暂不支持")
            return None
    except Exception:
        pass

    # 5. 从 cookie 提取 workspace_id
    auth_cookie = login.session.cookies.get("oai-client-auth-session") or ""
    if not auth_cookie:
        log_fn("    ⚠️ cookie 中无 oai-client-auth-session")
        return None

    workspace_id = ""
    for part in auth_cookie.split("."):
        decoded = _decode_jwt_segment(part)
        if isinstance(decoded, dict) and "workspaces" in decoded:
            workspaces = decoded.get("workspaces") or []
            if workspaces:
                workspace_id = str((workspaces[0] or {}).get("id") or "").strip()
            break

    if not workspace_id:
        log_fn("    ⚠️ cookie 中无 workspace 信息")
        return None

    log_fn(f"    workspace_id: {workspace_id}")

    # 6. workspace/select
    log_fn("  [pwd-relogin] workspace/select...")
    r = login.session.post(
        f"{AUTH}/api/accounts/workspace/select",
        json={"workspace_id": workspace_id},
        headers={
            "Content-Type": "application/json",
            "Referer": f"{AUTH}/sign-in-with-chatgpt/codex/consent",
            "User-Agent": login.fp.user_agent,
        },
        timeout=30, impersonate=login.fp.impersonate)
    log_fn(f"    workspace/select -> {r.status_code}")

    if r.status_code != 200:
        log_fn(f"    ⚠️ workspace/select 失败: {r.text[:300]}")
        return None

    try:
        ws_data = r.json()
        continue_url = ws_data.get("continue_url", "")
    except Exception:
        continue_url = ""

    if not continue_url:
        log_fn("    ⚠️ 无 continue_url")
        return None

    log_fn(f"    continue_url 获取成功")

    # 7. 重定向链获取 code
    log_fn("  [pwd-relogin] 重定向链...")
    current_url = continue_url
    auth_code = ""
    for i in range(15):
        r = login.session.get(
            current_url, allow_redirects=False,
            headers={"User-Agent": login.fp.user_agent},
            timeout=15, impersonate=login.fp.impersonate)

        if r.status_code in (301, 302, 303, 307, 308):
            next_url = r.headers.get("Location", "")
            if next_url and not next_url.startswith("http"):
                p = urlparse(current_url)
                next_url = f"{p.scheme}://{p.netloc}{next_url}"
        elif r.status_code == 200:
            # consent 页面需要 POST accept
            if "consent_challenge=" in current_url:
                cr = login.session.post(
                    current_url, data={"action": "accept"},
                    allow_redirects=False,
                    headers={"User-Agent": login.fp.user_agent},
                    timeout=15, impersonate=login.fp.impersonate)
                next_url = cr.headers.get("Location", "") if cr.status_code in (301, 302, 303, 307, 308) else ""
                if next_url and not next_url.startswith("http"):
                    p = urlparse(current_url)
                    next_url = f"{p.scheme}://{p.netloc}{next_url}"
            else:
                # meta refresh
                meta = re.search(r'content=["\']?\d+;\s*url=([^"\'>\s]+)', r.text, re.IGNORECASE)
                next_url = meta.group(1) if meta else ""
            if not next_url:
                break
        else:
            log_fn(f"    重定向 [{i}] 异常: {r.status_code}")
            break

        # 检查是否拿到 code
        if "code=" in next_url and "state=" in next_url:
            parsed = urlparse(next_url)
            qs = parse_qs(parsed.query)
            auth_code = qs.get("code", [""])[0]
            log_fn(f"    ✅ 拿到 auth code!")
            break

        current_url = next_url
        time.sleep(0.3)

    if not auth_code:
        log_fn("    ⚠️ 重定向链中未找到 code")
        return None

    # 8. Token 交换
    log_fn("  [pwd-relogin] Token 交换...")
    r = login.session.post(
        f"{AUTH}/api/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": CODEX_CLIENT_ID,
            "code": auth_code,
            "redirect_uri": CODEX_REDIRECT_URI,
            "code_verifier": code_verifier,
        },
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Origin": AUTH,
            "User-Agent": login.fp.user_agent,
        },
        timeout=30, impersonate=login.fp.impersonate)
    log_fn(f"    token -> {r.status_code}")

    if r.status_code != 200:
        log_fn(f"    ⚠️ token 交换失败: {r.text[:300]}")
        return None

    try:
        token_data = r.json()
        log_fn(f"    ✅ Token 获取成功! keys: {list(token_data.keys())}")
        return token_data
    except Exception as e:
        log_fn(f"    ⚠️ 解析 token 响应失败: {e}")
        return None


def process_one_login(idx, total, email_addr, outlook_pwd, client_id, ms_refresh_token, proxy, fetch_session=True):
    tag = email_addr.split("@")[0]
    log_fn = lambda msg: _safe_print(f"[{tag}] {msg}")
    # 密码 = 邮箱 @ 前面的部分
    password = email_addr.split("@")[0].split("+")[0]

    _safe_print(f"\n{'='*60}")
    _safe_print(f"  [{idx}/{total}] OTP 登录: {email_addr}")
    _safe_print(f"  代理: {proxy or '无'}")
    _safe_print(f"{'='*60}")

    try:
        login = CodexLogin(email=email_addr, proxy=proxy, tag=tag)

        # 和 accept_invite.py 完全一样的流程
        login.step1_oauth_init()
        login.step2_sentinel_probe()

        if not login.step3_authorize_continue():
            return False, email_addr, "authorize/continue 失败"

        # ── 检查服务端期望的登录方式 ──
        next_page = getattr(login, "_next_page_type", "")

        if next_page == "password":
            # 服务端要求密码登录（账号注册时设置了密码）
            log_fn(f"服务端要求密码登录, 使用密码验证...")
            if not login.step5_password_verify(password):
                return False, email_addr, "密码验证失败"
        else:
            # 默认 OTP 流程
            login.step4_sentinel_probe2()

            # 快照旧邮件
            known_ids = get_known_mail_ids(
                email_addr, client_id, ms_refresh_token,
                impersonate=login.fp.impersonate, log_fn=login._log)

            if not login.step5_send_otp():
                return False, email_addr, "send-otp 失败 (账号可能未注册)"

            login._delay(2.0, 5.0)

            # 获取 OTP
            log_fn("等待验证码...")
            code = fetch_otp(
                email_addr, client_id, ms_refresh_token,
                known_ids=known_ids, timeout=120,
                impersonate=login.fp.impersonate, log_fn=login._log)

            if not code:
                return False, email_addr, "OTP 获取超时"

            if not login.step6_validate_otp(code):
                return False, email_addr, "OTP 验证失败"

        # 检查 validate-otp / password-verify 响应的 _consent_url
        consent_url = getattr(login, "_consent_url", "") or ""

        # ── add-phone 检测: 用密码重登录绕过 ──
        if "add-phone" in consent_url:
            log_fn("检测到 add-phone，切换密码重登录绕过...")
            token_data = _password_relogin(login, password, log_fn)
            if token_data:
                # 密码重登录成功，直接保存 token
                token_output = login._build_output(token_data)
                out_dir = os.path.join(SCRIPT_DIR, "output")
                os.makedirs(out_dir, exist_ok=True)

                token_path = os.path.join(out_dir, f"token-{email_addr}.json")
                with _file_lock:
                    with open(token_path, "w", encoding="utf-8") as f:
                        json.dump(token_output, f, ensure_ascii=False, indent=2)
                log_fn(f"✅ Token 获取成功 (密码重登录) → {token_path}")

                if fetch_session:
                    try:
                        session_data = login.fetch_chatgpt_session(token_data.get("access_token", ""))
                        if session_data:
                            session_path = os.path.join(out_dir, f"session-{email_addr}.json")
                            with _file_lock:
                                with open(session_path, "w", encoding="utf-8") as f:
                                    json.dump(session_data, f, ensure_ascii=False, indent=2)
                            log_fn(f"✅ Session 导出成功 → {session_path}")
                        else:
                            log_fn("⚠️ Session 获取失败")
                    except Exception as se:
                        log_fn(f"⚠️ Session 获取异常: {se}")

                return True, email_addr, "登录成功 (密码重登录绕过 add-phone)"
            else:
                return False, email_addr, "add-phone 绕过失败"

        login.step6b_about_you()
        login._delay(0.5, 1.5)

        # 直接用 get_all_workspace_tokens 逐个尝试所有 workspace
        all_tokens = login.get_all_workspace_tokens()
        if not all_tokens:
            return False, email_addr, "所有 workspace 均未获取到 token"

        out_dir = os.path.join(SCRIPT_DIR, "output")
        os.makedirs(out_dir, exist_ok=True)

        saved_plans = []
        for ws_result in all_tokens:
            plan = ws_result["plan"]
            token_output = ws_result["token"]
            token_path = _save_token_file(out_dir, email_addr, plan, token_output)
            log_fn(f"✅ Token ({plan}) → {token_path}")
            saved_plans.append(plan)

            # 获取 ChatGPT session
            if fetch_session:
                try:
                    session_data = login.fetch_chatgpt_session(token_output.get("access_token", ""))
                    if session_data:
                        suffix = f"-{plan}" if plan == "team" else ""
                        session_path = os.path.join(out_dir, f"session-{email_addr}{suffix}.json")
                        with _file_lock:
                            with open(session_path, "w", encoding="utf-8") as f:
                                json.dump(session_data, f, ensure_ascii=False, indent=2)
                        log_fn(f"✅ Session ({plan}) → {session_path}")
                    else:
                        log_fn(f"⚠️ Session ({plan}) 获取失败")
                except Exception as se:
                    log_fn(f"⚠️ Session ({plan}) 异常: {se}")

        return True, email_addr, f"登录成功 + Token: {', '.join(saved_plans)}"
    except Exception as e:
        log_fn(f"异常: {e}")
        traceback.print_exc()
        return False, email_addr, f"异常: {e}"


def main():
    parser = argparse.ArgumentParser(description="已注册账号 OTP 登录取 Token")
    parser.add_argument("--email", help="只处理指定邮箱")
    parser.add_argument("--workers", type=int, default=1, help="并发数")
    parser.add_argument("--no-session", action="store_true", help="不导出 Session")
    args = parser.parse_args()

    emails_path = os.path.join(SCRIPT_DIR, "emails.txt")
    proxies_path = os.path.join(SCRIPT_DIR, "proxies.txt")

    entries = _load_emails(emails_path)
    if args.email:
        entries = [e for e in entries if e[0] == args.email]
    if not entries:
        _safe_print("[Error] 无有效账号")
        raise SystemExit(1)

    raw_proxies = _load_proxies(proxies_path)
    config = _load_config()
    if not raw_proxies and config.get("proxy"):
        raw_proxies = [config["proxy"]]

    _safe_print("=" * 60)
    _safe_print("  OTP 登录取 Token")
    _safe_print("=" * 60)
    _safe_print(f"已加载 {len(entries)} 个账号")
    _safe_print(f"已加载 {len(raw_proxies)} 个代理")

    def task(idx, entry):
        email_addr, outlook_pwd, client_id, ms_refresh_token = entry
        raw_proxy = raw_proxies[(idx - 1) % len(raw_proxies)] if raw_proxies else ""
        proxy = ensure_proxy_chain(raw_proxy) if raw_proxy else raw_proxy
        return process_one_login(idx, len(entries), email_addr, outlook_pwd, client_id, ms_refresh_token, proxy, fetch_session=not args.no_session)

    results = []
    if args.workers <= 1:
        for i, entry in enumerate(entries, 1):
            results.append(task(i, entry))
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(task, i, e): i for i, e in enumerate(entries, 1)}
            for future in as_completed(futures):
                results.append(future.result())

    _safe_print(f"\n{'='*60}")
    _safe_print("  登录结果汇总")
    _safe_print(f"{'='*60}")
    success = sum(1 for ok, _, _ in results if ok)
    fail = len(results) - success
    for ok, addr, msg in results:
        _safe_print(f"  [{'OK' if ok else 'FAIL'}] {addr}: {msg}")
    _safe_print(f"\n  总计: {len(results)} | 成功: {success} | 失败: {fail}")


if __name__ == "__main__":
    main()
