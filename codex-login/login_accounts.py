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
    成功返回 {"ws_id": ..., "plan": ..., "token": {...}}，失败返回 None。
    """
    import time

    log_fn("🔄 add-phone 绕过: 密码重登录...")

    # 清 cookie，重新开始
    login.session.cookies.clear()

    # 新的 PKCE
    code_verifier, code_challenge = generate_pkce()
    import secrets as _secrets
    state = _secrets.token_urlsafe(24)
    login.code_verifier = code_verifier
    login.code_challenge = code_challenge
    login.state = state

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

    login._consent_url = f"{AUTH}/sign-in-with-chatgpt/codex/consent"
    log_fn("  [pwd-relogin] 获取 personal workspace token...")
    result = login.get_personal_workspace_token()
    if not result:
        log_fn("    ⚠️ 该账号无 personal workspace 或 personal token 获取失败")
        return None

    log_fn(f"    ✅ Token 获取成功! plan={result['plan']}")
    return result


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
            ws_result = _password_relogin(login, password, log_fn)
            if ws_result:
                # 密码重登录成功，直接保存 token
                plan = ws_result["plan"]
                token_output = ws_result["token"]
                out_dir = os.path.join(SCRIPT_DIR, "output")
                os.makedirs(out_dir, exist_ok=True)

                token_path = _save_token_file(out_dir, email_addr, plan, token_output)
                log_fn(f"✅ Token 获取成功 (密码重登录, {plan}) → {token_path}")

                if fetch_session:
                    try:
                        session_data = login.fetch_chatgpt_session(token_output.get("access_token", ""))
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

                return True, email_addr, f"登录成功 (密码重登录绕过 add-phone, {plan})"
            else:
                return False, email_addr, "add-phone 绕过失败或该账号无 personal workspace"

        login.step6b_about_you()
        login._delay(0.5, 1.5)

        ws_result = login.get_personal_workspace_token()
        if not ws_result:
            return False, email_addr, "该账号无 personal workspace"

        out_dir = os.path.join(SCRIPT_DIR, "output")
        os.makedirs(out_dir, exist_ok=True)

        plan = ws_result["plan"]
        token_output = ws_result["token"]
        token_path = _save_token_file(out_dir, email_addr, plan, token_output)
        log_fn(f"✅ Token ({plan}) → {token_path}")

        if fetch_session:
            try:
                session_data = login.fetch_chatgpt_session(token_output.get("access_token", ""))
                if session_data:
                    session_path = os.path.join(out_dir, f"session-{email_addr}.json")
                    with _file_lock:
                        with open(session_path, "w", encoding="utf-8") as f:
                            json.dump(session_data, f, ensure_ascii=False, indent=2)
                    log_fn(f"✅ Session ({plan}) → {session_path}")
                else:
                    log_fn(f"⚠️ Session ({plan}) 获取失败")
            except Exception as se:
                log_fn(f"⚠️ Session ({plan}) 异常: {se}")

        return True, email_addr, f"登录成功 + Token: {plan}"
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
