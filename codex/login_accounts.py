#!/usr/bin/env python3
"""
已注册账号 OTP 登录取 Token
用邮箱验证码登录（和接受邀请相同的流程），不需要密码。
"""

import argparse
import json
import os
import traceback
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
)


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def process_one_login(idx, total, email_addr, outlook_pwd, client_id, ms_refresh_token, proxy, fetch_session=True):
    tag = email_addr.split("@")[0]
    log_fn = lambda msg: _safe_print(f"[{tag}] {msg}")

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

        login.step6b_about_you()
        login._delay(0.5, 1.5)

        # 获取 auth code
        if not login.step7_get_auth_code():
            return False, email_addr, "获取 auth code 失败"

        # Token 交换
        token_data = login.step9_exchange_token()
        if not token_data:
            return False, email_addr, "token 交换失败"

        token_output = login._build_output(token_data)
        out_dir = os.path.join(SCRIPT_DIR, "output")
        os.makedirs(out_dir, exist_ok=True)

        token_path = os.path.join(out_dir, f"token-{email_addr}.json")
        with _file_lock:
            with open(token_path, "w", encoding="utf-8") as f:
                json.dump(token_output, f, ensure_ascii=False, indent=2)
        log_fn(f"✅ Token 获取成功 → {token_path}")

        # 获取 ChatGPT session
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

        return True, email_addr, "登录成功 + Token 已获取"
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
