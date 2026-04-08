#!/usr/bin/env python3
"""
新账号注册脚本：邮箱 -> 密码 -> OTP 验证成功

主入口：
  python register_accounts.py
  python register_accounts.py --email xxx@hotmail.com

只负责注册到 OTP 验证成功。
"""

import argparse
import json
import os
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

from codex_login import (
    AUTH,
    CodexLogin,
    _file_lock,
    _load_config,
    _load_emails,
    _load_proxies,
    _safe_print,
    ensure_proxy_chain,
    fetch_otp,
    get_known_mail_ids,
)


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def derive_password(email_addr: str) -> str:
    return email_addr.split("@", 1)[0][:12]


def signup_authorize_continue(login: CodexLogin) -> bool:
    login._log("[Step 3] authorize/continue 提交邮箱 (signup)...")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": AUTH,
        "Referer": f"{AUTH}/create-account",
    }
    headers.update(login.fp.headers())
    if login._sentinel_token_1:
        headers["openai-sentinel-token"] = login._sentinel_token_1

    r = login.session.post(
        f"{AUTH}/api/accounts/authorize/continue",
        json={
            "username": {"kind": "email", "value": login.email},
            "screen_hint": "signup",
        },
        headers=headers,
        timeout=30,
        impersonate=login.fp.impersonate,
    )
    login._log(f"  authorize/continue(signup) -> {r.status_code}")
    if r.status_code != 200:
        login._log(f"  ⚠️ 失败: {r.text[:300]}")
        return False
    try:
        login._log(f"  响应: {json.dumps(r.json(), ensure_ascii=False)[:300]}")
    except Exception:
        pass
    return True


def signup_set_password(login: CodexLogin, password: str) -> bool:
    login._log(f"[Step 4] 提交注册密码: {password}")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": AUTH,
        "Referer": f"{AUTH}/create-account/password",
    }
    headers.update(login.fp.headers())

    r = login.session.post(
        f"{AUTH}/api/accounts/user/register",
        json={"username": login.email, "password": password},
        headers=headers,
        timeout=30,
        impersonate=login.fp.impersonate,
    )
    login._log(f"  user/register -> {r.status_code}")
    if r.status_code != 200:
        login._log(f"  ⚠️ 失败: {r.text[:300]}")
        return False
    return True


def signup_send_otp(login: CodexLogin) -> bool:
    login._log("[Step 5] 发送注册 OTP...")
    headers = {
        "Accept": "application/json",
        "Referer": f"{AUTH}/email-verification",
    }
    headers.update(login.fp.headers())

    r = login.session.get(
        f"{AUTH}/api/accounts/email-otp/send",
        headers=headers,
        timeout=30,
        impersonate=login.fp.impersonate,
    )
    login._log(f"  email-otp/send -> {r.status_code}")
    if r.status_code != 200:
        login._log(f"  ⚠️ 失败: {r.text[:300]}")
        return False
    return True


def process_one_registration(idx, total, email_addr, outlook_pwd, client_id, ms_refresh_token, proxy):
    tag = email_addr.split("@")[0]
    log_fn = lambda msg: _safe_print(f"[{tag}] {msg}")

    _safe_print(f"\n{'='*60}")
    _safe_print(f"  [{idx}/{total}] 注册: {email_addr}")
    _safe_print(f"  代理: {proxy or '无'}")
    _safe_print(f"{'='*60}")

    try:
        login = CodexLogin(email=email_addr, proxy=proxy, tag=tag)
        password = derive_password(email_addr)

        login.step1_oauth_init()
        login.step2_sentinel_probe()

        if not signup_authorize_continue(login):
            return False, email_addr, "authorize/continue(signup) 失败"

        if not signup_set_password(login, password):
            return False, email_addr, "设置密码失败"

        known_ids = get_known_mail_ids(
            email_addr,
            client_id,
            ms_refresh_token,
            impersonate=login.fp.impersonate,
            log_fn=login._log,
        )

        if not signup_send_otp(login):
            return False, email_addr, "发送注册 OTP 失败"

        login._delay(2.0, 5.0)
        log_fn("[Step 6] 等待验证码...")
        code = fetch_otp(
            email_addr,
            client_id,
            ms_refresh_token,
            known_ids=known_ids,
            timeout=120,
            impersonate=login.fp.impersonate,
            log_fn=login._log,
        )
        if not code:
            return False, email_addr, "OTP 获取超时"

        if not login.step6_validate_otp(code):
            return False, email_addr, "OTP 验证失败"

        result = {
            "email": email_addr,
            "registered": True,
            "registration_method": "email_password_otp",
            "password_rule": "email_local_part_first_12",
            "derived_password": password,
            "otp_validated": True,
        }

        out_dir = os.path.join(SCRIPT_DIR, "output")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"registered-{email_addr}.json")

        with _file_lock:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)

        log_fn(f"注册成功（已完成 OTP 验证）→ {out_path}")
        return True, email_addr, "注册成功（OTP 已验证）"
    except Exception as e:
        log_fn(f"异常: {e}")
        traceback.print_exc()
        return False, email_addr, f"异常: {e}"


def main():
    parser = argparse.ArgumentParser(description="OpenAI 新账号注册")
    parser.add_argument("--email", help="只处理指定邮箱")
    parser.add_argument("--workers", type=int, default=1, help="并发数")
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
    _safe_print("  新账号注册")
    _safe_print("=" * 60)
    _safe_print(f"已加载 {len(entries)} 个账号")
    _safe_print(f"已加载 {len(raw_proxies)} 个代理")

    def task(idx, entry):
        email_addr, outlook_pwd, client_id, ms_refresh_token = entry
        raw_proxy = raw_proxies[(idx - 1) % len(raw_proxies)] if raw_proxies else ""
        proxy = ensure_proxy_chain(raw_proxy) if raw_proxy else raw_proxy
        return process_one_registration(idx, len(entries), email_addr, outlook_pwd, client_id, ms_refresh_token, proxy)

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
    _safe_print("  注册结果汇总")
    _safe_print(f"{'='*60}")
    success = sum(1 for ok, _, _ in results if ok)
    fail = len(results) - success
    for ok, addr, msg in results:
        _safe_print(f"  [{'OK' if ok else 'FAIL'}] {addr}: {msg}")
    _safe_print(f"\n  总计: {len(results)} | 成功: {success} | 失败: {fail}")


if __name__ == "__main__":
    main()
