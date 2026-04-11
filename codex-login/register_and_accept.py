#!/usr/bin/env python3
"""
注册 + 接受邀请 一体化脚本

流程:
  1. 注册账号 (如果已注册则自动跳过)
  2. 搜索邀请邮件
  3. 登录 + 选择团队工作区 + 获取 Team Token

用法:
  python register_and_accept.py
  python register_and_accept.py --email xxx@hotmail.com
  python register_and_accept.py --workers 3
"""

import argparse
import json
import os
import re
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

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
    fetch_sentinel_token,
    get_known_mail_ids,
    decode_jwt_payload,
)

from accept_invite import (
    search_invite_emails,
    _parse_invite_params,
    process_one as accept_process_one,
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CODEX_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "codex")


# ══════════════════════════════════════════════════════════
# 注册相关函数 (复用 codex/register_accounts.py 逻辑)
# ══════════════════════════════════════════════════════════

def derive_password(email_addr: str) -> str:
    local = email_addr.split("@", 1)[0]
    return local.split("+", 1)[0]


def signup_authorize_continue(login: CodexLogin) -> dict:
    """注册流程的 authorize/continue, 返回响应数据"""
    login._log("[注册] authorize/continue (signup)...")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": AUTH,
        "Referer": f"{AUTH}/create-account",
    }
    headers.update(login.fp.headers())
    if login._sentinel_token_1:
        headers["openai-sentinel-token"] = login._sentinel_token_1

    import time as _time
    for attempt in range(3):
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
        if r.status_code == 429:
            wait = (attempt + 1) * 10
            login._log(f"  ⚠️ 频率限制, {wait}秒后重试 ({attempt+1}/3)")
            _time.sleep(wait)
            continue
        break
    if r.status_code != 200:
        login._log(f"  ⚠️ 失败: {r.text[:300]}")
        return None
    try:
        data = r.json()
        login._log(f"  响应: {json.dumps(data, ensure_ascii=False)[:300]}")
        return data
    except Exception:
        return {}


def signup_set_password(login: CodexLogin, password: str):
    """返回: "ok" | "already_registered" | "error" """
    login._log(f"[注册] 提交密码: {password}")
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
    if r.status_code == 200:
        return "ok"
    body = r.text[:300]
    login._log(f"  ⚠️ 失败: {body}")
    # 400 "Failed to register username" = 已注册
    if r.status_code == 400 and "register" in body.lower():
        return "already_registered"
    return "error"


def signup_send_otp(login: CodexLogin) -> bool:
    login._log("[注册] 发送注册 OTP...")
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


# ══════════════════════════════════════════════════════════
# 注册阶段
# ══════════════════════════════════════════════════════════

def process_one(idx, total, email_addr, outlook_pwd, client_id, ms_refresh_token, proxy):
    """
    一体化流程: 注册(到about-you) → 搜邀请 → 选workspace → 拿token
    注册完直接复用同一个 session, 不需要二次登录
    已注册账号自动走密码登录
    """
    tag = email_addr.split("@")[0]
    log_fn = lambda msg: _safe_print(f"[{tag}] {msg}")
    password = derive_password(email_addr)

    _safe_print(f"\n{'='*60}")
    _safe_print(f"  [{idx}/{total}] 注册+接受邀请: {email_addr}")
    _safe_print(f"  代理: {proxy or '无'}")
    _safe_print(f"{'='*60}")

    try:
        login = CodexLogin(email=email_addr, proxy=proxy, tag=tag)

        # ── 阶段1: 注册 / 登录 ──
        log_fn("━━━ 阶段1: 注册/登录 ━━━")

        login.step1_oauth_init()
        login.step2_sentinel_probe()

        # 用 signup 方式调 authorize/continue, 判断是新号还是老号
        data = signup_authorize_continue(login)
        if data is None:
            return False, email_addr, "authorize/continue(signup) 失败"

        page_type = (data.get("page") or {}).get("type", "")
        already_registered = page_type in ("login_password", "password")

        if already_registered:
            log_fn("账号已注册, 跳过注册步骤")
        else:
            # 新账号: 注册流程
            reg_result = signup_set_password(login, password)
            if reg_result == "already_registered":
                already_registered = True
                log_fn("账号已注册(register返回400)")
            elif reg_result != "ok":
                return False, email_addr, "设置密码失败"
            else:
                # 注册成功, 继续 OTP 验证
                known_ids = get_known_mail_ids(
                    email_addr, client_id, ms_refresh_token,
                    impersonate=login.fp.impersonate, log_fn=login._log)

                if not signup_send_otp(login):
                    return False, email_addr, "发送注册 OTP 失败"

                login._delay(2.0, 5.0)
                log_fn("[注册] 等待验证码...")
                code = fetch_otp(
                    email_addr, client_id, ms_refresh_token,
                    known_ids=known_ids, timeout=120,
                    impersonate=login.fp.impersonate, log_fn=login._log)

                if not code:
                    return False, email_addr, "OTP 获取超时"

                if not login.step6_validate_otp(code):
                    return False, email_addr, "OTP 验证失败"

                # 保存注册结果
                reg_data = {
                    "email": email_addr,
                    "registered": True,
                    "registration_method": "email_password_otp",
                    "password_rule": "email_local_part_no_alias",
                    "derived_password": password,
                    "otp_validated": True,
                }
                out_dir = os.path.join(CODEX_DIR, "output")
                os.makedirs(out_dir, exist_ok=True)
                out_path = os.path.join(out_dir, f"registered-{email_addr}.json")
                with _file_lock:
                    with open(out_path, "w", encoding="utf-8") as f:
                        json.dump(reg_data, f, ensure_ascii=False, indent=2)
                log_fn(f"[注册] ✅ 注册成功")

        reg_msg = "已注册" if already_registered else "注册成功"
        log_fn(f"阶段1完成: {reg_msg}")

        # ── 阶段2: 接受邀请 (直接复用 accept_invite.py 已验证的流程) ──
        log_fn("━━━ 阶段2: 接受邀请 ━━━")

        accept_ok, _, accept_msg = accept_process_one(
            idx, total, email_addr, outlook_pwd, client_id, ms_refresh_token, proxy)

        if not accept_ok:
            return False, email_addr, f"{reg_msg}但接受邀请失败: {accept_msg}"

        return True, email_addr, f"{reg_msg} + {accept_msg}"

    except Exception as e:
        log_fn(f"异常: {e}")
        traceback.print_exc()
        return False, email_addr, f"异常: {e}"


def main():
    parser = argparse.ArgumentParser(description="注册 + 接受邀请 一体化")
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
    _safe_print("  注册 + 接受邀请 一体化")
    _safe_print("=" * 60)
    _safe_print(f"已加载 {len(entries)} 个账号")
    _safe_print(f"已加载 {len(raw_proxies)} 个代理")

    def task(idx, entry):
        email_addr, outlook_pwd, client_id, ms_refresh_token = entry
        raw_proxy = raw_proxies[(idx - 1) % len(raw_proxies)] if raw_proxies else ""
        proxy = ensure_proxy_chain(raw_proxy) if raw_proxy else raw_proxy
        return process_one(idx, len(entries), email_addr, outlook_pwd, client_id, ms_refresh_token, proxy)

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
    _safe_print("  结果汇总")
    _safe_print(f"{'='*60}")
    success = sum(1 for ok, _, _ in results if ok)
    fail = len(results) - success
    for ok, addr, msg in results:
        _safe_print(f"  [{'OK' if ok else 'FAIL'}] {addr}: {msg}")
    _safe_print(f"\n  总计: {len(results)} | 成功: {success} | 失败: {fail}")


if __name__ == "__main__":
    main()
