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
        return None
    try:
        data = r.json()
        login._log(f"  响应: {json.dumps(data, ensure_ascii=False)[:300]}")
        return data
    except Exception:
        return {}


def signup_set_password(login: CodexLogin, password: str) -> bool:
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
    if r.status_code != 200:
        login._log(f"  ⚠️ 失败: {r.text[:300]}")
        return False
    return True


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

def do_register(email_addr, outlook_pwd, client_id, ms_refresh_token, proxy, log_fn):
    """
    执行注册。返回 (success, msg)
    如果账号已注册, 返回 (True, "已注册,跳过")
    """
    password = derive_password(email_addr)
    tag = email_addr.split("@")[0]

    login = CodexLogin(email=email_addr, proxy=proxy, tag=tag)

    login.step1_oauth_init()
    login.step2_sentinel_probe()

    data = signup_authorize_continue(login)
    if data is None:
        return False, "authorize/continue(signup) 失败"

    page_type = (data.get("page") or {}).get("type", "")

    # 已注册账号: 服务端返回 login_password 或 password
    if page_type in ("login_password", "password"):
        log_fn("账号已注册, 跳过注册步骤")
        return True, "已注册,跳过"

    # 新账号: 继续注册流程
    if not signup_set_password(login, password):
        return False, "设置密码失败"

    known_ids = get_known_mail_ids(
        email_addr, client_id, ms_refresh_token,
        impersonate=login.fp.impersonate, log_fn=login._log)

    if not signup_send_otp(login):
        return False, "发送注册 OTP 失败"

    login._delay(2.0, 5.0)
    log_fn("[注册] 等待验证码...")
    code = fetch_otp(
        email_addr, client_id, ms_refresh_token,
        known_ids=known_ids, timeout=120,
        impersonate=login.fp.impersonate, log_fn=login._log)

    if not code:
        return False, "OTP 获取超时"

    if not login.step6_validate_otp(code):
        return False, "OTP 验证失败"

    # 保存注册结果
    result = {
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
            json.dump(result, f, ensure_ascii=False, indent=2)

    log_fn(f"[注册] ✅ 注册成功 → {out_path}")
    return True, "注册成功"


# ══════════════════════════════════════════════════════════
# 接受邀请阶段
# ══════════════════════════════════════════════════════════

def do_accept(email_addr, outlook_pwd, client_id, ms_refresh_token, proxy, log_fn):
    """
    执行接受邀请。返回 (success, msg)
    """
    tag = email_addr.split("@")[0]
    password = derive_password(email_addr)

    # 搜索邀请邮件
    log_fn("[接受邀请] 搜索邀请邮件...")
    invite_results = search_invite_emails(
        email_addr, client_id, ms_refresh_token, log_fn=log_fn)

    if not invite_results:
        return False, "未找到邀请邮件"

    log_fn(f"[接受邀请] 找到 {len(invite_results)} 个邀请链接")
    for i, (link, subj) in enumerate(invite_results):
        log_fn(f"  [{i+1}] {link}")

    invite_url = invite_results[0][0]
    params = _parse_invite_params(invite_url)
    accept_wid = params.get("accept_wId") or params.get("wId")
    ws_name = params.get("inv_ws_name") or "Unknown"

    if accept_wid:
        log_fn(f"[接受邀请] 团队工作区: {ws_name} ({accept_wid})")

    # 登录
    log_fn("[接受邀请] 登录...")
    login = CodexLogin(email=email_addr, proxy=proxy, tag=tag)

    login.step1_oauth_init()
    login.step2_sentinel_probe()

    if not login.step3_authorize_continue():
        return False, "authorize/continue 失败"

    next_page = getattr(login, "_next_page_type", "")

    if next_page == "password":
        log_fn("[接受邀请] 使用密码验证...")
        if not login.step5_password_verify(password):
            return False, "密码验证失败"
    else:
        login.step4_sentinel_probe2()

        known_ids = get_known_mail_ids(
            email_addr, client_id, ms_refresh_token,
            impersonate=login.fp.impersonate, log_fn=login._log)

        if not login.step5_send_otp():
            return False, "send-otp 失败"

        login._delay(2.0, 5.0)

        log_fn("[接受邀请] 等待验证码...")
        code = fetch_otp(
            email_addr, client_id, ms_refresh_token,
            known_ids=known_ids, timeout=120,
            impersonate=login.fp.impersonate, log_fn=login._log)

        if not code:
            return False, "OTP 获取超时"

        if not login.step6_validate_otp(code):
            return False, "OTP 验证失败"

    if not login.step6b_about_you():
        return False, "about-you 失败"

    login._delay(0.5, 1.5)

    # 选择团队工作区
    if accept_wid:
        log_fn(f"[接受邀请] 选择团队工作区...")
        try:
            r = login.session.post(
                f"{AUTH}/api/accounts/workspace/select",
                json={"workspace_id": accept_wid},
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Origin": AUTH,
                    "User-Agent": login.fp.user_agent,
                    "Referer": f"{AUTH}/sign-in-with-chatgpt/codex/consent",
                },
                timeout=15, impersonate=login.fp.impersonate)
            log_fn(f"  workspace/select -> {r.status_code}")
            if r.status_code == 200:
                m = re.search(
                    r'login_verifier["\s:=]+([A-Za-z0-9_\-]{20,})', r.text)
                if m:
                    login._login_verifier = m.group(1)
                try:
                    ws_data = r.json()
                    cu = ws_data.get("continue_url", "")
                    if cu:
                        login._continue_url = cu
                except Exception:
                    pass
            else:
                log_fn(f"  workspace/select 失败: {r.text[:200]}")
        except Exception as e:
            log_fn(f"  workspace/select 异常: {e}")

    # 获取 auth code + token
    if not login.step7_get_auth_code():
        return False, "获取 auth code 失败"

    token_data = login.step9_exchange_token()
    if not token_data:
        return False, "token 交换失败"

    result = login._build_output(token_data)
    result["disabled"] = False

    account_id = result.get("account_id", "")
    payload = decode_jwt_payload(result.get("access_token", ""))
    auth_info = payload.get("https://api.openai.com/auth", {})
    plan = auth_info.get("chatgpt_plan_type", "free")

    # 保存 team token
    config = _load_config()
    output_dir = config.get("output_dir", "output")
    base_dir = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isabs(output_dir):
        output_dir = os.path.join(base_dir, output_dir)
    os.makedirs(output_dir, exist_ok=True)

    short_id = account_id[:8] if account_id else "unknown"
    out_filename = f"codex-{short_id}-{email_addr}-{plan}.json"
    out_path = os.path.join(output_dir, out_filename)

    with _file_lock:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False)

    log_fn(f"[接受邀请] ✅ Team Token 已保存 → {out_path}")
    log_fn(f"  account_id: {account_id}")
    log_fn(f"  plan: {plan}")
    return True, f"Team Token 已获取 ({plan})"


# ══════════════════════════════════════════════════════════
# 合并流程: 注册 → 接受邀请
# ══════════════════════════════════════════════════════════

def process_one(idx, total, email_addr, outlook_pwd, client_id, ms_refresh_token, proxy):
    tag = email_addr.split("@")[0]
    log_fn = lambda msg: _safe_print(f"[{tag}] {msg}")

    _safe_print(f"\n{'='*60}")
    _safe_print(f"  [{idx}/{total}] 注册+接受邀请: {email_addr}")
    _safe_print(f"  代理: {proxy or '无'}")
    _safe_print(f"{'='*60}")

    try:
        # 阶段1: 注册
        log_fn("━━━ 阶段1: 注册 ━━━")
        reg_ok, reg_msg = do_register(
            email_addr, outlook_pwd, client_id, ms_refresh_token, proxy, log_fn)

        if not reg_ok:
            return False, email_addr, f"注册失败: {reg_msg}"

        log_fn(f"注册结果: {reg_msg}")

        # 阶段2: 接受邀请
        log_fn("━━━ 阶段2: 接受邀请 ━━━")
        accept_ok, accept_msg = do_accept(
            email_addr, outlook_pwd, client_id, ms_refresh_token, proxy, log_fn)

        if not accept_ok:
            return False, email_addr, f"注册成功但接受邀请失败: {accept_msg}"

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
