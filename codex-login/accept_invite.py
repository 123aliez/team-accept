#!/usr/bin/env python3
"""
accept_invite.py - 自动接受 ChatGPT Team 邀请并获取 Codex 格式 Token

复用 codex_login.py 的 IMAP、指纹、代理加载等模块
共用 emails.txt / proxies.txt

前提: 账号必须已在 OpenAI 注册完成

用法:
  python accept_invite.py              # 批量处理所有账号
  python accept_invite.py --search     # 仅搜索邀请邮件，不接受
  python accept_invite.py --email xxx  # 只处理指定邮箱
"""

import argparse
import os
import sys
import re
import json
import time
import random
import threading
import traceback
import email as email_lib
from datetime import datetime
from email.header import decode_header
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

from html import unescape as html_unescape

# 复用 codex_login 的模块
from codex_login import (
    Fingerprint,
    _safe_print,
    _load_emails,
    _load_proxies,
    _load_config,
    _get_imap_access_token,
    _imap_connect,
    fetch_sentinel_token,
    CodexLogin,
    decode_jwt_payload,
    get_known_mail_ids,
    fetch_otp,
    ensure_proxy_chain,
    AUTH,
    _print_lock,
    _file_lock,
)


# ══════════════════════════════════════════════════════════
# IMAP 搜索邀请邮件
# ══════════════════════════════════════════════════════════

def _extract_body(msg):
    """提取邮件正文 (HTML + Plain)"""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/html", "text/plain"):
                try:
                    charset = part.get_content_charset() or "utf-8"
                    body += part.get_payload(decode=True).decode(charset, errors="ignore")
                except Exception:
                    pass
    else:
        try:
            charset = msg.get_content_charset() or "utf-8"
            body = msg.get_payload(decode=True).decode(charset, errors="ignore")
        except Exception:
            pass
    return body


def _extract_invite_links(html_body):
    """从邮件正文提取邀请链接"""
    href_links = re.findall(r'href=["\']([^"\']+)["\']', html_body)
    raw_links = re.findall(r'https?://[^\s"\'<>]+', html_body)
    all_links = href_links + raw_links

    invite_patterns = [
        r'chatgpt\.com/auth/login.*accept_wId',
        r'chatgpt\.com/invite',
        r'chat\.openai\.com/invite',
        r'platform\.openai\.com.*invite',
        r'openai\.com.*invite',
        r'chatgpt\.com.*join',
        r'chatgpt\.com.*team',
    ]

    invite_links = []
    for link in all_links:
        link = html_unescape(link)
        link = link.split('"')[0].split("'")[0].rstrip('>')
        for pattern in invite_patterns:
            if re.search(pattern, link, re.IGNORECASE):
                invite_links.append(link)
                break

    return invite_links


def search_invite_emails(email_addr, client_id, refresh_token,
                         impersonate="chrome136", log_fn=None):
    """
    搜索 IMAP 收件箱中的 ChatGPT Team 邀请邮件
    返回: [(invite_url, subject), ...]
    """
    _log = log_fn or _safe_print

    try:
        access_token, imap_server = _get_imap_access_token(
            client_id, refresh_token, impersonate)
        imap = _imap_connect(email_addr, access_token, imap_server)
    except Exception as e:
        _log(f"[Invite] IMAP 连接失败: {e}")
        return []

    results = []

    try:
        imap.select("INBOX")

        search_criteria = [
            '(FROM "noreply@tm.openai.com")',
            '(FROM "noreply@openai.com")',
            '(FROM "openai.com")',
        ]

        seen_ids = set()

        # 先搜索全部邮件，找出最近的发件人，辅助调试
        try:
            status_all, data_all = imap.search(None, "ALL")
            if status_all == "OK" and data_all[0]:
                all_ids = data_all[0].split()
                _log(f"[Invite] 收件箱共 {len(all_ids)} 封邮件，扫描最近 10 封的发件人...")
                for mid in reversed(all_ids[-10:]):
                    try:
                        st, md = imap.fetch(mid, "(BODY[HEADER.FIELDS (FROM SUBJECT)])")
                        if st == "OK":
                            _log(f"[Invite]   #{mid.decode()}: {md[0][1].decode(errors='ignore').strip()}")
                    except Exception:
                        pass
        except Exception as e:
            _log(f"[Invite] 全量扫描异常: {e}")

        for criteria in search_criteria:
            try:
                status, data = imap.search(None, criteria)
                _log(f"[Invite] 搜索 {criteria} -> {status}, 找到 {len(data[0].split()) if data[0] else 0} 封")
                if status != "OK" or not data[0]:
                    continue

                msg_ids = data[0].split()
                for mid in reversed(msg_ids[-20:]):
                    if mid in seen_ids:
                        continue
                    seen_ids.add(mid)

                    status, msg_data = imap.fetch(mid, "(RFC822)")
                    if status != "OK":
                        continue

                    msg = email_lib.message_from_bytes(msg_data[0][1])

                    subject = ""
                    raw_subject = msg.get("Subject", "")
                    if raw_subject:
                        decoded = decode_header(raw_subject)
                        subject = "".join(
                            part.decode(enc or "utf-8") if isinstance(part, bytes) else part
                            for part, enc in decoded)

                    body = _extract_body(msg)

                    invite_keywords = [
                        "invite", "invitation", "join", "team",
                        "workspace",
                    ]
                    text_to_check = (subject + " " + body[:1000]).lower()
                    is_invite = any(kw in text_to_check for kw in invite_keywords)

                    if not is_invite:
                        continue

                    _log(f"[Invite] 邀请邮件: {subject}")

                    links = _extract_invite_links(body)
                    for link in links:
                        results.append((link, subject))

            except Exception as e:
                _log(f"[Invite] 搜索异常: {e}")
                continue

    finally:
        try:
            imap.logout()
        except Exception:
            pass

    # 去重
    seen = set()
    unique = []
    for link, subj in results:
        if link not in seen:
            seen.add(link)
            unique.append((link, subj))

    return unique


def _parse_invite_params(invite_url):
    """从邀请链接提取关键参数"""
    parsed = urlparse(invite_url)
    params = parse_qs(parsed.query)
    return {
        "accept_wId": params.get("accept_wId", [None])[0],
        "wId": params.get("wId", [None])[0],
        "inv_email": params.get("inv_email", [None])[0],
        "inv_ws_name": params.get("inv_ws_name", [None])[0],
    }


# ══════════════════════════════════════════════════════════
# 单账号处理 (已验证的工作流程)
# ══════════════════════════════════════════════════════════

def process_one(idx, total, email_addr, outlook_pwd, client_id,
                ms_refresh_token, proxy, search_only=False):
    """
    处理单个账号: 搜索邀请 → CodexLogin 登录 → 选择团队工作区 → 保存 token

    前提: 账号必须已在 OpenAI 完成注册 (authorize/continue 返回
    email_otp_verification 才能继续)
    """
    tag = email_addr.split("@")[0]

    _safe_print(f"\n{'='*60}")
    _safe_print(f"  [{idx}/{total}] {email_addr}")
    _safe_print(f"  代理: {proxy or '无'}")
    _safe_print(f"{'='*60}")

    log_fn = lambda msg: _safe_print(f"[{tag}] {msg}")

    # ── Step 1: 搜索邀请邮件 ──
    log_fn("[1/4] 搜索邀请邮件...")

    invite_results = search_invite_emails(
        email_addr, client_id, ms_refresh_token,
        log_fn=log_fn)

    if not invite_results:
        log_fn("未找到邀请邮件，跳过")
        return False, email_addr, "未找到邀请邮件"

    log_fn(f"找到 {len(invite_results)} 个邀请链接:")
    for i, (link, subj) in enumerate(invite_results):
        log_fn(f"  [{i+1}] {link}")
        log_fn(f"       主题: {subj}")

    # 解析 accept_wId (团队工作区 ID)
    invite_url = invite_results[0][0]
    params = _parse_invite_params(invite_url)
    accept_wid = params.get("accept_wId") or params.get("wId")
    ws_name = params.get("inv_ws_name") or "Unknown"

    if accept_wid:
        log_fn(f"团队工作区: {ws_name} ({accept_wid})")
    else:
        log_fn("未找到 accept_wId 参数")

    if search_only:
        return True, email_addr, f"找到 {len(invite_results)} 个邀请"

    # ── Step 2: CodexLogin 标准登录流程 ──
    log_fn("[2/4] CodexLogin 登录...")

    try:
        login = CodexLogin(email=email_addr, proxy=proxy, tag=tag)

        login.step1_oauth_init()
        login.step2_sentinel_probe()

        if not login.step3_authorize_continue():
            return False, email_addr, "authorize/continue 失败"

        # ── 检查服务端期望的登录方式 ──
        next_page = getattr(login, "_next_page_type", "")
        # 密码 = 邮箱 @ 前面的部分 (注册时的规则)
        password = email_addr.split("@")[0].split("+")[0]

        if next_page == "password":
            # 服务端要求密码登录
            log_fn(f"服务端要求密码登录, 使用密码验证...")
            if not login.step5_password_verify(password):
                return False, email_addr, "密码验证失败"
        else:
            # 默认 OTP 流程
            login.step4_sentinel_probe2()

            # 快照旧邮件 (send-otp 之前)
            known_ids = get_known_mail_ids(
                email_addr, client_id, ms_refresh_token,
                impersonate=login.fp.impersonate, log_fn=login._log)

            if not login.step5_send_otp():
                return False, email_addr, "send-otp 失败 (账号可能未注册)"

            login._delay(2.0, 5.0)

            # 自动获取 OTP
            log_fn("[3/4] 等待验证码...")
            code = fetch_otp(
                email_addr, client_id, ms_refresh_token,
                known_ids=known_ids, timeout=120,
                impersonate=login.fp.impersonate, log_fn=login._log)

            if not code:
                return False, email_addr, "OTP 获取超时"

            if not login.step6_validate_otp(code):
                # OTP 验证失败, 可能取到了邀请邮件中的数字, 重试一次
                log_fn("OTP 验证失败, 将已用邮件加入 known_ids 后重试...")
                known_ids.add(code)  # 标记, 不影响逻辑
                # 重新发送 OTP
                login.step2_sentinel_probe()
                login.step4_sentinel_probe2()
                if not login.step5_send_otp():
                    return False, email_addr, "重试 send-otp 失败"
                login._delay(3.0, 6.0)
                # 重新快照 (把之前的旧邮件+错误邮件都过滤掉)
                known_ids_retry = get_known_mail_ids(
                    email_addr, client_id, ms_refresh_token,
                    impersonate=login.fp.impersonate, log_fn=login._log)
                code2 = fetch_otp(
                    email_addr, client_id, ms_refresh_token,
                    known_ids=known_ids_retry, timeout=120,
                    impersonate=login.fp.impersonate, log_fn=login._log)
                if not code2:
                    return False, email_addr, "重试 OTP 获取超时"
                if not login.step6_validate_otp(code2):
                    return False, email_addr, "OTP 验证失败 (重试后仍失败)"

        if not login.step6b_about_you():
            return False, email_addr, "about-you 失败"

        login._delay(0.5, 1.5)

        # ── Step 3: 选择团队工作区 ──
        if accept_wid:
            log_fn(f"[4/4] 选择团队工作区 ({accept_wid[:12]}...)...")
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
                        log_fn("  login_verifier (team)")
                    try:
                        ws_data = r.json()
                        cu = ws_data.get("continue_url", "")
                        if cu:
                            login._continue_url = cu
                            log_fn("  continue_url (team)")
                    except Exception:
                        pass
                else:
                    log_fn(f"  workspace/select 失败: {r.text[:200]}")
            except Exception as e:
                log_fn(f"  workspace/select 异常: {e}")
        else:
            log_fn("[4/4] 无 accept_wId，使用默认工作区...")

        # 获取 authorization code (处理重定向链)
        if not login.step7_get_auth_code():
            return False, email_addr, "获取 auth code 失败"

        # Token 交换
        token_data = login.step9_exchange_token()
        if not token_data:
            return False, email_addr, "token 交换失败"

        # 构建输出 (Codex 格式)
        result = login._build_output(token_data)
        result["disabled"] = False

        # 检测 plan 类型
        account_id = result.get("account_id", "")
        payload = decode_jwt_payload(result.get("access_token", ""))
        auth_info = payload.get("https://api.openai.com/auth", {})
        plan = auth_info.get("chatgpt_plan_type", "free")

        # 保存文件
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

        log_fn(f"token 已保存 → {out_path}")
        log_fn(f"  account_id: {account_id}")
        log_fn(f"  plan: {plan}")
        log_fn(f"  expired: {result.get('expired')}")
        return True, email_addr, f"token 已保存 ({plan})"

    except Exception as e:
        log_fn(f"异常: {e}")
        traceback.print_exc()
        return False, email_addr, f"异常: {e}"


# ══════════════════════════════════════════════════════════
# 主入口
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="ChatGPT Team 邀请自动接受 + 获取 Codex Token")
    parser.add_argument("--email", help="只处理指定邮箱")
    parser.add_argument("--search", action="store_true",
                        help="仅搜索邀请邮件，不接受")
    parser.add_argument("--workers", type=int, default=0,
                        help="并发数 (默认读 config.json)")
    args = parser.parse_args()

    _safe_print("=" * 60)
    _safe_print("  ChatGPT Team 邀请接受 + Codex Token 获取")
    _safe_print("=" * 60)

    config = _load_config()

    # 加载账号
    emails = _load_emails(config.get("outlook_input_file", "emails.txt"))
    if not emails:
        _safe_print("[Error] 无账号，检查 emails.txt")
        sys.exit(1)

    # 过滤指定邮箱
    if args.email:
        emails = [e for e in emails if e[0] == args.email]
        if not emails:
            _safe_print(f"[Error] 未找到邮箱: {args.email}")
            sys.exit(1)

    _safe_print(f"\n已加载 {len(emails)} 个账号")

    # 加载代理
    proxies = _load_proxies("proxies.txt")
    if not proxies and config.get("proxy"):
        proxies = [config["proxy"]]
    _safe_print(f"已加载 {len(proxies)} 个代理\n")

    max_workers = args.workers or config.get("max_workers", 1)
    total = len(emails)
    results = []

    def _task(idx, entry):
        email_addr, outlook_pwd, client_id, ms_refresh_token = entry
        raw_proxy = proxies[(idx - 1) % len(proxies)] if proxies else None
        proxy = ensure_proxy_chain(raw_proxy) if raw_proxy else raw_proxy
        return process_one(idx, total, email_addr, outlook_pwd,
                           client_id, ms_refresh_token, proxy,
                           search_only=args.search)

    if max_workers <= 1:
        for i, entry in enumerate(emails, 1):
            results.append(_task(i, entry))
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_task, i, e): i
                       for i, e in enumerate(emails, 1)}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    idx = futures[future]
                    results.append((False, emails[idx-1][0], str(e)))

    # ── 汇总 ──
    _safe_print(f"\n{'='*60}")
    _safe_print("  处理结果汇总")
    _safe_print(f"{'='*60}")

    success = sum(1 for r in results if r[0])
    fail = len(results) - success

    for ok, addr, msg in results:
        status = "OK" if ok else "FAIL"
        _safe_print(f"  [{status}] {addr}: {msg}")

    _safe_print(f"\n  总计: {len(results)} | 成功: {success} | 失败: {fail}")
    _safe_print("=" * 60)


if __name__ == "__main__":
    main()
