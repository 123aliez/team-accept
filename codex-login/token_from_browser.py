#!/usr/bin/env python3
"""
从浏览器复制的 access_token 生成 JSON 文件

用法:
  python token_from_browser.py
  然后粘贴 token, 回车即可
"""
import json
import base64
import os
import sys
from datetime import datetime, timedelta, timezone


def decode_jwt_payload(token):
    try:
        payload_b64 = token.split(".")[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return {}


def main():
    print("粘贴从浏览器获取的 access_token (一整行):")
    token = input().strip()
    if not token:
        print("错误: token 为空")
        sys.exit(1)

    payload = decode_jwt_payload(token)
    auth = payload.get("https://api.openai.com/auth", {})
    profile = payload.get("https://api.openai.com/profile", {})

    email = profile.get("email", "unknown")
    account_id = auth.get("chatgpt_account_id", "")
    plan = auth.get("chatgpt_plan_type", "free")
    exp = payload.get("exp", 0)

    tz = timezone(timedelta(hours=8))
    expired = datetime.fromtimestamp(exp, tz).strftime("%Y-%m-%dT%H:%M:%S+08:00") if exp else ""
    now = datetime.now(tz).strftime("%Y-%m-%dT%H:%M:%S+08:00")

    result = {
        "access_token": token,
        "account_id": account_id,
        "email": email,
        "expired": expired,
        "last_refresh": now,
        "type": "codex",
    }

    is_team = plan in ("team", "team_business", "enterprise")
    short_id = account_id[:8] if account_id else "unknown"

    if is_team:
        filename = f"codex-{short_id}-{email}-{plan}.json"
    else:
        filename = f"token-{email}.json"

    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, filename)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"\n✅ 已保存: {out_path}")
    print(f"   邮箱: {email}")
    print(f"   计划: {plan}")
    print(f"   过期: {expired}")


if __name__ == "__main__":
    main()
