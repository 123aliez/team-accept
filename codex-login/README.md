# Codex 邀请接收 + Token 获取工具

这是一个用于 **自动接收 ChatGPT Team/Business 邀请，并导出 Codex Token** 的工具。

对你的实际使用场景来说，默认只需要跑：

```bash
python accept_invite.py --email 你的邮箱@hotmail.com
```

程序会自动完成：

- 搜索邀请邮件
- 解析团队工作区 ID (`accept_wId`)
- 登录 OpenAI
- Outlook IMAP 自动获取 OTP 验证码
- 自动处理 `about-you`
- 选择团队工作区
- 获取并保存 Team Token

## 功能

- ✅ 自动搜索 Team/Business 邀请邮件
- ✅ 自动接收邀请并切换团队工作区
- ✅ 完整 PKCE OAuth 2.0 登录流程
- ✅ Sentinel 风控探针
- ✅ Outlook IMAP 自动获取 OTP 验证码
- ✅ 自动处理 `about-you`
- ✅ 支持本地代理 + 外部代理链（xray → V2Ray/Clash → 外部代理）
- ✅ 输出标准 Codex JSON 凭证文件

## 依赖安装

```bash
pip install curl_cffi
```

## 快速开始

### 0. 主命令（以后默认用这个）

```bash
python accept_invite.py --email 你的邮箱@hotmail.com
```

批量处理：

```bash
python accept_invite.py
```

### 1. 准备 emails.txt

在项目目录下创建 `emails.txt`，每行一个账号，格式：

```
邮箱----Outlook密码----OAuth客户端ID----Outlook刷新令牌
```

示例：

```
KellyThomas3821@hotmail.com----MyPass123----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.C5xx_BAY.0.U...
alice@outlook.com----AlicePwd----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.C5xx_BAY.0.U...
```

> **字段说明：**
> - `邮箱`：已注册 ChatGPT 的 Outlook 邮箱
> - `Outlook密码`：Outlook 邮箱密码（仅记录，不参与登录流程）
> - `OAuth客户端ID`：微软 OAuth 应用的 client_id（用于 IMAP 读取邮件）
> - `Outlook刷新令牌`：微软 OAuth refresh_token（用于获取 IMAP access_token）

### 2. 接收邀请并获取 Team Token（主流程）

```bash
python accept_invite.py --email KellyThomas3821@hotmail.com
```

默认流程：

1. 搜索邀请邮件
2. 登录 OpenAI
3. 自动获取验证码
4. 自动处理 `about-you`
5. 选择团队工作区
6. 输出 Team Token 到 `output/`

### 3. 仅搜索邀请（不真正登录）

```bash
python accept_invite.py --search
```

### 4. 备用：仅普通登录取 token

```bash
python codex_login.py --email KellyThomas3821@hotmail.com
```

> 这个脚本是备用入口。你的日常使用一般不需要它。

## 命令行参数

| 参数 | 缩写 | 说明 | 默认值 |
|------|------|------|--------|
| `--email` | `-e` | 单个登录邮箱（不传则批量） | — |
| `--proxy` | `-p` | 代理地址 | 无 |
| `--workers` | `-w` | 并发数 | 2 |
| `--output` | `-o` | 输出目录 | output |
| `--input` | `-i` | 邮箱列表文件 | emails.txt |

**示例：**

```bash
# 使用代理，3 线程并发
python codex_login.py --proxy socks5://127.0.0.1:7890 --workers 3

# 指定输入输出
python codex_login.py --input accounts.txt --output tokens/

# 单个账号 + 代理
python codex_login.py -e alice@outlook.com -p http://127.0.0.1:7890
```

## 配置文件

可选创建 `config.json`：

```json
{
    "proxy": "socks5h://127.0.0.1:10808",
    "pre_proxy": "",
    "max_workers": 1,
    "outlook_input_file": "emails.txt",
    "output_dir": "output"
}
```

推荐：

- `config.json` 的 `proxy` 填本地 V2Ray/Clash，如 `socks5h://127.0.0.1:10808`
- `proxies.txt` 填外部代理（如 arxlabs / 1024proxy）
- 程序会自动走：本地 xray → 本机代理 → 外部代理 → OpenAI

命令行参数优先级高于配置文件。

## 输出格式

每个账号生成 `codex-邮箱-套餐.json`，例如 `codex-alice@outlook.com-free.json`：

```json
{
    "access_token": "eyJhbGciOi...",
    "account_id": "8d36c22b-21b1-4fa4-b485-336a32bb7834",
    "email": "alice@outlook.com",
    "expired": "2026-04-11T18:30:42+08:00",
    "id_token": "eyJhbGciOi...",
    "last_refresh": "2026-04-01T18:30:43+08:00",
    "refresh_token": "rt_YoA9zz...",
    "type": "codex"
}
```

## 项目结构

```
codex-login/
├── accept_invite.py    # 主脚本：接收邀请 + 登录 + 获取 Team Token
├── codex_login.py      # 底层登录模块 / 备用脚本
├── config.json         # 配置文件
├── emails.txt          # 邮箱列表
├── proxies.txt         # 外部代理列表
├── requirements.txt    # Python 依赖
└── output/             # 输出目录（自动创建）
    ├── codex-e3cb9792-xxx@hotmail.com-team.json
    └── codex-e3cb9792-xxx@outlook.com-team.json
```

## 主流程（邀请 → 登录 → Token）

```
Step 1: IMAP 搜索邀请邮件
Step 2: 提取邀请链接中的 accept_wId / wId
Step 3: OAuth 初始化 (PKCE + client_id)
Step 4: Sentinel 风控探针 #1
Step 5: authorize/continue (提交邮箱)
Step 6: Sentinel 风控探针 #2
  ↓
★ 快照旧邮件 ID ← 确保不会误取过旧验证码
  ↓
Step 7: passwordless/send-otp (发送验证码)
  ↓
★ 轮询新邮件 (all_ids - known_ids)
  ↓
Step 8: email-otp/validate (验证 OTP)
Step 9: 自动处理 about-you
Step 10: workspace/select (切换团队工作区)
Step 11: OAuth 重定向链 → 获取 authorization code
Step 12: Token 交换 → access_token / id_token / refresh_token
```

## 获取 Outlook OAuth 凭证

如果你还没有 `client_id` 和 `refresh_token`，需要在 [Azure 应用注册](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) 创建一个应用：

1. **注册应用**：选择"个人 Microsoft 帐户"，重定向 URI 设为 `http://localhost`
2. **API 权限**：添加 `IMAP.AccessAsUser.All` 和 `offline_access`
3. **获取 refresh_token**：通过 OAuth 授权码流程获取

`client_id` 通常为 `9e5f94bc-e8a4-4e73-b8be-63364c29d753`（Thunderbird 公共 client_id，可直接使用）。

## 常见问题

**Q: 验证码获取超时？**
检查 `refresh_token` 是否过期，尝试重新获取。IMAP 轮询间隔 3 秒，默认超时 120 秒。

**Q: Sentinel 探针失败？**
通常不影响流程，工具会继续执行。如果 `authorize/continue` 也失败，检查代理是否正常。

**Q: 输出的 access_token 多久过期？**
JWT 中的 `exp` 字段决定，通常 10 天。JSON 文件中的 `expired` 字段已标注。
