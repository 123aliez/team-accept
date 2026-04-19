# Team-Accept 项目文档

> **一站式 ChatGPT 账号管理平台**：批量注册 OpenAI 账号 → 自动接受 Team 邀请拿 Team Token → 或对已有账号登录拿 Personal (Free/Plus) Token，全流程 Web 可视化操作。

---

## 一、项目总览

Team-Accept 由 **1 个 Web 控制台** + **2 个子模块** 组成：

| 模块 | 路径 | 功能 | 技术栈 |
|------|------|------|--------|
| **Web 控制台** | `web_console.py` | 统一操作入口，调度两个子模块 | Python 3 (内置 http.server) |
| **codex (注册模块)** | `codex/` | 批量注册新 OpenAI 账号（邮箱+密码+OTP） | Python 3 + curl_cffi |
| **codex-login (登录/邀请模块)** | `codex-login/` | 注册+接受邀请取 Team Token / 已注册账号登录取 Personal Token | Python 3 + curl_cffi |

### 整体工作流程

Web 控制台提供两条主路径：

```
┌────────────────────────────────────────────────────────────────┐
│                    Web Console (:8089)                          │
│                                                                 │
│  ┌──────────────────────────┐    ┌──────────────────────────┐   │
│  │ 🚀 注册 + 接受邀请         │    │ 🔑 登录取 Token           │   │
│  │  (register_and_accept)   │    │  (login_accounts)        │   │
│  │                          │    │                          │   │
│  │  新邮箱 → 注册            │    │  已注册账号               │   │
│  │    → 搜邀请邮件            │    │    → OTP 登录             │   │
│  │    → 接受邀请              │    │    → 解析 personal ws     │   │
│  │    → 拿 Team Token        │    │    → 拿 Free/Plus Token   │   │
│  └──────────────────────────┘    └──────────────────────────┘   │
│           │                               │                     │
│           ▼                               ▼                     │
│  codex-login/output/              codex-login/output/           │
│  codex-{id}-{email}-team.json     token-{email}.json            │
└────────────────────────────────────────────────────────────────┘
```

**两条路径的用途区分**（重要）：

| 路径 | 目标账号 | 目标 Token | 典型场景 |
|------|---------|-----------|---------|
| 🚀 注册+接受邀请 | 新邮箱 / 未注册账号 | **Team Token** (team plan) | 批量给新账号发邀请，让他们入 team |
| 🔑 登录取 Token | 已有账号 **且有个人 workspace** | **Personal Token** (free / plus plan) | 拿个人账号的自用 token |

> ⚠️ **"登录取 Token" 只取 personal**：如果目标账号只加入了 team 但没有自己的 personal workspace，会直接返回失败 `该账号无 personal workspace`，**不会回退到 team**。这是刻意设计，两条路径职责分离。

---

## 二、项目结构

```
team-accept/
├── web_console.py              # Web 控制台主程序 (端口 8089)
│
├── codex/                      # 注册模块
│   ├── register_accounts.py    # 批量注册脚本
│   ├── codex_login.py          # 底层登录模块（注册用）
│   ├── config.json             # 注册模块配置
│   ├── emails.txt              # 邮箱列表 (gitignore)
│   ├── proxies.txt             # 代理列表 (由 Web 控制台写入)
│   └── output/                 # 注册结果输出目录
│       └── registered-{email}.json
│
├── codex-login/                # 登录/邀请模块
│   ├── register_and_accept.py  # ⭐ 主入口 A：注册 + 接受邀请 一体化
│   ├── login_accounts.py       # ⭐ 主入口 B：登录取 Personal Token
│   ├── accept_invite.py        # 辅助脚本：仅接受邀请（register_and_accept 阶段 2 复用此逻辑）
│   ├── codex_login.py          # 底层 OAuth / Token 交换实现
│   ├── config.json             # 模块配置
│   ├── emails.txt              # 邮箱列表 (gitignore)
│   ├── proxies.txt             # 代理列表 (gitignore)
│   ├── requirements.txt        # Python 依赖 (curl_cffi)
│   ├── test_proxy.py           # 代理自检脚本
│   └── output/                 # Token 输出目录
│       ├── codex-{id}-{email}-team.json    # Team token（路径 A 的产物）
│       └── token-{email}.json              # Personal token（路径 B 的产物）
│
└── __pycache__/                # (gitignore)
```

---

## 三、环境要求

| 项目 | 版本要求 |
|------|---------|
| Python | >= 3.8 (推荐 3.11+) |
| pip 包 | `curl_cffi` |
| 操作系统 | Linux / macOS / Windows |
| 网络 | 必须配置代理 (不允许走本机直连) |

---

## 四、安装步骤

### 1. 克隆项目

```bash
git clone https://github.com/123aliez/team-accept.git
cd team-accept
```

### 2. 安装 Python 依赖

```bash
pip install curl_cffi

# 国内镜像加速
pip install curl_cffi -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### 3. 准备配置文件

首次使用时，从示例模板生成：

```bash
cp codex/config.json.example codex/config.json
cp codex/emails.txt.example codex/emails.txt
cp codex/proxies.txt.example codex/proxies.txt

cp codex-login/config.json.example codex-login/config.json
cp codex-login/emails.txt.example codex-login/emails.txt
cp codex-login/proxies.txt.example codex-login/proxies.txt
```

---

## 五、配置文件详解

### 5.1 `config.json`（两个模块各一份，格式相同）

```json
{
    "proxy": "",
    "pre_proxy": "",
    "max_workers": 1,
    "outlook_input_file": "emails.txt",
    "output_dir": "output"
}
```

| 字段 | 类型 | 说明 | 默认值 |
|------|------|------|--------|
| `proxy` | string | 全局兜底代理，推荐填本地 V2Ray/Clash 地址，如 `socks5h://127.0.0.1:10808` | 空 |
| `pre_proxy` | string | 预连接代理，一般不需要填 | 空 |
| `max_workers` | int | 最大并发数 | 1 |
| `outlook_input_file` | string | 邮箱列表文件名 | `emails.txt` |
| `output_dir` | string | 输出目录名 | `output` |

### 5.2 `emails.txt` （邮箱列表）

每行一个账号，用 `----` 分隔四个字段：

```
邮箱----Outlook密码----OAuth客户端ID----Outlook刷新令牌
```

**示例：**
```
alice@hotmail.com----MyPass123----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.C5xx_BAY.0.U...
```

| # | 字段 | 说明 |
|---|------|------|
| 1 | 邮箱 | Outlook / Hotmail 邮箱 |
| 2 | Outlook 密码 | 仅记录，不参与 OpenAI 登录 |
| 3 | OAuth client_id | Microsoft 应用的 `client_id`，用 Thunderbird 公共值 `9e5f94bc-e8a4-4e73-b8be-63364c29d753` 即可 |
| 4 | Outlook Refresh Token | 微软 OAuth 的 `refresh_token`，用于 IMAP 读邮件 |

### 5.3 `proxies.txt` （代理列表）

> 通过 Web 控制台操作时，代理由前端自动写入 `codex/proxies.txt` 和 `codex-login/proxies.txt`，无需手动编辑。

每行一个代理，支持多种格式：

```bash
# 格式 1: host:port:user:pass
us.arxlabs.io:3010:user1:pass1

# 格式 2: 协议格式
socks5://user:pass@ip:port
http://user:pass@ip:port
```

**代理分配规则：** 数量不足时自动循环分配。

### 5.4 Web 控制台环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `WEB_HOST` | 监听地址 | `127.0.0.1` |
| `WEB_PORT` | 监听端口 | `8089` |

---

## 六、推荐代理配置方案

```
本地脚本 → 本地 xray 临时端口 → 本机 V2Ray/Clash → 外部代理 → OpenAI
```

1. `config.json` 的 `proxy` 填本地 V2Ray/Clash 地址：`socks5h://127.0.0.1:10808`
2. `proxies.txt` 或 Web 控制台前端填外部代理 (如 arxlabs / 1024proxy)
3. 程序自动建立 xray 代理链

如果只有本地代理，`proxies.txt` 留空即可。

---

## 七、启动与使用

### 7.1 启动 Web 控制台

```bash
cd team-accept
python3 web_console.py
```

启动成功后访问：`http://127.0.0.1:8089`

自定义地址和端口：
```bash
WEB_HOST=0.0.0.0 WEB_PORT=9090 python3 web_console.py
```

### 7.2 Web 控制台功能

**操作面板 (⚡ 操作)**

- **邮箱 & 代理输入区**：直接粘贴（留空则使用 `emails.txt` 文件）
- **并发数设置**：控制同时处理的账号数
- **🚀 注册 + 接受邀请**：调用 `codex-login/register_and_accept.py`
  - 新号走：注册 → 搜邀请邮件 → 接受 → 取 **Team Token**
  - 老号走：跳过注册 → 直接接受邀请 → 取 **Team Token**
- **🔑 登录取 Token**：调用 `codex-login/login_accounts.py`
  - 仅处理已注册账号
  - 解析 consent 页面的 React Router 流数据，定位 `kind=personal` workspace
  - 取 **Personal Token**（free / plus）
  - 无 personal workspace 则 fail
- **实时输出**：当前任务日志
- **失败账号**：实时显示失败原因
- **Token 结果**：分"Personal" / "Team" 两栏展示
- **📥 导出 Token**：分别导出 personal / team tokens 为 ZIP

**任务面板 (📋 任务)**

- 查看所有历史任务 (pending / running / done / error / stopped)
- 查看任务详情和完整日志
- 停止正在运行的任务

### 7.3 命令行直接使用

**注册账号**（仅注册，不接受邀请）：
```bash
cd codex
python3 register_accounts.py                      # 批量
python3 register_accounts.py --email x@hotmail.com
python3 register_accounts.py --workers 3
```

**注册 + 接受邀请 一体化**（推荐）：
```bash
cd codex-login
python3 register_and_accept.py                    # 批量
python3 register_and_accept.py --email x@hotmail.com
python3 register_and_accept.py --workers 2
```

**仅接受邀请**（账号已注册，单独走接受邀请流程）：
```bash
cd codex-login
python3 accept_invite.py
python3 accept_invite.py --email x@hotmail.com
python3 accept_invite.py --search                  # 仅搜索邀请邮件，不接受
```

**登录取 Personal Token**：
```bash
cd codex-login
python3 login_accounts.py                          # 批量
python3 login_accounts.py --email x@hotmail.com
python3 login_accounts.py --no-session             # 不导出 ChatGPT session
```

---

## 八、API 接口文档

### GET 接口

| 路径 | 说明 |
|------|------|
| `GET /` | Web 控制台前端页面 |
| `GET /api/status` | 服务状态检查 |
| `GET /api/tasks` | 获取所有任务列表 |
| `GET /api/task/{task_id}` | 获取指定任务详情 |
| `GET /api/results/codex` | 获取注册结果列表 |
| `GET /api/results/login` | 获取 Token 结果列表（personal + team） |
| `GET /api/failures` | 获取所有失败记录 |
| `GET /api/export/tokens` | 导出 Team Token 为 ZIP |
| `GET /api/export/personal-tokens` | 导出 Personal Token 为 ZIP |
| `GET /api/export/sessions` | 导出 ChatGPT Session 为 ZIP |

### POST 接口

| 路径 | Body 字段 | 说明 |
|------|-----------|------|
| `POST /api/run/register` | `emails`, `workers`, `proxies` | 启动注册任务（仅注册） |
| `POST /api/run/accept` | `emails`, `workers`, `proxies` | 启动接受邀请任务（账号已注册） |
| `POST /api/run/register-accept` | `emails`, `workers`, `proxies` | 启动 注册+接受邀请 一体化任务 |
| `POST /api/run/login` | `emails`, `workers`, `proxies`, `fetch_session` | 启动登录取 Personal Token 任务 |
| `POST /api/task/stop` | `task_id` | 停止指定任务 |
| `POST /api/clear/tokens` | — | 清除所有 token 文件 |
| `POST /api/clear/personal-tokens` | — | 清除 personal token 文件 |
| `POST /api/clear/team-tokens` | — | 清除 team token 文件 |
| `POST /api/clear/sessions` | — | 清除 session 文件 |

**POST Body 示例：**
```json
{
  "emails": "alice@hotmail.com----pwd----clientId----refreshToken\nbob@outlook.com----pwd----clientId----refreshToken",
  "workers": "2",
  "proxies": "us.proxy.io:3010:user:pass\njp.proxy.io:3010:user:pass",
  "fetch_session": true
}
```

> **注意：** `proxies` 是必填项，不允许走本机直连网络。

---

## 九、输出文件格式

### 9.1 注册结果 `codex/output/registered-{email}.json`

```json
{
  "email": "alice@hotmail.com",
  "registered": true,
  "registration_method": "email_password_otp",
  "password_rule": "email_local_part_no_alias",
  "derived_password": "alice",
  "otp_validated": true
}
```

### 9.2 Team Token `codex-login/output/codex-{id}-{email}-team.json`

由 "注册+接受邀请" 流程产生：

```json
{
  "access_token": "eyJhbGciOi...",
  "account_id": "1bda5cab-6fde-4a1b-9d73-34a338d5633c",
  "email": "alice@hotmail.com",
  "expired": "2026-04-29T14:51:33+08:00",
  "id_token": "eyJhbGciOi...",
  "last_refresh": "2026-04-19T14:51:33+08:00",
  "refresh_token": "rt_3ebG...",
  "type": "codex",
  "disabled": false
}
```

### 9.3 Personal Token `codex-login/output/token-{email}.json`

由 "登录取 Token" 流程产生（plan = free / plus）：

```json
{
  "access_token": "eyJhbGciOi...",
  "account_id": "fa2675d3-8663-40f1-8c16-5bed6b083ad4",
  "email": "alice@hotmail.com",
  "expired": "2026-04-29T17:14:02+08:00",
  "id_token": "eyJhbGciOi...",
  "last_refresh": "2026-04-19T17:14:02+08:00",
  "refresh_token": "rt_...",
  "type": "codex",
  "disabled": false
}
```

> Token 通常 10 天过期，`expired` 字段标注过期时间。可用 `refresh_token` 刷新。

---

## 十、注册流程详解

```
Step 1: OAuth 初始化 (PKCE + client_id)
Step 2: Sentinel 风控探针
Step 3: authorize/continue（提交邮箱，signup 模式）
Step 4: user/register（设置密码，密码规则：邮箱前缀前 12 位）
Step 5: email-otp/send（发送注册验证码）
Step 6: IMAP 自动获取验证码 + email-otp/validate（验证 OTP）
  ↓
→ 输出注册结果 JSON
```

## 十一、注册 + 接受邀请 流程详解

```
阶段 1：注册 / 识别已注册
   - OAuth 初始化
   - authorize/continue(signup) → 判定是否已注册
   - 新号：设置密码 + OTP 验证
   - 老号：跳过

阶段 2：接受邀请（复用 accept_invite.py 流程）
   - IMAP 搜索邀请邮件（来自 openai.com）
   - 解析邀请链接中的 accept_wId（团队工作区 ID）
   - 重新起 session 做 OTP 登录
   - step6b_about_you（自动补全姓名/生日）
   - workspace/select(accept_wId) → 获取 login_verifier + continue_url
   - OAuth 重定向链 → 拿 authorization code
   - Token 交换 → Team Token
  ↓
→ 输出 codex-{id}-{email}-team.json
```

## 十二、登录取 Personal Token 流程详解

```
Step 1: OAuth 初始化
Step 2-3: Sentinel 风控探针 + authorize/continue
Step 4-6: 发送 OTP → IMAP 拉取验证码 → validate-otp
Step 6b: about-you（补全姓名）
Step 7: 解析 consent 页面的 React Router 流数据
   - 定位 kind=personal 的 workspace
   - 如果账号无 personal workspace → fail: "该账号无 personal workspace"
Step 8: workspace/select(personal_ws_id)
Step 9: OAuth 重定向链 → 拿 authorization code
Step 10: Token 交换 → 解析 plan_type
   - plan=free / plus → 保存 token
   - plan=team → 视为错误（personal 路径不应拿到 team）
  ↓
→ 输出 token-{email}.json
```

---

## 十三、智能功能

- **自动排除失败账号：** 执行"注册+接受邀请"时，自动检查 `codex/output/` 中注册失败的邮箱，跳过不再重试
- **代理自动写入：** Web 控制台输入的代理自动同步写入两个模块的 `proxies.txt`
- **代理链自动构建：** 自动建立 xray 代理链（本地 xray → 本机代理 → 外部代理）
- **OTP 自动重试：** OTP 验证失败会自动重发并重试
- **Personal workspace 精确解析：** 登录取 Token 流程解析 consent 页面的 `window.__reactRouterContext.streamController.enqueue(...)` RSC flight 数据，精确定位 `kind=personal` 的 workspace_id（不依赖正则扫 UUID 的启发式猜测）
- **浏览器指纹模拟：** 使用 curl_cffi 模拟 Chrome 浏览器指纹，降低风控检测

---

## 十四、获取 Outlook OAuth 凭证

如果还没有 `client_id` 和 `refresh_token`：

1. **使用公共 client_id：** `9e5f94bc-e8a4-4e73-b8be-63364c29d753`（Thunderbird 公共 client_id）
2. **或在 [Azure 应用注册](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) 创建应用：**
   - 选择"个人 Microsoft 帐户"
   - 重定向 URI 设为 `http://localhost`
   - API 权限添加 `IMAP.AccessAsUser.All` 和 `offline_access`
   - 通过 OAuth 授权码流程获取 `refresh_token`

---

## 十五、常见问题

| 问题 | 解决方案 |
|------|---------|
| `curl_cffi` 安装失败 | `python -m pip install --upgrade pip && pip install curl_cffi` |
| send-otp 返回 409 | 账号未在 OpenAI 完成注册，需先注册 |
| 验证码获取超时 | 检查 `refresh_token` 是否过期，IMAP 轮询默认超时 120 秒 |
| 未找到邀请邮件 | 确认邀请已发到该邮箱，检查垃圾箱 |
| workspace/select 失败 | 确认邀请链接包含 `accept_wId` 参数 |
| `该账号无 personal workspace` | 该账号是通过邀请链接注册的 team-only 账号，OpenAI 没给它 personal workspace。这是预期行为，想拿 free token 需用自主注册账号 |
| `302 → /error` / `未获取到 code` | session 被烧了。常见于并发过高或代理 IP 跳变触发风控；尝试降低并发、换代理重试 |
| access_token 过期 | 通常 10 天过期，可用 `refresh_token` 刷新 |
| 代理数量少于账号数 | 自动循环分配 |
| 必须提供代理 | Web 控制台强制要求代理，不允许本机直连 |

---

## 十六、部署示例（systemd）

参考 `deploy.sh` 或以下示例：

```ini
# /etc/systemd/system/team-accept.service
[Unit]
Description=Team Accept Web Console
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/path/to/team-accept
ExecStart=/usr/bin/python3 /path/to/team-accept/web_console.py
Environment=WEB_HOST=127.0.0.1
Environment=WEB_PORT=8089
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable team-accept
sudo systemctl restart team-accept
```

---

## 十七、更新日志

主要版本变更参见 `git log`。近期关键改动：

- **Personal Token 精确解析**：`login_accounts.py` 改为通过 React Router stream 定位 `kind=personal` workspace，替换原先基于 UUID 正则扫描的启发式。只拿 free/plus，不回退 team。
- **accept_invite session 烧毁修复**：`step7_get_auth_code` 在 `accept_wId` 已预填 `_login_verifier` + `_continue_url` 时跳过候选扫描，避免对 sessionLoggingId 做 workspace/select 触发 409 烧掉合法 session。
- **一体化注册+接受邀请**：`register_and_accept.py` 合并注册与接受邀请为一步，减少重复登录。
