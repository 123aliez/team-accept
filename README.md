# Team-Accept 项目文档

> **一站式 ChatGPT Team 账号管理平台**：批量注册 OpenAI 账号 → 自动接受 Team 邀请 → 获取 Codex Token，全流程 Web 可视化操作。

---

## 一、项目总览

Team-Accept 由 **3 个子模块** 组成，统一通过 Web 控制台协调：

| 模块 | 路径 | 功能 | 技术栈 |
|------|------|------|--------|
| **Web 控制台** | `web_console.py` | 统一操作入口，管理注册/接受邀请的全流程 | Python 3 (内置 http.server) |
| **codex (注册模块)** | `codex/` | 批量注册新 OpenAI 账号 (邮箱+密码+OTP验证) | Python 3 + curl_cffi |
| **codex-login (邀请模块)** | `codex-login/` | 自动搜索 Team 邀请邮件、接受邀请、获取 Team Token | Python 3 + curl_cffi |

### 整体工作流程

```
┌─────────────────────────────────────────────────────┐
│              Web Console (:8089)                     │
│                                                     │
│   ┌─────────────┐         ┌─────────────────────┐   │
│   │ 🚀 注册账号  │         │ ✅ 接受邀请+取Token  │   │
│   │ (codex 模块) │         │ (codex-login 模块)   │   │
│   └──────┬──────┘         └──────────┬──────────┘   │
│          │                           │              │
│          ▼                           ▼              │
│   register_accounts.py        accept_invite.py      │
│          │                           │              │
│          ▼                           ▼              │
│   codex/output/              codex-login/output/    │
│   (注册结果 JSON)            (Token JSON 文件)       │
└─────────────────────────────────────────────────────┘
```

---

## 二、项目结构

```
team-accept/
├── web_console.py              # Web 控制台主程序 (端口 8089)
│
├── codex/                      # 注册模块
│   ├── register_accounts.py    # 批量注册脚本
│   ├── codex_login.py          # 底层登录模块 (被 register_accounts.py 引用)
│   ├── config.json             # 注册模块配置
│   ├── emails.txt              # 邮箱列表
│   ├── proxies.txt             # 代理列表 (由 Web 控制台自动写入)
│   └── output/                 # 注册结果输出目录
│       └── registered-xxx@hotmail.com.json
│
├── codex-login/                # 邀请接受模块
│   ├── accept_invite.py        # 主脚本：搜索邀请 + 接受 + 取 Token
│   ├── codex_login.py          # 底层登录模块
│   ├── config.json             # 邀请模块配置
│   ├── emails.txt              # 邮箱列表
│   ├── proxies.txt             # 代理列表 (由 Web 控制台自动写入)
│   ├── requirements.txt        # Python 依赖 (curl_cffi)
│   ├── test_proxy.py           # 代理测试脚本
│   └── output/                 # Token 输出目录
│       └── codex-{id}-{email}-{plan}.json
│
└── __pycache__/
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

### 1. 安装 Python 环境

```bash
# 验证 Python 版本
python3 --version   # 需要 >= 3.8
```

### 2. 安装 Python 依赖

```bash
pip install curl_cffi

# 国内镜像加速
pip install curl_cffi -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### 3. 确认项目文件

```bash
cd /home/ccweb/workspace/team-accept
ls -la  # 确认 web_console.py、codex/、codex-login/ 存在
```

---

## 五、配置文件详解

### 5.1 `codex/config.json` (注册模块配置)

```json
{
    "proxy": "",
    "pre_proxy": "",
    "max_workers": 1,
    "outlook_input_file": "emails.txt",
    "output_dir": "output"
}
```

### 5.2 `codex-login/config.json` (邀请模块配置)

```json
{
    "proxy": "",
    "pre_proxy": "",
    "max_workers": 1,
    "outlook_input_file": "emails.txt",
    "output_dir": "output"
}
```

### 配置字段说明

| 字段 | 类型 | 说明 | 默认值 |
|------|------|------|--------|
| `proxy` | string | 全局兜底代理。推荐填本地 V2Ray/Clash 地址，如 `socks5h://127.0.0.1:10808` | 空 (无) |
| `pre_proxy` | string | 预连接代理，一般不需要填 | 空 |
| `max_workers` | int | 最大并发数 | 1 |
| `outlook_input_file` | string | 邮箱列表文件名 | `emails.txt` |
| `output_dir` | string | 输出目录名 | `output` |

### 5.3 `emails.txt` (邮箱列表)

两个模块各有一份 `emails.txt`，格式相同，每行一个账号，用 `----` 分隔四个字段：

```
邮箱----Outlook密码----OAuth客户端ID----Outlook刷新令牌
```

**示例：**
```
alice@hotmail.com----MyPass123----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.C5xx_BAY.0.U...
bob@outlook.com----BobPwd456----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.C5xx_BAY.0.U...
```

**字段说明：**

| # | 字段 | 说明 |
|---|------|------|
| 1 | 邮箱 | Outlook / Hotmail 邮箱地址 |
| 2 | Outlook 密码 | 邮箱密码 (仅记录，不参与 OpenAI 登录) |
| 3 | OAuth 客户端 ID | 微软 Azure 应用的 `client_id`，用于 IMAP OAuth2 读取邮件。通常使用 Thunderbird 公共 ID：`9e5f94bc-e8a4-4e73-b8be-63364c29d753` |
| 4 | Outlook Refresh Token | 微软 OAuth 的 `refresh_token`，用于获取 IMAP `access_token` |

### 5.4 `proxies.txt` (代理列表)

> **注意：** 通过 Web 控制台操作时，代理列表由前端自动写入到 `codex/proxies.txt` 和 `codex-login/proxies.txt`，无需手动编辑。

每行一个代理，支持多种格式：

```bash
# 格式 1: host:port:user:pass
us.arxlabs.io:3010:user1:pass1
jp.arxlabs.io:3010:user2:pass2

# 格式 2: 协议格式
socks5://user:pass@ip:port
http://user:pass@ip:port
```

**代理分配规则：** 代理数量不足时自动循环分配。例如 2 条代理 + 5 个账号 → 1→代理1, 2→代理2, 3→代理1, 4→代理2, 5→代理1。

### 5.5 Web 控制台环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `WEB_HOST` | Web 服务监听地址 | `127.0.0.1` |
| `WEB_PORT` | Web 服务监听端口 | `8089` |

---

## 六、推荐代理配置方案

```
本地脚本 → 本地 xray 临时端口 → 本机 V2Ray/Clash → 外部代理 → OpenAI
```

1. **config.json** 的 `proxy` 填本地 V2Ray/Clash 地址：`socks5h://127.0.0.1:10808`
2. **proxies.txt** 或 Web 控制台前端填外部代理 (如 arxlabs / 1024proxy)
3. 程序会自动建立 xray 代理链

如果只有本地代理，`proxies.txt` 留空，程序将仅使用 `config.json` 中的 `proxy`。

---

## 七、启动与使用

### 7.1 启动 Web 控制台

```bash
cd /home/ccweb/workspace/team-accept
python3 web_console.py
```

启动成功后访问：`http://127.0.0.1:8089`

自定义地址和端口：

```bash
WEB_HOST=0.0.0.0 WEB_PORT=9090 python3 web_console.py
```

### 7.2 Web 控制台功能

**操作面板 (⚡ 操作)**

- **左上：邮箱 & 代理输入区** — 输入邮箱列表和代理列表 (留空邮箱则使用 `emails.txt` 文件)
- **并发数设置** — 控制同时处理的账号数
- **🚀 开始注册** — 调用 `codex/register_accounts.py` 批量注册
- **✅ 接受邀请 + 取 Token** — 调用 `codex-login/accept_invite.py` 批量处理
- **实时输出** — 显示当前任务的实时日志
- **失败账号** — 实时显示注册失败和 Token 获取失败的账号
- **执行结果** — 显示注册结果和 Token 结果
- **📥 导出 Token** — 将所有成功的 Token 打包为 ZIP 下载

**任务面板 (📋 任务)**

- 查看所有历史任务的状态 (pending / running / done / error / stopped)
- 查看任务详情和完整日志
- 停止正在运行的任务

### 7.3 命令行直接使用 (不经过 Web 控制台)

**注册账号：**
```bash
cd /home/ccweb/workspace/team-accept/codex

# 批量注册
python3 register_accounts.py

# 注册单个邮箱
python3 register_accounts.py --email alice@hotmail.com

# 指定并发数
python3 register_accounts.py --workers 3
```

**接受邀请 + 取 Token：**
```bash
cd /home/ccweb/workspace/team-accept/codex-login

# 批量处理
python3 accept_invite.py

# 单个邮箱
python3 accept_invite.py --email alice@hotmail.com

# 仅搜索邀请 (不接受)
python3 accept_invite.py --search

# 指定并发数
python3 accept_invite.py --workers 2
```

---

## 八、API 接口文档

Web 控制台提供以下 REST API：

### GET 接口

| 路径 | 说明 |
|------|------|
| `GET /` | Web 控制台前端页面 |
| `GET /api/status` | 服务状态检查 |
| `GET /api/tasks` | 获取所有任务列表 |
| `GET /api/task/{task_id}` | 获取指定任务详情 |
| `GET /api/results/codex` | 获取注册结果列表 |
| `GET /api/results/login` | 获取 Token 结果列表 |
| `GET /api/failures` | 获取所有失败记录 (注册失败 + Token 获取失败) |
| `GET /api/export/tokens` | 导出所有成功 Token 为 ZIP 压缩包 |

### POST 接口

| 路径 | Body 字段 | 说明 |
|------|-----------|------|
| `POST /api/run/register` | `emails`, `workers`, `proxies` | 启动注册任务 |
| `POST /api/run/accept` | `emails`, `workers`, `proxies` | 启动接受邀请任务 |
| `POST /api/task/stop` | `task_id` | 停止指定任务 |

**POST Body 示例：**
```json
{
  "emails": "alice@hotmail.com----pwd----clientId----refreshToken\nbob@outlook.com----pwd----clientId----refreshToken",
  "workers": "2",
  "proxies": "us.proxy.io:3010:user:pass\njp.proxy.io:3010:user:pass"
}
```

> **注意：** `proxies` 是必填项，不允许走本机直连网络。

---

## 九、输出文件格式

### 注册结果 (`codex/output/registered-{email}.json`)

```json
{
  "email": "alice@hotmail.com",
  "registered": true,
  "registration_method": "email_password_otp",
  "password_rule": "email_local_part_first_12",
  "derived_password": "alice",
  "otp_validated": true
}
```

### Token 结果 (`codex-login/output/codex-{id}-{email}-{plan}.json`)

```json
{
  "access_token": "eyJhbGciOi...",
  "account_id": "e3cb9792-5f9c-4949-a80d-81910d767faf",
  "email": "alice@hotmail.com",
  "expired": "2026-04-15T03:15:28+08:00",
  "id_token": "eyJhbGciOi...",
  "last_refresh": "2026-04-05T03:15:28+08:00",
  "refresh_token": "rt_3ebG...",
  "type": "codex",
  "disabled": false
}
```

> Token 通常 10 天过期，`expired` 字段标注过期时间。可使用 `refresh_token` 刷新。

---

## 十、注册流程详解

```
Step 1: OAuth 初始化 (PKCE + client_id)
Step 2: Sentinel 风控探针
Step 3: authorize/continue (提交邮箱, signup 模式)
Step 4: user/register (设置密码，密码规则: 邮箱前缀前12位)
Step 5: email-otp/send (发送注册验证码)
Step 6: IMAP 自动获取验证码 + email-otp/validate (验证 OTP)
  ↓
→ 输出注册结果 JSON
```

## 十一、邀请接受流程详解

```
Step 1: IMAP 搜索邀请邮件 (来自 openai.com)
Step 2: 提取邀请链接中的 accept_wId (团队工作区 ID)
Step 3: CodexLogin 标准登录流程:
   - OAuth 初始化 (PKCE)
   - Sentinel 风控探针 #1
   - authorize/continue (提交邮箱)
   - Sentinel 风控探针 #2
   - ★ 快照旧邮件 ID (防误取旧验证码)
   - send-otp → IMAP 轮询新邮件获取验证码 → validate-otp
   - 自动处理 about-you (补全姓名和生日)
Step 4: workspace/select (选择团队工作区)
Step 5: OAuth 重定向链 → 获取 authorization code
Step 6: Token 交换 → access_token / id_token / refresh_token
  ↓
→ 输出 Codex 格式 Token JSON
```

---

## 十二、智能功能

- **自动排除失败账号：** 执行"接受邀请"时，会自动检查 `codex/output/` 中注册失败的邮箱，自动跳过不再重试
- **代理自动写入：** 通过 Web 控制台输入的代理会自动同步写入两个模块的 `proxies.txt`
- **代理链自动构建：** 程序自动建立 xray 代理链（本地 xray → 本机代理 → 外部代理）
- **OTP 自动重试：** 如果 OTP 验证失败（可能误取了邀请邮件中的数字），会自动重新发送并重试
- **浏览器指纹模拟：** 使用 curl_cffi 模拟 Chrome 浏览器指纹，降低风控检测

---

## 十三、获取 Outlook OAuth 凭证

如果你还没有 `client_id` 和 `refresh_token`，可以：

1. **使用公共 client_id：** `9e5f94bc-e8a4-4e73-b8be-63364c29d753` (Thunderbird 公共 client_id)
2. **或在 [Azure 应用注册](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade) 创建应用：**
   - 选择"个人 Microsoft 帐户"
   - 重定向 URI 设为 `http://localhost`
   - API 权限添加 `IMAP.AccessAsUser.All` 和 `offline_access`
   - 通过 OAuth 授权码流程获取 `refresh_token`

---

## 十四、常见问题

| 问题 | 解决方案 |
|------|---------|
| `curl_cffi` 安装失败 | `python -m pip install --upgrade pip && pip install curl_cffi` |
| send-otp 返回 409 | 账号未在 OpenAI 完成注册，需先注册 |
| 验证码获取超时 | 检查 `refresh_token` 是否过期，IMAP 轮询默认超时 120 秒 |
| 未找到邀请邮件 | 确认邀请已发到该邮箱，检查垃圾箱 |
| workspace/select 失败 | 确认邀请链接包含 `accept_wId` 参数 |
| access_token 过期 | 通常 10 天过期，可用 `refresh_token` 刷新 |
| 代理数量少于账号数 | 自动循环分配 |
| 必须提供代理 | Web 控制台强制要求代理，不允许本机直连 |
