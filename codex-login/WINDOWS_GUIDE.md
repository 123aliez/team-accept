# Codex 邀请接收 + Token 获取 - Windows 操作指南

**你的实际使用场景只需要一个主流程：**

> **先接收邀请，再登录获取 token**

也就是主用：`accept_invite.py`

| 工具 | 用途 |
|------|------|
| `accept_invite.py` | 主流程：搜索邀请邮件 → 接收团队邀请 → 登录 → 获取 Team Token |
| `codex_login.py` | 备用：仅普通登录获取 token（一般不用） |

---

## 一、环境准备

### 1. 安装 Python

1. 打开 https://www.python.org/downloads/
2. 下载 Python 3.8 以上版本（推荐 3.11+）
3. 安装时 **务必勾选** `Add Python to PATH`
4. 验证：

```cmd
python --version
```

### 2. 安装依赖

```cmd
pip install curl_cffi
```

国内镜像：

```cmd
pip install curl_cffi -i https://pypi.tuna.tsinghua.edu.cn/simple
```

### 3. 下载项目

将整个 `codex-login` 文件夹拷贝到你的电脑上，比如放在 `D:\codex-login\`。

---

## 二、项目结构

```
D:\codex-login\
├── codex_login.py      # 工具1: Codex 登录 (获取个人/Team Token)
├── accept_invite.py    # 工具2: 邀请接受 + Team Token 获取
├── config.json         # 全局配置 (代理、并发数等)
├── emails.txt          # 账号列表 (必须填写)
├── proxies.txt         # 代理列表 (每行一个)
├── requirements.txt    # Python 依赖
├── README.md           # 项目说明
└── output\             # 输出目录 (自动创建)
    ├── codex-e3cb9792-xxx@hotmail.com-team.json
    └── codex-44df9455-xxx@gmail.com-team.json
```

---

## 三、配置文件

### emails.txt（账号列表）

每行一个账号，用 `----` 分隔：

```
邮箱----Outlook密码----OAuth客户端ID----Outlook刷新令牌
```

示例：

```
BonnieHernandez4458@hotmail.com----MyPass123----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.C5xx_BAY.0.U...
alice@outlook.com----AlicePwd----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.C5xx_BAY.0.U...
```

> 字段说明：
> - `邮箱`：**已在 OpenAI 注册过的** Outlook 邮箱
> - `Outlook密码`：Outlook 邮箱密码（仅记录，不参与登录流程）
> - `OAuth客户端ID`：微软 OAuth 应用的 client_id（用于 IMAP 读取验证码邮件）
> - `Outlook刷新令牌`：微软 OAuth 的 refresh_token

### proxies.txt（代理列表）

每行一个代理，按顺序分配给账号：

```
# 格式: host:port:user:pass
us.arxlabs.io:3010:user1:pass1
jp.arxlabs.io:3010:user2:pass2
```

分配规则：代理数量不足时自动循环。文件为空则使用 config.json 的全局代理。

### config.json（全局配置）

```json
{
    "proxy": "socks5h://127.0.0.1:10808",
    "pre_proxy": "",
    "max_workers": 1,
    "outlook_input_file": "emails.txt",
    "output_dir": "output"
}
```

| 字段 | 说明 | 默认值 |
|------|------|--------|
| proxy | 全局兜底代理。推荐填本机 V2Ray/Clash，如 `socks5h://127.0.0.1:10808` | 无 |
| pre_proxy | 兼容保留字段，一般不用填 | 空 |
| max_workers | 并发数 | 2 |
| outlook_input_file | 邮箱列表文件名 | emails.txt |
| output_dir | 输出目录 | output |

### 推荐代理配置（当前可用方案）

**推荐：本机先开 V2Ray/Clash，本项目再自动为外部代理建立 xray 代理链。**

也就是说：

- `config.json` 里的 `proxy` 推荐填本地代理，例如：
  - `socks5h://127.0.0.1:10808`
- `proxies.txt` 里填写外部代理，例如：
  - `us.arxlabs.io:3010:user:pass`
  - `us.1024proxy.io:3000:user:pass`

程序实际链路是：

```text
本地脚本 -> 本地 xray 临时端口 -> 本机 V2Ray/Clash -> 外部代理 -> OpenAI
```

如果 `proxies.txt` 为空，就只走 `config.json` 里的本地代理。

---

## 四、工具1：codex_login.py（批量登录）

用于直接登录 OpenAI 账号，获取 Codex 格式 Token。

### 批量登录

```cmd
cd D:\codex-login
python codex_login.py
```

### 单个账号（手动输入验证码）

```cmd
python codex_login.py --email xxx@hotmail.com
```

### 常用参数

```cmd
python codex_login.py --proxy socks5://127.0.0.1:7890
python codex_login.py --workers 3
python codex_login.py --output D:\tokens
python codex_login.py --input accounts.txt
```

---

## 五、主流程：accept_invite.py（接受邀请 + 获取 Team Token）

这是你以后**默认只需要使用的脚本**。

用途：自动搜索 ChatGPT Team/Business 邀请邮件 → 接收邀请 → 登录 → 选择团队工作区 → 获取 Team Token。

### 前提条件

> **重要：** 账号必须已在 OpenAI 完成注册。未注册的账号会在 `send-otp` 步骤失败。
>
> 流程：先手动注册账号 → 收到 Team 邀请邮件 → 运行本工具

### 批量处理

```cmd
cd D:\codex-login
python accept_invite.py
```

### 只搜索邀请（不登录）

```cmd
python accept_invite.py --search
```

### 指定账号

```cmd
python accept_invite.py --email BonnieHernandez4458@hotmail.com
```

### 指定并发数

```cmd
python accept_invite.py --workers 2
```

### 工作流程

```
1. IMAP 搜索邀请邮件 (来自 openai.com)
2. 提取邀请链接中的 accept_wId (团队工作区 ID)
3. CodexLogin 标准登录流程:
   - OAuth 初始化 (PKCE)
   - Sentinel 风控探针
   - authorize/continue (提交邮箱)
   - send-otp → 自动获取验证码 → validate-otp
   - 如果返回 about-you，会自动补全姓名和生日
4. workspace/select (选择团队工作区)
5. OAuth 重定向 → Token 交换
6. 保存 Codex 格式 Team Token
```

### 当前推荐操作流程（Windows）

以后你就按下面这个流程来：

1. 确保本机 V2Ray/Clash 已开启
2. `config.json` 保持：

```json
{
    "proxy": "socks5h://127.0.0.1:10808",
    "pre_proxy": "",
    "max_workers": 1,
    "outlook_input_file": "emails.txt",
    "output_dir": "output"
}
```

3. 在 `emails.txt` 中准备账号
4. 在 `proxies.txt` 中准备外部代理
5. 运行：

```cmd
cd D:\codex-login
python accept_invite.py --email 你的邮箱@hotmail.com
```

6. 程序会自动执行：
   - 搜索邀请邮件
   - 提取团队工作区 ID
   - 登录 OpenAI
   - 自动收验证码
   - 自动补全 about-you
   - 自动切换团队工作区
   - 自动导出 team token

7. 成功后去 `output\` 目录取 token 文件

### 批量模式（多个账号）

```cmd
python accept_invite.py
```

### 只搜索邀请（不真正登录）

```cmd
python accept_invite.py --search
```

### 一句话记住

- **以后默认跑 `accept_invite.py`**
- `codex_login.py` 只是备用脚本，一般不用

---

## 六、输出格式

两个工具输出格式一致，保存在 `output\` 目录：

文件名格式：`codex-{account_id前8位}-{邮箱}-{plan}.json`

示例：`codex-e3cb9792-BonnieHernandez4458@hotmail.com-team.json`

```json
{
    "access_token": "eyJhbGciOi...",
    "account_id": "e3cb9792-5f9c-4949-a80d-81910d767faf",
    "disabled": false,
    "email": "BonnieHernandez4458@hotmail.com",
    "expired": "2026-04-15T03:15:28+08:00",
    "id_token": "eyJhbGciOi...",
    "last_refresh": "2026-04-05T03:15:28+08:00",
    "refresh_token": "rt_3ebG...",
    "type": "codex"
}
```

> `plan` 取决于账号类型：`free` / `plus` / `team` / `enterprise`

---

## 七、常见问题

### Q: `pip` 不是内部命令？
安装 Python 时没勾选 `Add to PATH`。重新安装或手动添加：
```
C:\Users\你的用户名\AppData\Local\Programs\Python\Python311\Scripts
```

### Q: `curl_cffi` 安装失败？
```cmd
python -m pip install --upgrade pip
pip install curl_cffi
```

### Q: send-otp 返回 409？
账号未在 OpenAI 完成注册。需要先手动登录 https://chatgpt.com 完成注册流程，再运行工具。

### Q: 验证码获取超时？
- 检查 Outlook 的 refresh_token 是否过期
- IMAP 轮询间隔 3 秒，默认超时 120 秒
- 检查代理是否正常

### Q: 未找到邀请邮件？
- 确认邀请邮件已发送到该 Outlook 邮箱
- 检查是否在垃圾箱（工具只搜索收件箱）
- 邀请邮件发件人为 `noreply@tm.openai.com` 或 `noreply@openai.com`

### Q: workspace/select 失败？
- 确认邀请链接中包含 `accept_wId` 参数
- 确认账号已被邀请到该团队工作区

### Q: access_token 多久过期？
通常 10 天，JSON 文件中 `expired` 字段已标注。可用 `refresh_token` 刷新。

### Q: 代理数量少于账号数？
自动循环分配：2 条代理 + 5 个账号 → 1→代理1, 2→代理2, 3→代理1, 4→代理2, 5→代理1
