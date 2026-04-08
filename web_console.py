#!/usr/bin/env python3
"""
Team-Accept Web Console
统一管理 codex 注册 + codex-login 接受邀请 的 Web 控制台
"""

import http.server
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

HOST = os.environ.get("WEB_HOST", "127.0.0.1")
PORT = int(os.environ.get("WEB_PORT", "8089"))
BASE_DIR = Path(__file__).resolve().parent
CODEX_DIR = BASE_DIR / "codex"
LOGIN_DIR = BASE_DIR / "codex-login"

# ── 全局任务管理 ──
_tasks_lock = threading.Lock()
_tasks = {}  # task_id -> {type, status, output, started, email, ...}
_task_counter = 0


def _new_task_id():
    global _task_counter
    _task_counter += 1
    return f"task-{_task_counter}-{int(time.time())}"


def _run_script(task_id, work_dir, cmd):
    """在后台线程中执行脚本并实时收集输出"""
    with _tasks_lock:
        _tasks[task_id]["status"] = "running"

    try:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        proc = subprocess.Popen(
            cmd,
            cwd=str(work_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
        with _tasks_lock:
            _tasks[task_id]["pid"] = proc.pid

        lines = []
        for line in proc.stdout:
            lines.append(line)
            with _tasks_lock:
                _tasks[task_id]["output"] = "".join(lines)

        proc.wait()
        with _tasks_lock:
            _tasks[task_id]["status"] = "done" if proc.returncode == 0 else "error"
            _tasks[task_id]["exit_code"] = proc.returncode
            _tasks[task_id]["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        with _tasks_lock:
            _tasks[task_id]["status"] = "error"
            _tasks[task_id]["output"] += f"\n[Exception] {e}"
            _tasks[task_id]["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── 文件帮助函数 ──

def _read_file(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except Exception:
        return ""


def _write_file(path, content):
    Path(path).write_text(content, encoding="utf-8")


def _list_results(directory):
    results = []
    output_dir = Path(directory) / "output"
    if not output_dir.exists():
        return results
    for f in sorted(output_dir.iterdir()):
        if f.name == "proxy-chains" or f.is_dir():
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            data["_filename"] = f.name
        except Exception:
            data = {"_filename": f.name, "_raw": f.read_text(encoding="utf-8", errors="replace")[:500]}
        results.append(data)
    return results


def _get_register_failed_emails():
    """扫描 codex/output，返回注册失败的邮箱集合"""
    failed = set()
    output_dir = CODEX_DIR / "output"
    if not output_dir.exists():
        return failed
    for f in output_dir.iterdir():
        if f.is_dir() or f.name == "proxy-chains":
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if not (data.get("registered") or data.get("otp_validated")):
                email = data.get("email", "")
                if email:
                    failed.add(email)
        except Exception:
            pass
    return failed


def _get_registered_emails():
    """扫描 codex/output，返回注册成功的邮箱集合"""
    success = set()
    output_dir = CODEX_DIR / "output"
    if not output_dir.exists():
        return success
    for f in output_dir.iterdir():
        if f.is_dir() or f.name == "proxy-chains":
            continue
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if data.get("registered") or data.get("otp_validated"):
                email = data.get("email", "")
                if email:
                    success.add(email)
        except Exception:
            pass
    return success


def _get_all_failures():
    """汇总所有失败信息：注册失败 + token获取失败"""
    failures = []

    # 注册失败
    output_dir = CODEX_DIR / "output"
    registered_emails = set()
    if output_dir.exists():
        for f in sorted(output_dir.iterdir()):
            if f.is_dir() or f.name == "proxy-chains":
                continue
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                email = data.get("email", "")
                ok = data.get("registered") or data.get("otp_validated")
                if ok:
                    registered_emails.add(email)
                else:
                    failures.append({
                        "email": email or f.name,
                        "step": "注册",
                        "reason": data.get("error", "注册失败"),
                    })
            except Exception:
                pass

    # Token 获取失败
    output_dir = LOGIN_DIR / "output"
    if output_dir.exists():
        for f in sorted(output_dir.iterdir()):
            if f.is_dir() or f.name == "proxy-chains":
                continue
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                email = data.get("email", "")
                if not data.get("access_token"):
                    failures.append({
                        "email": email or f.name,
                        "step": "接受邀请/取Token",
                        "reason": data.get("error", data.get("_raw", "获取失败")),
                    })
            except Exception:
                pass

    return failures


# ── API Handler ──

class ConsoleHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sys.stderr.write(f"[{ts}] {args[0]}\n")

    def _json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw)

    # ── GET routes ──
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/":
            return self._html(INDEX_HTML)
        elif path == "/api/status":
            return self._json({"status": "ok", "tasks": len(_tasks)})
        elif path == "/api/tasks":
            with _tasks_lock:
                return self._json(list(_tasks.values()))
        elif path.startswith("/api/task/"):
            tid = path.split("/api/task/")[1]
            with _tasks_lock:
                t = _tasks.get(tid)
            if t:
                return self._json(t)
            return self._json({"error": "not found"}, 404)
        elif path == "/api/results/codex":
            return self._json(_list_results(CODEX_DIR))
        elif path == "/api/results/login":
            return self._json(_list_results(LOGIN_DIR))
        elif path == "/api/failures":
            return self._json(_get_all_failures())
        elif path == "/api/export/tokens":
            return self._export_tokens()
        elif path == "/api/export/personal-tokens":
            return self._export_tokens(personal_only=True)
        elif path == "/api/export/sessions":
            return self._export_sessions()
        else:
            self.send_error(404)

    # ── POST routes ──
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        body = self._read_body()

        if path == "/api/run/register":
            return self._start_task("register", CODEX_DIR, body)
        elif path == "/api/run/accept":
            return self._start_task("accept", LOGIN_DIR, body)
        elif path == "/api/run/login":
            return self._start_task("login", LOGIN_DIR, body)
        elif path == "/api/task/stop":
            return self._stop_task(body)
        elif path == "/api/clear/tokens":
            return self._clear_files("tokens")
        elif path == "/api/clear/sessions":
            return self._clear_files("sessions")
        else:
            self.send_error(404)

    def _start_task(self, task_type, work_dir, body):
        emails_text = body.get("emails", "").strip()
        workers = body.get("workers", "")
        proxies_text = body.get("proxies", "").strip()

        # 强制要求代理，不允许走本机网络
        proxy_lines = [l.strip() for l in proxies_text.splitlines() if l.strip() and not l.strip().startswith("#")]
        if not proxy_lines:
            return self._json({"error": "必须提供代理，不允许走本机网络"}, 400)

        # 将前端传入的代理列表写入两个模块的 proxies.txt
        # 对无协议前缀的代理，使用前端指定的默认协议补前缀（跳过不稳定的自动探测）
        default_proto = body.get("proxy_proto", "socks5")
        normalized_lines = []
        for line in proxies_text.splitlines():
            line_s = line.strip()
            if not line_s or line_s.startswith("#"):
                normalized_lines.append(line_s)
                continue
            if "://" in line_s:
                # 已有协议前缀，但仍需确保 URL 中无裸空格
                normalized_lines.append(line_s.replace(" ", "%20"))
            else:
                # host:port:user:pass 格式，补协议前缀
                parts = line_s.split(":")
                port_idx = -1
                for i in range(1, len(parts)):
                    if parts[i].isdigit():
                        port_idx = i
                        break
                if port_idx > 0:
                    host = ":".join(parts[:port_idx])
                    port = parts[port_idx]
                    rest = parts[port_idx + 1:]
                    if rest:
                        user = urllib.parse.quote(rest[0], safe="")
                        pwd = urllib.parse.quote(":".join(rest[1:]), safe="") if len(rest) > 1 else ""
                        normalized_lines.append(f"{default_proto}://{user}:{pwd}@{host}:{port}")
                    else:
                        normalized_lines.append(f"{default_proto}://{host}:{port}")
                else:
                    normalized_lines.append(line_s)
        normalized_proxies = "\n".join(normalized_lines)
        _write_file(CODEX_DIR / "proxies.txt", normalized_proxies)
        _write_file(LOGIN_DIR / "proxies.txt", normalized_proxies)

        # 将前端传入的邮箱列表写入对应模块的 emails.txt
        if emails_text:
            _write_file(work_dir / "emails.txt", emails_text)

        # 解析多行邮箱 → 逐行过滤空行
        email_lines = [l.strip() for l in emails_text.splitlines() if l.strip()]

        # 接受邀请时，自动排除注册失败的邮箱
        skipped_count = 0
        skipped_emails = []
        if task_type == "accept" and email_lines:
            failed_emails = _get_register_failed_emails()
            if failed_emails:
                before = len(email_lines)
                filtered = []
                for l in email_lines:
                    em = l.split("----")[0].strip()
                    if em in failed_emails:
                        skipped_emails.append(em)
                    else:
                        filtered.append(l)
                email_lines = filtered
                skipped_count = before - len(email_lines)
                if skipped_count > 0:
                    print(f"[auto-skip] 已排除 {skipped_count} 个注册失败的邮箱")
                if not email_lines:
                    return self._json({"error": "所有邮箱均注册失败，无可用账号"}, 400)

        extract_token = body.get("extract_token", True)
        fetch_session = body.get("fetch_session", True)

        if task_type == "register":
            cmd = [sys.executable, str(work_dir / "register_accounts.py")]
            if len(email_lines) == 1:
                cmd += ["--email", email_lines[0].split("----")[0].strip()]
            if not extract_token:
                cmd += ["--no-token"]
            if not fetch_session:
                cmd += ["--no-session"]
        elif task_type == "accept":
            cmd = [sys.executable, str(work_dir / "accept_invite.py")]
            if len(email_lines) == 1:
                cmd += ["--email", email_lines[0].split("----")[0].strip()]
        elif task_type == "login":
            work_dir = LOGIN_DIR
            cmd = [sys.executable, str(LOGIN_DIR / "login_accounts.py")]
            if len(email_lines) == 1:
                cmd += ["--email", email_lines[0].split("----")[0].strip()]
            if not fetch_session:
                cmd += ["--no-session"]

        if workers:
            cmd += ["--workers", str(workers)]

        label = email_lines[0].split("----")[0].strip() if len(email_lines) == 1 else f"(批量 {len(email_lines)} 个)" if email_lines else "(全部 emails.txt)"
        skip_info = f" (已排除 {skipped_count} 个注册失败)" if skipped_count > 0 else ""

        task_id = _new_task_id()
        with _tasks_lock:
            _tasks[task_id] = {
                "id": task_id,
                "type": task_type,
                "status": "pending",
                "output": (f"[auto-skip] 已自动排除 {skipped_count} 个注册失败的邮箱:\n" +
                          "\n".join(f"  ❌ {em}" for em in skipped_emails) + "\n\n") if skipped_count > 0 else "",
                "started": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "email": label + skip_info,
                "cmd": " ".join(cmd),
            }

        t = threading.Thread(target=_run_script, args=(task_id, work_dir, cmd), daemon=True)
        t.start()

        return self._json({"task_id": task_id, "status": "started"})

    def _stop_task(self, body):
        tid = body.get("task_id", "")
        with _tasks_lock:
            task = _tasks.get(tid)
        if not task:
            return self._json({"error": "not found"}, 404)
        pid = task.get("pid")
        if pid:
            try:
                import signal
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        with _tasks_lock:
            _tasks[tid]["status"] = "stopped"
            _tasks[tid]["finished"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return self._json({"status": "stopped"})

    def _clear_files(self, file_type):
        """清除 token 或 session 文件"""
        count = 0
        for output_dir in (CODEX_DIR / "output", LOGIN_DIR / "output"):
            if not output_dir.exists():
                continue
            for f in list(output_dir.iterdir()):
                if f.is_dir() or f.name == "proxy-chains":
                    continue
                if file_type == "tokens":
                    if f.name.startswith("token-") or (f.suffix == ".json" and not f.name.startswith(("session-", "registered-"))):
                        try:
                            data = json.loads(f.read_text(encoding="utf-8"))
                            if data.get("access_token"):
                                f.unlink()
                                count += 1
                        except Exception:
                            pass
                elif file_type == "sessions":
                    if f.name.startswith("session-"):
                        try:
                            f.unlink()
                            count += 1
                        except Exception:
                            pass
        label = "Token" if file_type == "tokens" else "Session"
        return self._json({"message": f"已清除 {count} 个 {label} 文件"})

    def _export_tokens(self, personal_only=False):
        """导出 token JSON 文件为 zip 压缩包"""
        import io
        import zipfile

        buf = io.BytesIO()
        count = 0
        seen_emails = set()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # 扫描 codex-login/output 和 codex/output 两个目录
            for output_dir in (LOGIN_DIR / "output", CODEX_DIR / "output"):
                if not output_dir.exists():
                    continue
                for f in sorted(output_dir.iterdir()):
                    if f.is_dir() or f.name == "proxy-chains":
                        continue
                    try:
                        data = json.loads(f.read_text(encoding="utf-8"))
                        if data.get("access_token"):
                            # 判断是否 Team Token: 文件名含 -team 或无 token- 前缀且在 login 目录
                            is_team = "-team" in f.name
                            if personal_only and is_team:
                                continue
                            if not personal_only:
                                pass  # 导出全部
                            email = data.get("email", "")
                            key = email or f.name
                            if key in seen_emails:
                                continue
                            seen_emails.add(key)
                            out_name = f"{email}.json" if email else f.name
                            zf.writestr(out_name, json.dumps(data, ensure_ascii=False, indent=2))
                            count += 1
                    except Exception:
                        pass

        if count == 0:
            label = "个人 token" if personal_only else "token"
            return self._json({"error": f"无可导出的 {label}"}, 404)

        body = buf.getvalue()
        prefix = "personal_tokens" if personal_only else "tokens"
        fname = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _export_sessions(self):
        """导出 session JSON 文件为 zip 压缩包"""
        import io
        import zipfile

        buf = io.BytesIO()
        count = 0
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for output_dir in (CODEX_DIR / "output", LOGIN_DIR / "output"):
                if not output_dir.exists():
                    continue
                for f in sorted(output_dir.iterdir()):
                    if not f.name.startswith("session-") or f.is_dir():
                        continue
                    try:
                        data = json.loads(f.read_text(encoding="utf-8"))
                        email = data.get("user", {}).get("email", "") or f.name.replace("session-", "").replace(".json", "")
                        out_name = f"session-{email}.json" if email else f.name
                        zf.writestr(out_name, json.dumps(data, ensure_ascii=False, indent=2))
                        count += 1
                    except Exception:
                        pass

        if count == 0:
            return self._json({"error": "无可导出的 session"}, 404)

        body = buf.getvalue()
        fname = f"sessions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)


# ── 前端 HTML ──

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Team Accept Console</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--text2:#94a3b8;--primary:#3b82f6;--green:#22c55e;--red:#ef4444;--yellow:#eab308;--orange:#f97316}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.header{background:var(--card);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;gap:16px}
.header h1{font-size:20px;font-weight:700}
.header .badge{background:var(--green);color:#000;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}
.container{max-width:1400px;margin:0 auto;padding:24px}
.tabs{display:flex;gap:4px;margin-bottom:24px;background:var(--card);border-radius:12px;padding:4px;border:1px solid var(--border)}
.tab{padding:10px 20px;border:none;background:none;color:var(--text2);cursor:pointer;border-radius:8px;font-size:14px;font-weight:500;transition:all .2s}
.tab.active{background:var(--primary);color:#fff}
.tab:hover:not(.active){background:#ffffff10}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:900px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px}
.card h3{font-size:15px;font-weight:600;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.card h3 .icon{font-size:18px}
.form-group{margin-bottom:14px}
.form-group label{display:block;font-size:13px;color:var(--text2);margin-bottom:6px}
.form-group input,.form-group select{width:100%;padding:8px 12px;background:#0f172a;border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px}
.form-group textarea{width:100%;padding:8px 12px;background:#0f172a;border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:13px;font-family:monospace;resize:vertical}
.btn{padding:8px 18px;border:none;border-radius:8px;font-size:14px;font-weight:500;cursor:pointer;transition:all .2s}
.btn-primary{background:var(--primary);color:#fff}.btn-primary:hover{filter:brightness(1.15)}
.btn-green{background:var(--green);color:#000}.btn-green:hover{filter:brightness(1.15)}
.btn-red{background:var(--red);color:#fff}.btn-red:hover{filter:brightness(1.15)}
.btn-orange{background:var(--orange);color:#000}.btn-orange:hover{filter:brightness(1.15)}
.btn-sm{padding:5px 12px;font-size:12px}
.btn-group{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.output{background:#000;border:1px solid var(--border);border-radius:8px;padding:12px;font-family:'Cascadia Code','Fira Code',monospace;font-size:12px;max-height:500px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;color:#a5f3fc;line-height:1.6}
.task-item{padding:12px;border:1px solid var(--border);border-radius:8px;margin-bottom:8px;cursor:pointer;transition:all .15s}
.task-item:hover{border-color:var(--primary)}
.task-item .meta{display:flex;justify-content:space-between;align-items:center;gap:8px}
.task-item .type{font-weight:600;font-size:13px}
.task-item .email{font-size:12px;color:var(--text2)}
.task-item .time{font-size:11px;color:var(--text2)}
.status{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.status.running{background:#3b82f620;color:var(--primary)}
.status.done{background:#22c55e20;color:var(--green)}
.status.error{background:#ef444420;color:var(--red)}
.status.pending{background:#eab30820;color:var(--yellow)}
.status.stopped{background:#f9731620;color:var(--orange)}
.result-item{padding:10px;border:1px solid var(--border);border-radius:8px;margin-bottom:6px;font-size:12px}
.result-item.success{border-left:3px solid var(--green)}
.result-item.fail{border-left:3px solid var(--red)}
.result-item .r-email{font-weight:600}
.result-item .r-email.ok{color:var(--green)}
.result-item .r-email.fail{color:var(--red)}
.result-item .r-info{color:var(--text2);margin-top:3px;font-size:11px}
.result-item .r-token{font-family:monospace;word-break:break-all;color:var(--text2);font-size:11px;margin-top:3px;max-height:40px;overflow:hidden}
.fail-item{padding:8px 10px;border:1px solid var(--border);border-left:3px solid var(--red);border-radius:6px;margin-bottom:6px;font-size:12px}
.fail-item .f-email{font-weight:600;color:var(--red)}
.fail-item .f-step{display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:600;margin-left:6px}
.fail-item .f-step.reg{background:#ef444420;color:var(--red)}
.fail-item .f-step.token{background:#f9731620;color:var(--orange)}
.fail-item .f-reason{color:var(--text2);margin-top:3px;font-size:11px}
.empty{text-align:center;padding:40px;color:var(--text2)}
.full-width{grid-column:1/-1}
.hidden{display:none}
.input-row{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:900px){.input-row{grid-template-columns:1fr}}
.action-bar{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.action-bar .form-group{margin-bottom:0;min-width:100px}
.action-bar .form-group input{width:80px}
.results-scroll{max-height:400px;overflow-y:auto}
</style>
</head>
<body>

<div class="header">
  <h1>🤖 Team Accept Console</h1>
  <span class="badge" id="statusBadge">连接中...</span>
</div>

<div class="container">
  <div class="tabs">
    <button class="tab active" data-tab="operations" onclick="switchTab('operations')">⚡ 操作</button>
    <button class="tab" data-tab="tasks" onclick="switchTab('tasks')">📋 任务</button>
  </div>

  <!-- 操作面板 -->
  <div id="panel-operations">
    <!-- 公共输入区：邮箱 + 代理 -->
    <div class="card" style="margin-bottom:20px">
      <h3><span class="icon">📋</span> 邮箱 & 代理 (所有步骤共用)</h3>
      <div class="input-row">
        <div class="form-group">
          <label>邮箱列表 (每行一个，留空=使用 emails.txt) <span id="email-count" style="color:var(--primary);font-weight:600"></span></label>
          <textarea id="shared-emails" rows="8" oninput="updateCounts()" placeholder="email----outlook_pwd----client_id----refresh_token&#10;email----outlook_pwd----client_id----refresh_token&#10;..."></textarea>
        </div>
        <div class="form-group">
          <label>代理列表 (每行一个，<b style="color:var(--red)">必填</b>) <span id="proxy-count" style="color:var(--orange);font-weight:600"></span>
            <select id="proxy-proto" style="margin-left:8px;padding:2px 6px;background:#0f172a;border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px">
              <option value="socks5">默认 SOCKS5</option>
              <option value="http">默认 HTTP</option>
            </select>
          </label>
          <textarea id="shared-proxies" rows="8" oninput="updateCounts()" placeholder="host:port:user:pass&#10;socks5://user:pass@ip:port&#10;..."></textarea>
        </div>
      </div>
      <div class="action-bar" style="margin-top:12px">
        <div class="form-group">
          <label>并发数</label>
          <input type="number" id="shared-workers" value="2" min="1" max="20">
        </div>
        <button class="btn btn-primary" onclick="runTask('register')">🚀 开始注册</button>
        <button class="btn btn-orange" onclick="runTask('login')">🔑 登录取 Token</button>
        <button class="btn btn-green" onclick="runTask('accept')">✅ 接受邀请 + 取 Token</button>
      </div>
      <div style="display:flex;gap:16px;margin-top:8px;padding-left:2px">
        <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;user-select:none">
          <input type="checkbox" id="extract-token" checked style="width:16px;height:16px;cursor:pointer">
          注册后提取个人Token
        </label>
        <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;user-select:none">
          <input type="checkbox" id="fetch-session" checked style="width:16px;height:16px;cursor:pointer">
          注册后导出Session
        </label>
      </div>
    </div>

    <!-- 下方：实时输出 + 失败列表 + 结果 -->
    <div class="grid" style="grid-template-columns:1fr 1fr">
      <div>
        <div class="card" style="margin-bottom:20px">
          <h3><span class="icon">📊</span> 实时输出</h3>
          <div class="output" id="live-output" style="min-height:260px">等待任务启动...</div>
        </div>
        <div class="card">
          <h3><span class="icon">❌</span> 失败账号 <button class="btn btn-sm btn-red" onclick="loadFailures()" style="margin-left:auto">刷新</button></h3>
          <div class="results-scroll" id="failures-container" style="max-height:220px"><div class="empty" style="padding:20px">暂无失败记录</div></div>
        </div>
      </div>
      <div>
        <div class="card" style="margin-bottom:20px">
          <h3>
            <span class="icon">📝</span> 注册结果
            <button class="btn btn-sm btn-primary" onclick="loadTokenResults()" style="margin-left:auto">刷新</button>
          </h3>
          <div class="results-scroll" id="reg-results" style="max-height:180px"><div class="empty">暂无注册记录</div></div>
        </div>
        <div class="card" style="margin-bottom:20px">
          <h3>
            <span class="icon">🎫</span> Token 结果
            <button class="btn btn-sm btn-primary" onclick="loadTokenResults()" style="margin-left:auto">刷新</button>
            <button class="btn btn-sm btn-green" onclick="exportTokens()">📥 全部</button>
            <button class="btn btn-sm btn-orange" onclick="exportPersonalTokens()">📥 个人</button>
            <button class="btn btn-sm btn-red" onclick="clearFiles('tokens')">🗑 清除</button>
          </h3>
          <div class="results-scroll" id="token-results"><div class="empty">暂无 Token</div></div>
        </div>
        <div class="card">
          <h3>
            <span class="icon">🌐</span> Session 结果
            <button class="btn btn-sm btn-primary" onclick="loadSessionResults()" style="margin-left:auto">刷新</button>
            <button class="btn btn-sm btn-primary" onclick="exportSessions()" style="background:#8b5cf6">📥 导出</button>
            <button class="btn btn-sm btn-red" onclick="clearFiles('sessions')">🗑 清除</button>
          </h3>
          <div class="results-scroll" id="session-results"><div class="empty">点击刷新查看</div></div>
        </div>
      </div>
    </div>
  </div>

  <!-- 任务面板 -->
  <div id="panel-tasks" class="grid hidden">
    <div class="card full-width">
      <h3><span class="icon">📋</span> 任务列表 <button class="btn btn-sm btn-primary" onclick="refreshTasks()" style="margin-left:auto">刷新</button></h3>
      <div id="task-list"><div class="empty">暂无任务</div></div>
    </div>
    <div class="card full-width">
      <h3><span class="icon">📄</span> 任务详情</h3>
      <div class="output" id="task-detail" style="min-height:200px">点击左侧任务查看详情...</div>
    </div>
  </div>

</div>

<script>
let currentTab = 'operations';
let pollTimer = null;
let currentTaskId = null;

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
  ['operations','tasks'].forEach(p => {
    document.getElementById('panel-'+p).classList.toggle('hidden', p !== tab);
  });
  currentTab = tab;
  if (tab === 'tasks') refreshTasks();
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  return r.json();
}

async function runTask(type) {
  const emails = document.getElementById('shared-emails').value.trim();
  const proxies = document.getElementById('shared-proxies').value.trim();
  const workers = document.getElementById('shared-workers').value;
  const extract_token = document.getElementById('extract-token').checked;
  const fetch_session = document.getElementById('fetch-session').checked;
  const proxy_proto = document.getElementById('proxy-proto').value;
  const res = await api('/api/run/' + type, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({emails, workers, proxies, extract_token, fetch_session, proxy_proto})
  });
  currentTaskId = res.task_id;
  document.getElementById('live-output').textContent = '任务已启动: ' + res.task_id + '\n';
  startPoll();
}

function startPoll() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    if (!currentTaskId) return;
    const t = await api('/api/task/' + currentTaskId);
    const el = document.getElementById('live-output');
    el.textContent = `[${t.type}] ${t.status} | ${t.email}\n${'-'.repeat(50)}\n${t.output || '(waiting...)'}`;
    el.scrollTop = el.scrollHeight;
    // 轮询期间同步刷新失败列表
    loadFailures();
    if (['done','error','stopped'].includes(t.status)) {
      clearInterval(pollTimer);
      pollTimer = null;
      loadResults();
      loadFailures();
    }
  }, 1500);
}

async function refreshTasks() {
  const tasks = await api('/api/tasks');
  const el = document.getElementById('task-list');
  if (!tasks.length) {
    el.innerHTML = '<div class="empty">暂无任务</div>';
    return;
  }
  el.innerHTML = tasks.reverse().map(t => `
    <div class="task-item" onclick="showTask('${t.id}')">
      <div class="meta">
        <span class="type">${{register:'📝 注册',accept:'✅ 接受邀请+Token',login:'🔑 登录取Token'}[t.type] || t.type}</span>
        <span class="status ${t.status}">${t.status}</span>
      </div>
      <div class="meta" style="margin-top:6px">
        <span class="email">${t.email}</span>
        <span class="time">${t.started}</span>
      </div>
      ${t.status==='running'?'<button class="btn btn-sm btn-red" style="margin-top:6px" onclick="event.stopPropagation();stopTask(\''+t.id+'\')">停止</button>':''}
    </div>
  `).join('');
}

async function showTask(tid) {
  const t = await api('/api/task/' + tid);
  document.getElementById('task-detail').textContent =
    `Task: ${t.id}\nType: ${t.type}\nStatus: ${t.status}\nEmail: ${t.email}\nCmd: ${t.cmd}\nStarted: ${t.started}\nFinished: ${t.finished||'-'}\n${'='.repeat(50)}\n${t.output||'(no output)'}`;
}

async function stopTask(tid) {
  await api('/api/task/stop', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({task_id: tid})
  });
  refreshTasks();
}

function loadResults() { loadTokenResults(); loadSessionResults(); }

async function loadTokenResults() {
  const [codex, login] = await Promise.all([
    api('/api/results/codex'), api('/api/results/login')
  ]);
  const el = document.getElementById('token-results');
  let html = '';

  const codexTokens = codex.filter(r => r.access_token && !(r._filename||'').startsWith('session-'));
  const allTokens = [...login.filter(r => r.access_token), ...codexTokens];

  if (allTokens.length) {
    html += '<div style="font-size:12px;color:var(--text2);margin-bottom:6px">' + allTokens.length + ' 个 Token</div>';
    for (const r of allTokens) {
      const source = r._filename && r._filename.startsWith('token-') ? ' (注册提取)' : '';
      html += `<div class="result-item success">
        <div class="r-email ok">✅ ${r.email||r._filename}${source}</div>
        ${r.type?`<div class="r-info">类型: ${r.type} | 过期: ${r.expired||'-'}</div>`:''}
        <div class="r-token">${r.access_token.substring(0,100)}...</div>
      </div>`;
    }
  }

  el.innerHTML = html || '<div class="empty">暂无 Token</div>';

  // 注册结果单独加载到注册结果区域
  const regEl = document.getElementById('reg-results');
  if (regEl) {
    const codexRegs = codex.filter(r => !r.access_token && !(r._filename||'').startsWith('session-'));
    let regHtml = '';
    if (codexRegs.length) {
      regHtml += '<div style="font-size:12px;color:var(--text2);margin-bottom:6px">' + codexRegs.length + ' 个注册记录</div>';
      for (const r of codexRegs) {
        const ok = r.registered || r.otp_validated;
        const tokenTag = r.token_extracted ? ' <span style="color:var(--green);font-size:11px">🎫 Token已提取</span>' : '';
        regHtml += `<div class="result-item ${ok?'success':'fail'}">
          <div class="r-email ${ok?'ok':'fail'}">${ok?'✅':'❌'} ${r.email||r._filename}${tokenTag}</div>
          ${r.registration_method?`<div class="r-info">方式: ${r.registration_method}</div>`:''}
          ${!ok && r._raw?`<div class="r-info" style="color:var(--red)">${r._raw}</div>`:''}
        </div>`;
      }
    }
    regEl.innerHTML = regHtml || '<div class="empty">暂无注册记录</div>';
  }
}

async function loadSessionResults() {
  const codex = await api('/api/results/codex');
  const el = document.getElementById('session-results');
  const sessions = codex.filter(r => r._filename && r._filename.startsWith('session-'));
  if (!sessions.length) {
    el.innerHTML = '<div class="empty">暂无 Session</div>';
    return;
  }
  let html = '<div style="font-size:12px;color:var(--text2);margin-bottom:6px">' + sessions.length + ' 个 Session</div>';
  for (const r of sessions) {
    const email = (r.user && r.user.email) || r._filename.replace('session-','').replace('.json','');
    const fields = Object.keys(r).filter(k => k !== '_filename');
    html += `<div class="result-item success" style="border-left-color:#8b5cf6">
      <div class="r-email ok" style="color:#8b5cf6">🌐 ${email}</div>
      <div class="r-info">字段: ${fields.join(', ')}</div>
      ${r.accessToken?`<div class="r-token">${r.accessToken.substring(0,80)}...</div>`:''}
    </div>`;
  }
  el.innerHTML = html;
}

async function clearFiles(type) {
  if (!confirm('确认清除所有 ' + (type==='tokens'?'Token':'Session') + ' 文件？')) return;
  const res = await api('/api/clear/' + type, {method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'});
  alert(res.message || res.error || '完成');
  if (type === 'tokens') loadTokenResults(); else loadSessionResults();
}

async function loadFailures() {
  const failures = await api('/api/failures');
  const el = document.getElementById('failures-container');
  if (!failures.length) {
    el.innerHTML = '<div class="empty" style="padding:20px">暂无失败记录</div>';
    return;
  }
  let html = '';
  for (const f of failures) {
    const stepCls = f.step === '注册' ? 'reg' : 'token';
    html += `<div class="fail-item">
      <span class="f-email">${f.email}</span>
      <span class="f-step ${stepCls}">${f.step}</span>
      <div class="f-reason">${f.reason || '未知错误'}</div>
    </div>`;
  }
  el.innerHTML = html;
}

function exportTokens() {
  window.location.href = '/api/export/tokens';
}

function exportPersonalTokens() {
  window.location.href = '/api/export/personal-tokens';
}

function exportSessions() {
  window.location.href = '/api/export/sessions';
}

function updateCounts() {
  const emails = document.getElementById('shared-emails').value.trim();
  const proxies = document.getElementById('shared-proxies').value.trim();
  const emailCount = emails ? emails.split('\n').filter(l => l.trim()).length : 0;
  const proxyCount = proxies ? proxies.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).length : 0;
  document.getElementById('email-count').textContent = emailCount > 0 ? `(${emailCount} 个账号)` : '';
  document.getElementById('proxy-count').textContent = proxyCount > 0 ? `(${proxyCount} 条代理)` : '(未填写)';
  document.getElementById('proxy-count').style.color = proxyCount > 0 ? 'var(--orange)' : 'var(--red)';
}

// 初始化
(async () => {
  try {
    const s = await api('/api/status');
    document.getElementById('statusBadge').textContent = '在线';
    updateCounts();
    loadResults();
    loadFailures();
  } catch {
    document.getElementById('statusBadge').textContent = '离线';
    document.getElementById('statusBadge').style.background = '#ef4444';
  }
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer((HOST, PORT), ConsoleHandler)
    print(f"[Team-Accept Console] 启动于 http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Team-Accept Console] 已停止")
        server.shutdown()
