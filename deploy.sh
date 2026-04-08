#!/bin/bash
# ============================================
# Team-Accept 一键部署脚本
# 支持 Ubuntu/Debian/CentOS
# ============================================
set -e

echo "========================================"
echo "  Team-Accept 一键部署"
echo "========================================"

# ── 1. 检查 Python ──
if ! command -v python3 &>/dev/null; then
    echo "[!] 未找到 python3，正在安装..."
    if command -v apt &>/dev/null; then
        sudo apt update && sudo apt install -y python3 python3-pip python3-venv
    elif command -v yum &>/dev/null; then
        sudo yum install -y python3 python3-pip
    else
        echo "[ERROR] 无法自动安装 python3，请手动安装"
        exit 1
    fi
fi
echo "[✓] Python: $(python3 --version)"

# ── 2. 安装依赖 ──
echo "[*] 安装 Python 依赖..."
pip3 install --break-system-packages curl_cffi 2>/dev/null || pip3 install curl_cffi
echo "[✓] 依赖安装完成"

# ── 3. 创建目录结构 ──
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "[*] 项目目录: $BASE_DIR"

mkdir -p "$BASE_DIR/codex/output"
mkdir -p "$BASE_DIR/codex-login/output"

# ── 4. 创建空的 emails.txt (如果不存在) ──
for sub in codex codex-login; do
    if [ ! -f "$BASE_DIR/$sub/emails.txt" ]; then
        echo "# 每行一个账号，格式: email----outlook_pwd----client_id----refresh_token" > "$BASE_DIR/$sub/emails.txt"
        echo "[✓] 已创建 $sub/emails.txt (空模板)"
    fi
done

# ── 5. 配置监听地址 ──
DEFAULT_HOST="0.0.0.0"
DEFAULT_PORT="8089"

read -p "[?] 监听地址 (默认 $DEFAULT_HOST): " HOST
HOST=${HOST:-$DEFAULT_HOST}

read -p "[?] 监听端口 (默认 $DEFAULT_PORT): " PORT
PORT=${PORT:-$DEFAULT_PORT}

# ── 6. 创建 systemd 服务 (可选) ──
read -p "[?] 是否创建 systemd 服务实现开机自启? (y/N): " CREATE_SERVICE

if [[ "$CREATE_SERVICE" =~ ^[Yy]$ ]]; then
    SERVICE_FILE="/etc/systemd/system/team-accept.service"
    sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Team-Accept Web Console
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$BASE_DIR
Environment=WEB_HOST=$HOST
Environment=WEB_PORT=$PORT
ExecStart=$(which python3) $BASE_DIR/web_console.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable team-accept
    sudo systemctl start team-accept
    echo "[✓] systemd 服务已创建并启动"
    echo "    管理命令:"
    echo "      sudo systemctl status team-accept"
    echo "      sudo systemctl restart team-accept"
    echo "      sudo systemctl stop team-accept"
    echo "      journalctl -u team-accept -f"
else
    # 直接启动
    echo "[*] 直接启动服务..."
    WEB_HOST=$HOST WEB_PORT=$PORT nohup python3 "$BASE_DIR/web_console.py" > "$BASE_DIR/console.log" 2>&1 &
    echo "[✓] 服务已在后台启动 (PID: $!)"
    echo "    查看日志: tail -f $BASE_DIR/console.log"
fi

echo ""
echo "========================================"
echo "  部署完成!"
echo "  访问地址: http://$HOST:$PORT"
echo "========================================"
echo ""
echo "提示:"
echo "  1. 如有防火墙，请放行端口 $PORT"
echo "     ufw allow $PORT  或  firewall-cmd --add-port=$PORT/tcp --permanent"
echo "  2. 邮箱格式: email----outlook_pwd----client_id----refresh_token"
echo "  3. 代理格式: host:port:user:pass"
