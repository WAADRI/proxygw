#!/usr/bin/env bash
# proxygw 节点一键接入脚本（Linux）
#
# 用法：
#   sudo ./install-node.sh \
#     --server https://gw.example.com:443 \
#     --token <节点接入令牌> \
#     --pin sha256/<服务端 SPKI 指纹> \
#     --client-id node-us-1 \
#     --tags us-residential --alias "美西住宅节点"
#
# 可选：
#   --binary /path/to/proxygw-client   使用本地二进制（默认从 DOWNLOAD_BASE 下载）
#   --version v1.0.0                   下载版本（配合 DOWNLOAD_BASE）
#   --no-service                       只安装与自检，不注册 systemd 服务
# 说明：脚本不会把接入令牌写入命令行历史之外的文件权限过宽的位置；配置文件 0600。
set -euo pipefail

SERVER_URL=""
TOKEN=""
PIN=""
CLIENT_ID=""
ALIAS=""
TAGS=""
REGION=""
TRANSPORT="auto"
PLANES="2"
BINARY=""
DOWNLOAD_BASE="${DOWNLOAD_BASE:-https://downloads.example.invalid/proxygw}"
VERSION="${VERSION:-latest}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/proxygw"
STATE_DIR="/var/lib/proxygw/state"
SERVICE_NAME="proxygw-client"
NO_SERVICE=0

die() { echo "错误：$*" >&2; exit 1; }
info() { echo "[proxygw] $*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server) SERVER_URL="$2"; shift 2;;
    --token) TOKEN="$2"; shift 2;;
    --pin) PIN="$2"; shift 2;;
    --client-id) CLIENT_ID="$2"; shift 2;;
    --alias) ALIAS="$2"; shift 2;;
    --tags) TAGS="$2"; shift 2;;
    --region) REGION="$2"; shift 2;;
    --transport) TRANSPORT="$2"; shift 2;;
    --planes) PLANES="$2"; shift 2;;
    --binary) BINARY="$2"; shift 2;;
    --version) VERSION="$2"; shift 2;;
    --no-service) NO_SERVICE=1; shift;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) die "未知参数 $1";;
  esac
done

[[ -n "$SERVER_URL" ]] || die "缺少 --server"
[[ -n "$TOKEN" ]] || die "缺少 --token（或在服务端配置 mTLS 时使用客户端证书）"
[[ $EUID -eq 0 ]] || die "请用 root 或 sudo 运行"

info "检测系统架构"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) GOARCH=amd64;;
  aarch64|arm64) GOARCH=arm64;;
  armv7l) GOARCH=arm;;
  *) die "不支持的架构 $ARCH";;
esac
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

if [[ -z "$BINARY" ]]; then
  command -v curl >/dev/null || die "需要 curl 下载二进制"
  BINARY="/tmp/proxygw-client-${OS}-${GOARCH}"
  URL="${DOWNLOAD_BASE}/${VERSION}/proxygw-client-${OS}-${GOARCH}"
  info "下载 $URL"
  curl -fsSL --retry 3 -o "$BINARY" "$URL" || die "下载失败，可改用 --binary 指定本地二进制"
  chmod +x "$BINARY"
fi
[[ -x "$BINARY" ]] || die "二进制不可执行：$BINARY"

info "安装二进制到 $INSTALL_DIR"
install -d "$CONFIG_DIR" "$STATE_DIR"
install -m 0755 "$BINARY" "$INSTALL_DIR/proxygw-client"

if ! id -u proxygw >/dev/null 2>&1; then
  useradd --system --home /var/lib/proxygw --shell /usr/sbin/nologin proxygw
fi
chown -R proxygw:proxygw /var/lib/proxygw
chmod 700 /var/lib/proxygw /var/lib/proxygw/state

info "写入配置 $CONFIG_DIR/config.client.yaml"
umask 077
cat > "$CONFIG_DIR/config.client.yaml" <<EOF
server_url: "$SERVER_URL"
token: "$TOKEN"
client_id: "$CLIENT_ID"
alias: "$ALIAS"
tags: [$(echo "$TAGS" | sed 's/,/","/g' | sed 's/^/"/;s/$/"/' | sed 's/""//g')]
region: "$REGION"
transport: $TRANSPORT
planes: $PLANES
state_dir: $STATE_DIR
tls:
  mode: pin
  pin: "$PIN"
  pins: []
log:
  level: info
  format: json
EOF
chown proxygw:proxygw "$CONFIG_DIR/config.client.yaml"

info "配置校验"
sudo -u proxygw "$INSTALL_DIR/proxygw-client" -config "$CONFIG_DIR/config.client.yaml" -check-config

info "安装 systemd 服务"
if [[ $NO_SERVICE -eq 0 ]] && command -v systemctl >/dev/null; then
  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=proxygw node agent
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=proxygw
Group=proxygw
WorkingDirectory=/var/lib/proxygw
ExecStart=$INSTALL_DIR/proxygw-client -config $CONFIG_DIR/config.client.yaml
Restart=always
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/proxygw
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
  sleep 2
  info "服务状态："
  systemctl --no-pager --lines=20 status "$SERVICE_NAME" || true
else
  info "未注册服务；可直接运行：$INSTALL_DIR/proxygw-client -config $CONFIG_DIR/config.client.yaml"
  "$INSTALL_DIR/proxygw-client" -config "$CONFIG_DIR/config.client.yaml" &
  CLIENT_PID=$!
  sleep 3
fi

info "连通性自检（服务端 /healthz）"
BASE_URL=$(echo "$SERVER_URL" | sed 's#^wss://#https://#; s#^ws://#http://#; s#/tunnel/*$##')
curl -fsS --max-time 5 "${BASE_URL}/healthz" || echo "警告：无法访问 ${BASE_URL}/healthz（自签证书请加 -k 或改用 ca 模式）"

cat <<'EOF'

接入完成。请到服务端面板「节点」页确认节点在线，并核对出口 IP / 归属地。
若 30 秒内节点仍离线，请按 README「故障排查」检查：
  1. 服务端 TCP+UDP 443 是否放行（QUIC 需要 UDP）；
  2. pin 指纹是否与服务端控制台打印的一致；
  3. token 是否被吊销；
  4. 日志：journalctl -u proxygw-client -n 100 --no-pager
EOF
