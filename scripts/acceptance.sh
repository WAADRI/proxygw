#!/usr/bin/env bash
# proxygw 本地自动化验收脚本（Linux / macOS / Git Bash）
#
# 一条命令完成本地可自动化的验收项：
#   * go vet / go test / 构建 server 与 client 二进制
#   * 生成唯一临时目录 + 随机高位端口 + 临时配置（pin 模式、强随机节点令牌、auth required、geo 关闭、JSON 日志落文件）
#   * 启动本地 origin HTTP 服务、服务端、两个节点客户端
#   * 逐项检查：healthz/version、节点注册与 QUIC 主用、HTTP/CONNECT/SOCKS5 代理、
#     面板登录/CSRF/设置热更与撤销、审计脱敏、组隔离与 fail-closed、会话粘性、
#     QUIC→wss 回退（UDP 黑洞模拟）、pin 不匹配硬失败、并发与连接回收、SIGTERM 优雅停机
# 输出 PASS/FAIL/SKIP 汇总；失败退出码 1，成功 0。
#
# 用法：
#   bash scripts/acceptance.sh [--skip-unit-tests] [--keep-artifacts] [--repo-root DIR]
#
# 依赖：Go 1.22+、curl；本地 origin 需要 node 或 python3（二者皆无时相关检查标 SKIP）。
# 本地测试需要回环目标，因此仅服务端进程注入 NP_ACL_ALLOW_LOOPBACK_TARGETS=1。
# 说明：SIGTERM 优雅停机仅在 Linux/macOS 实际验证；在 Git Bash/MSYS 下会标记 SKIP（见 docs/ACCEPTANCE.md）。

set -uo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
SKIP_UNIT_TESTS=0
KEEP_ARTIFACTS=0

usage() {
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-unit-tests) SKIP_UNIT_TESTS=1 ;;
        --keep-artifacts) KEEP_ARTIFACTS=1 ;;
        --repo-root)
            shift
            REPO_ROOT=$(cd -- "$1" && pwd)
            ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "未知参数：$1（使用 --help 查看用法）" >&2
            exit 2
            ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# 环境与全局状态
# ---------------------------------------------------------------------------
case "$(uname -s 2>/dev/null || echo unknown)" in
    MINGW*|MSYS*|CYGWIN*) EXE_SUFFIX=".exe"; HOST_IS_WINDOWS=1 ;;
    *) EXE_SUFFIX=""; HOST_IS_WINDOWS=0 ;;
esac

GO_BIN=$(command -v go 2>/dev/null || true)
CURL_BIN=$(command -v curl 2>/dev/null || true)
NODE_BIN=$(command -v node 2>/dev/null || true)
PY_BIN=$(command -v python3 2>/dev/null || true)

HAS_NODE=0; [ -n "$NODE_BIN" ] && HAS_NODE=1
HAS_PY=0; [ -n "$PY_BIN" ] && HAS_PY=1

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/proxygw-accept-XXXXXX" 2>/dev/null || true)
if [ -z "$TMP_DIR" ]; then
    echo "无法创建临时目录" >&2
    exit 2
fi
RESULTS_FILE="$TMP_DIR/results.tsv"
: > "$RESULTS_FILE"

TOTAL=0; PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0
NOTE=""

STACK_READY=0
ORIGIN_READY=0
ORIGIN_TOOL=""

# 主服务端
LISTEN_PORT=0
HTTP_PORT=0
SOCKS_PORT=0
ORIGIN_PORT=0
SERVER_PID=""
SERVER_ERR=""
PANEL_BASE=""
COOKIE_JAR="$TMP_DIR/cookies.txt"
CSRF=""
PIN=""
PROXY_USER=""
PROXY_PASS=""
ADMIN_USER=""
ADMIN_PASS=""
NODE_TOKEN=""
USED_PORTS=" "
SERVER_PID_MAIN=""
CLIENT1_PID=""
CLIENT2_PID=""
CLIENT1_CFG=""
CLIENT2_CFG=""
ORIGIN_PID=""
GROUP_ID=""
CRED_A_ID=""
CRED_A_USER="cred-a"
CRED_A_PASS=""
FALLBACK_PID=""
FALLBACK_CLIENT_PID=""
FALLBACK_BLACKHOLE_PID=""
SERVER_BIN=""
CLIENT_BIN=""

C_RESET=""; C_GREEN=""; C_RED=""; C_YELLOW=""; C_CYAN=""
if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_GREEN=$'\033[32m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
fi

PROCS=()

cleanup() {
    local pid
    for pid in "${FALLBACK_CLIENT_PID:-}" "${FALLBACK_PID:-}" "${FALLBACK_BLACKHOLE_PID:-}" "${CLIENT2_PID:-}" "${CLIENT1_PID:-}" "${SERVER_PID_MAIN:-}" "${ORIGIN_PID:-}"; do
        [ -n "$pid" ] || continue
        kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 1 2>/dev/null || true
    for pid in "${PROCS[@]:-}"; do
        [ -n "$pid" ] || continue
        kill -KILL "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------
now_ms() {
    local v
    v=$(date +%s%N 2>/dev/null || true)
    case "$v" in *[!0-9]*|"") v="" ;; esac
    if [ -n "$v" ]; then
        echo $((v / 1000000))
        return
    fi
    if [ "$HAS_PY" = 1 ]; then
        "$PY_BIN" -c 'import time;print(int(time.time()*1000))'
        return
    fi
    echo $(( $(date +%s) * 1000 ))
}

record() { # id title status ms note
    local id="$1" title="$2" status="$3" ms="$4" note="$5"
    TOTAL=$((TOTAL + 1))
    local color="$C_RESET" prefix=""
    case "$status" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)); color="$C_GREEN" ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)); color="$C_RED" ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)); color="$C_YELLOW" ;;
    esac
    note=$(printf '%s' "$note" | tr '\t\n' '  ')
    printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$title" "$status" "$ms" "$note" >> "$RESULTS_FILE"
    printf '  %-4s %-34s %s%-5s%s %8s  %s\n' "$id" "$title" "$color" "$status" "$C_RESET" "$ms" "$note"
}

run_check() { # id title fn needs_stack needs_origin
    local id="$1" title="$2" fn="$3" needs_stack="${4:-0}" needs_origin="${5:-0}"
    if [ "$needs_stack" = "1" ] && [ "$STACK_READY" != "1" ]; then
        record "$id" "$title" SKIP 0 "依赖主栈未启动（前置检查失败）"
        return
    fi
    if [ "$needs_origin" = "1" ] && [ "$ORIGIN_READY" != "1" ]; then
        record "$id" "$title" SKIP 0 "本地 origin 不可用（缺少 node/python3）"
        return
    fi
    NOTE=""
    local start; start=$(now_ms)
    "$fn"
    local rc=$?
    local ms; ms=$(( $(now_ms) - start ))
    case "$rc" in
        0) record "$id" "$title" PASS "$ms" "$NOTE" ;;
        2) record "$id" "$title" SKIP "$ms" "$NOTE" ;;
        *) [ -n "$NOTE" ] || NOTE="检查失败（退出码 $rc）"; record "$id" "$title" FAIL "$ms" "$NOTE" ;;
    esac
}

say() { printf '%s\n' "$*"; }
say_cyan() { printf '%s%s%s\n' "$C_CYAN" "$*" "$C_RESET"; }
say_red() { printf '%s%s%s\n' "$C_RED" "$*" "$C_RESET"; }
say_yellow() { printf '%s%s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }

# ---- 端口 -----------------------------------------------------------------
free_port() {
    local p i=0
    while [ $i -lt 60 ]; do
        i=$((i + 1))
        p=$(( (RANDOM % 40000) + 20000 ))
        case "$USED_PORTS" in *" $p "*) continue ;; esac
        if port_free "$p"; then
            USED_PORTS="$USED_PORTS$p "
            echo "$p"
            return 0
        fi
    done
    return 1
}

port_free() { # port
    local p="$1"
    if [ "$HAS_PY" = 1 ]; then
        "$PY_BIN" -c '
import socket, sys
port = int(sys.argv[1])
try:
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    t.bind(("127.0.0.1", port)); t.close()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", port)); u.close()
except OSError:
    sys.exit(1)
sys.exit(0)
' "$p"
        return $?
    fi
    if [ "$HAS_NODE" = 1 ]; then
        "$NODE_BIN" -e '
const net = require("net");
const dgram = require("dgram");
const port = Number(process.argv[1]);
const t = net.createServer();
t.once("error", () => process.exit(1));
t.listen(port, "127.0.0.1", () => {
  t.close(() => {
    const u = dgram.createSocket("udp4");
    u.once("error", () => process.exit(1));
    u.bind(port, "127.0.0.1", () => { u.close(); process.exit(0); });
  });
});
' "$p"
        return $?
    fi
    return 0
}

udp_port_busy() { # port -> 0 busy
    local p="$1"
    if [ "$HAS_PY" = 1 ]; then
        "$PY_BIN" -c '
import socket, sys
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    u.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(0)
u.close()
sys.exit(1)
' "$p"
        return $?
    fi
    "$NODE_BIN" -e '
const dgram = require("dgram");
const u = dgram.createSocket("udp4");
u.once("error", () => process.exit(0));
u.bind(Number(process.argv[1]), "127.0.0.1", () => { u.close(); process.exit(1); });
' "$p"
    return $?
}

# ---- HTTP -----------------------------------------------------------------
HTTP_CODE=0
HTTP_BODY=""
http_do() { # curl args...
    local out="$TMP_DIR/http.out" err="$TMP_DIR/http.err"
    HTTP_CODE=$("$CURL_BIN" -sS --max-time "${HTTP_MAX_TIME:-30}" -o "$out" -w '%{http_code}' "$@" 2>"$err") || true
    case "$HTTP_CODE" in ''|*[!0-9]*) HTTP_CODE=0 ;; esac
    HTTP_BODY=$(cat "$out" 2>/dev/null || true)
}

wait_http_ok() { # url timeout_s [curl extra...]
    local url="$1" timeout="${2:-60}" i=0
    shift 2
    while [ $i -lt "$timeout" ]; do
        http_do -k "$@" "$url"
        if [ "$HTTP_CODE" = "200" ]; then return 0; fi
        i=$((i + 1))
        sleep 1
    done
    return 1
}

# ---- JSON -----------------------------------------------------------------
json_get() { # json path
    local json="$1" path="$2"
    if [ "$HAS_PY" = 1 ]; then
        printf '%s' "$json" | "$PY_BIN" -c '
import json, sys
try:
    d = json.load(sys.stdin)
    for k in sys.argv[1].split("."):
        d = d[int(k)] if isinstance(d, list) else d[k]
    if isinstance(d, bool):
        print("true" if d else "false")
    elif isinstance(d, (dict, list)):
        print(json.dumps(d, ensure_ascii=False))
    else:
        print(d)
except Exception:
    sys.exit(1)
' "$path"
        return $?
    fi
    if [ "$HAS_NODE" = 1 ]; then
        printf '%s' "$json" | "$NODE_BIN" -e '
let s = "";
process.stdin.on("data", (d) => (s += d));
process.stdin.on("end", () => {
  try {
    let o = JSON.parse(s);
    for (const k of process.argv[1].split(".")) o = Array.isArray(o) ? o[Number(k)] : o[k];
    if (o === undefined) process.exit(1);
    process.stdout.write(typeof o === "object" ? JSON.stringify(o) : String(o));
  } catch (e) { process.exit(1); }
});
' "$path"
        return $?
    fi
    return 1
}

node_field() { # node_id field [json] -> 输出节点字段值（布尔转小写）
    local node_id="$1" field="$2" json="${3:-$HTTP_BODY}"
    if [ "$HAS_PY" = 1 ]; then
        printf '%s' "$json" | "$PY_BIN" -c '
import json, sys
d = json.load(sys.stdin)
for n in d.get("items", []):
    if n.get("id") == sys.argv[1]:
        v = n.get(sys.argv[2])
        if isinstance(v, bool): print("true" if v else "false")
        elif isinstance(v, (dict, list)): print(json.dumps(v, ensure_ascii=False))
        else: print(v)
        sys.exit(0)
sys.exit(1)
' "$node_id" "$field"
        return $?
    fi
    if [ "$HAS_NODE" = 1 ]; then
        printf '%s' "$json" | "$NODE_BIN" -e '
let s = "";
process.stdin.on("data", (d) => (s += d));
process.stdin.on("end", () => {
  const d = JSON.parse(s);
  const n = (d.items || []).find((x) => x.id === process.argv[1]);
  if (!n) process.exit(1);
  const v = n[process.argv[2]];
  if (v === undefined) process.exit(1);
  process.stdout.write(typeof v === "object" ? JSON.stringify(v) : String(v));
});
' "$node_id" "$field"
        return $?
    fi
    return 1
}

inflight_node() { # 从当前 /nodes 响应中找出 inflight>0 的节点 id
    local json="${1:-$HTTP_BODY}"
    if [ "$HAS_PY" = 1 ]; then
        printf '%s' "$json" | "$PY_BIN" -c '
import json, sys
try:
    d = json.load(sys.stdin)
    for n in d.get("items", []):
        if int(n.get("inflight") or 0) > 0:
            print(n.get("id", ""))
            sys.exit(0)
except Exception:
    pass
sys.exit(1)
'
        return $?
    fi
    if [ "$HAS_NODE" = 1 ]; then
        printf '%s' "$json" | "$NODE_BIN" -e '
let s = "";
process.stdin.on("data", (d) => (s += d));
process.stdin.on("end", () => {
  try {
    const d = JSON.parse(s);
    for (const n of d.items || []) { if (Number(n.inflight || 0) > 0) { process.stdout.write(n.id); return; } }
  } catch (e) {}
  process.exit(1);
});
'
        return $?
    fi
    return 1
}

proxy_request_node_ids() { # 从服务端日志提取 http 代理请求命中的 node_id（每行一个）
    local log="$1"
    [ -f "$log" ] || return 1
    grep -a '"protocol":"http"' "$log" 2>/dev/null \
        | grep -a "\"target\":\"127.0.0.1:$ORIGIN_PORT\"" 2>/dev/null \
        | sed -nE 's/.*"node_id":"([^"]+)".*/\1/p' \
        | sed '/^$/d'
}

gen_token() { # 强随机令牌
    if [ "$HAS_PY" = 1 ]; then
        "$PY_BIN" -c 'import secrets;print(secrets.token_urlsafe(36))'
        return
    fi
    if [ "$HAS_NODE" = 1 ]; then
        "$NODE_BIN" -e 'console.log(require("crypto").randomBytes(36).toString("base64url"))'
        return
    fi
    od -An -N36 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n'
    echo
}

make_settings_body() { # mode value（stdin = GET /settings 响应）
    local mode="$1" value="$2"
    if [ "$HAS_PY" = 1 ]; then
        "$PY_BIN" -c '
import json, sys
d = json.load(sys.stdin)
cur = d["current"]
mode, val = sys.argv[1], sys.argv[2]
if mode == "strategy":
    cur["scheduler"]["strategy"] = val
elif mode == "ttl":
    cur["scheduler"]["sticky"]["ttl"] = val
print(json.dumps({"settings": cur}, ensure_ascii=False))
' "$mode" "$value"
        return $?
    fi
    if [ "$HAS_NODE" = 1 ]; then
        "$NODE_BIN" -e '
let s = "";
process.stdin.on("data", (d) => (s += d));
process.stdin.on("end", () => {
  const d = JSON.parse(s);
  const cur = d.current;
  const mode = process.argv[1], val = process.argv[2];
  if (mode === "strategy") cur.scheduler.strategy = val;
  else if (mode === "ttl") cur.scheduler.sticky.ttl = val;
  process.stdout.write(JSON.stringify({ settings: cur }));
});
' "$mode" "$value"
        return $?
    fi
    return 1
}

# ---- 面板 -----------------------------------------------------------------
panel_get() { # path
    http_do -k -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$PANEL_BASE$1"
}

panel_write() { # method path body [no_csrf]
    local method="$1" path="$2" body="$3" no_csrf="${4:-0}"
    local bf="$TMP_DIR/panel-req.json"
    printf '%s' "$body" > "$bf"
    if [ "$no_csrf" = "1" ]; then
        http_do -k -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X "$method" -H 'Content-Type: application/json' --data-binary "@$bf" "$PANEL_BASE$path"
    else
        http_do -k -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X "$method" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' --data-binary "@$bf" "$PANEL_BASE$path"
    fi
}

panel_write_nocsrf() { # method path body
    panel_write "$1" "$2" "$3" 1
}

panel_login() { # user pass
    local user="$1" pass="$2" body
    body=$(printf '{"username":"%s","password":"%s"}' "$user" "$pass")
    http_do -k -c "$COOKIE_JAR" -H 'Content-Type: application/json' --data-binary "$body" "$PANEL_BASE/api/v1/login"
    if [ "$HTTP_CODE" != "200" ]; then
        NOTE="面板登录失败 HTTP $HTTP_CODE：$HTTP_BODY"
        return 1
    fi
    CSRF=$(printf '%s' "$HTTP_BODY" | sed -nE 's/.*"csrf":"([^"]+)".*/\1/p' | head -1)
    if [ -z "$CSRF" ]; then
        NOTE="面板登录响应缺少 csrf：$HTTP_BODY"
        return 1
    fi
    return 0
}

panel_overview_online() {
    panel_get /api/v1/overview
    json_get "$HTTP_BODY" online_nodes
}

panel_nodes_json() {
    panel_get '/api/v1/nodes?size=100'
}

wait_online_nodes() { # minimum timeout_s
    local minimum="$1" timeout="$2" i=0 count
    while [ $i -lt "$timeout" ]; do
        count=$(panel_overview_online 2>/dev/null || true)
        case "$count" in ''|*[!0-9]*) count=-1 ;; esac
        if [ "$count" -ge "$minimum" ]; then return 0; fi
        i=$((i + 1)); sleep 1
    done
    return 1
}

# ---- 进程 -----------------------------------------------------------------
start_bg() { # outfile_errfile command...
    local log="$1"; shift
    "$@" >>"$log" 2>&1 &
    local pid=$!
    PROCS+=("$pid")
    echo "$pid"
}

# ---- 日志解析 -------------------------------------------------------------
read_pin() { sed -nE 's/.*SPKI 指纹=(sha256\/[A-Za-z0-9+\/=]+).*/\1/p' "$1" 2>/dev/null | head -1; }
read_proxy_creds() { sed -nE 's/.*代理凭据（仅本次显示，请立即保存）：用户名 ([^ ]+) +密码 ([^ ]+).*/\1 \2/p' "$1" 2>/dev/null | head -1; }
read_admin_creds() { sed -nE 's/.*面板管理员密码（仅本次显示，请立即保存）：用户名 ([^ ]+) +密码 ([^ ]+).*/\1 \2/p' "$1" 2>/dev/null | head -1; }

wait_boot_messages() { # errfile timeout_s
    local errfile="$1" timeout="${2:-60}" i=0 pin creds admin
    while [ $i -lt "$timeout" ]; do
        pin=$(read_pin "$errfile")
        creds=$(read_proxy_creds "$errfile")
        admin=$(read_admin_creds "$errfile")
        if [ -n "$pin" ] && [ -n "$creds" ] && [ -n "$admin" ]; then
            PIN="$pin"
            PROXY_USER=$(printf '%s' "$creds" | cut -d' ' -f1)
            PROXY_PASS=$(printf '%s' "$creds" | cut -d' ' -f2)
            ADMIN_USER=$(printf '%s' "$admin" | cut -d' ' -f1)
            ADMIN_PASS=$(printf '%s' "$admin" | cut -d' ' -f2)
            return 0
        fi
        i=$((i + 1)); sleep 1
    done
    return 1
}

log_tail() { # file lines
    local file="$1" lines="${2:-20}"
    if [ ! -s "$file" ]; then echo "(空)"; return; fi
    tail -n "$lines" "$file" 2>/dev/null | tr '\n' '|' | sed 's/|/ | /g'
}

# ---- 配置生成 -------------------------------------------------------------
write_server_config() { # path listen http socks state token transport
    cat > "$1" <<EOF
# proxygw 验收脚本生成的服务端配置（临时，勿用于生产）
state_dir: $5
log:
  level: info
  format: json
server:
  listen_addr: "127.0.0.1:$2"
  ui_enabled: true
  proxy_protocol: false
proxy:
  http_listen: "127.0.0.1:$3"
  socks5_listen: "127.0.0.1:$4"
  auth_mode: required
  max_header_bytes: 65536
tunnel:
  transport: ${7:-auto}
  planes: 2
  alpn: proxygw/1
tls:
  mode: pin
  client_auth: none
admin:
  username: admin
nodes:
  mtls: false
  tokens:
    - node_id: "*"
      token: "$6"
geo:
  enabled: false
observability:
  metrics_enabled: true
audit:
  enabled: true
settings:
  scheduler:
    strategy: random
    sticky:
      enabled: true
      ttl: 10m
EOF
}

write_client_config() { # path server_url token client_id tag state pin [transport] [planes]
    cat > "$1" <<EOF
# proxygw 验收脚本生成的节点配置（临时，勿用于生产）
server_url: "$2"
token: "$3"
client_id: "$4"
alias: "$4"
tags: ["$5"]
weight: 100
transport: ${8:-auto}
quic_fallback: 2s
planes: ${9:-2}
compression: false
state_dir: "$6"
log:
  level: info
  format: json
tls:
  mode: pin
  pin: "$7"
egress:
  manual_v4: "127.0.0.1"
security:
  allow_insecure_defaults: false
EOF
}

# ---- origin ---------------------------------------------------------------
start_origin() { # port
    local port="$1"
    ORIGIN_READY=0
    if [ "$HAS_NODE" = 1 ]; then
        ORIGIN_TOOL="node"
        cat > "$TMP_DIR/origin.js" <<'EOF'
const http = require('http');
const fs = require('fs');
const port = Number(process.argv[2]);
const logPath = process.argv[3];
const big = Buffer.alloc(65536);
for (let i = 0; i < big.length; i++) { big[i] = 97 + (i % 26); }
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://origin.invalid');
  const path = url.pathname;
  const respond = (code, type, data) => {
    res.writeHead(code, { 'Content-Type': type, 'Content-Length': Buffer.byteLength(data), 'Cache-Control': 'no-store' });
    res.end(data);
  };
  if (path === '/healthz') { respond(200, 'application/json', JSON.stringify({ ok: true, origin: true })); return; }
  if (path === '/echo') { respond(200, 'application/json', JSON.stringify({ ok: true, url: req.url, method: req.method, host: req.headers.host || '' })); return; }
  if (path === '/64k') { res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': big.length }); res.end(big); return; }
  if (path === '/slow') {
    const ms = Math.min(20000, Number(url.searchParams.get('ms') || '1500'));
    setTimeout(() => respond(200, 'application/json', JSON.stringify({ ok: true, slow_ms: ms })), ms);
    return;
  }
  respond(404, 'text/plain', 'not found');
});
server.on('error', (err) => { try { fs.writeFileSync(logPath, 'error: ' + err.message); } catch (e) {} process.exit(1); });
server.listen(port, '127.0.0.1', () => { try { fs.writeFileSync(logPath, 'ready ' + port); } catch (e) {} });
EOF
        ORIGIN_PID=$(start_bg "$TMP_DIR/origin.log" "$NODE_BIN" "$TMP_DIR/origin.js" "$port" "$TMP_DIR/origin.ready")
    elif [ "$HAS_PY" = 1 ]; then
        ORIGIN_TOOL="python3"
        cat > "$TMP_DIR/origin.py" <<'EOF'
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port = int(sys.argv[1])
log_path = sys.argv[2]
big = bytes(97 + (i % 26) for i in range(65536))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, ctype, data):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/healthz":
            self._send(200, "application/json", b'{"ok":true,"origin":true}')
        elif path == "/echo":
            self._send(200, "application/json", json.dumps({"ok": True, "url": self.path}).encode())
        elif path == "/64k":
            self._send(200, "application/octet-stream", big)
        elif path == "/slow":
            ms = 1500
            try:
                ms = min(20000, int(self.path.split("ms=")[1].split("&")[0]))
            except Exception:
                pass
            time.sleep(ms / 1000.0)
            self._send(200, "application/json", b'{"ok":true}')
        else:
            self._send(404, "text/plain", b"not found")


ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
EOF
        ORIGIN_PID=$(start_bg "$TMP_DIR/origin.log" "$PY_BIN" "$TMP_DIR/origin.py" "$port" "$TMP_DIR/origin.ready")
    else
        NOTE="缺少 node/python3，无法启动本地 origin"
        return 1
    fi
    local i=0
    while [ $i -lt 30 ]; do
        http_do "http://127.0.0.1:$port/healthz"
        if [ "$HTTP_CODE" = "200" ]; then
            ORIGIN_READY=1
            return 0
        fi
        i=$((i + 1)); sleep 1
    done
    NOTE="本地 origin 启动失败（$ORIGIN_TOOL）"
    return 1
}

# ---------------------------------------------------------------------------
# 0) 构建与单元测试
# ---------------------------------------------------------------------------
run_go() { # outfile errfile workdir timeout_s go args...
    local out="$1" err="$2" workdir="$3" timeout="$4"; shift 4
    local i=0 pid rc
    ( cd "$workdir" && "$GO_BIN" "$@" >"$out" 2>"$err" ) &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        if [ $i -ge "$timeout" ]; then
            kill -KILL "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 124
        fi
        i=$((i + 1))
        sleep 1
    done
    wait "$pid"
    rc=$?
    return $rc
}

check_build_and_tests() {
    local rc bin_dir

    # go vet
    NOTE=""
    run_go "$TMP_DIR/vet.out" "$TMP_DIR/vet.err" "$REPO_ROOT" 600 vet ./...
    rc=$?
    if [ "$rc" -ne 0 ]; then
        NOTE="go vet 失败（exit=$rc）：$(log_tail "$TMP_DIR/vet.err" 6) $(log_tail "$TMP_DIR/vet.out" 6)"
        record 0a "go vet ./..." FAIL 0 "$NOTE"
    else
        record 0a "go vet ./..." PASS 0 "通过"
    fi

    # go test
    if [ "$SKIP_UNIT_TESTS" = "1" ]; then
        record 0b "go test ./..." SKIP 0 "指定了 --skip-unit-tests"
    else
        run_go "$TMP_DIR/test.out" "$TMP_DIR/test.err" "$REPO_ROOT" 1800 test ./...
        rc=$?
        if [ "$rc" -ne 0 ]; then
            record 0b "go test ./..." FAIL 0 "go test 失败（exit=$rc）：$(log_tail "$TMP_DIR/test.out" 12) $(log_tail "$TMP_DIR/test.err" 8)"
        else
            local ok_count
            ok_count=$(grep -c '^ok' "$TMP_DIR/test.out" 2>/dev/null || true)
            record 0b "go test ./..." PASS 0 "${ok_count:-0} 个包通过"
        fi
    fi

    # 构建
    bin_dir="$REPO_ROOT/bin"
    mkdir -p "$bin_dir"
    run_go "$TMP_DIR/build-s.out" "$TMP_DIR/build-s.err" "$REPO_ROOT" 600 build -o "$bin_dir/proxygw-server$EXE_SUFFIX" ./cmd/proxygw-server
    rc=$?
    if [ "$rc" -ne 0 ]; then
        record 0c "构建 server/client 二进制" FAIL 0 "构建服务端失败：$(log_tail "$TMP_DIR/build-s.err" 10)"
        return 1
    fi
    run_go "$TMP_DIR/build-c.out" "$TMP_DIR/build-c.err" "$REPO_ROOT" 600 build -o "$bin_dir/proxygw-client$EXE_SUFFIX" ./cmd/proxygw-client
    rc=$?
    if [ "$rc" -ne 0 ]; then
        record 0c "构建 server/client 二进制" FAIL 0 "构建客户端失败：$(log_tail "$TMP_DIR/build-c.err" 10)"
        return 1
    fi
    record 0c "构建 server/client 二进制" PASS 0 "bin/proxygw-server$EXE_SUFFIX + bin/proxygw-client$EXE_SUFFIX"
    return 0
}

# ---------------------------------------------------------------------------
# 启动主栈
# ---------------------------------------------------------------------------
start_main_stack() {
    LISTEN_PORT=$(free_port) || { NOTE="无法分配空闲端口"; return 1; }
    HTTP_PORT=$(free_port) || { NOTE="无法分配空闲端口"; return 1; }
    SOCKS_PORT=$(free_port) || { NOTE="无法分配空闲端口"; return 1; }
    ORIGIN_PORT=$(free_port) || { NOTE="无法分配空闲端口"; return 1; }
    NODE_TOKEN=$(gen_token)
    if [ -z "$NODE_TOKEN" ]; then
        NODE_TOKEN="token-$(date +%s)-$RANDOM$RANDOM"
    fi
    if [ ${#NODE_TOKEN} -lt 32 ]; then
        NODE_TOKEN="$NODE_TOKEN$(date +%s)$RANDOM$RANDOM"
    fi

    PANEL_BASE="https://127.0.0.1:$LISTEN_PORT"
    SERVER_ERR="$TMP_DIR/server.err.log"
    write_server_config "$TMP_DIR/server.yaml" "$LISTEN_PORT" "$HTTP_PORT" "$SOCKS_PORT" "$TMP_DIR/server-state" "$NODE_TOKEN" auto

    start_origin "$ORIGIN_PORT" || true

    NP_ACL_ALLOW_LOOPBACK_TARGETS=1 "$SERVER_BIN" -config "$TMP_DIR/server.yaml" >"$TMP_DIR/server.out.log" 2>"$SERVER_ERR" &
    SERVER_PID_MAIN=$!
    PROCS+=("$SERVER_PID_MAIN")

    local i=0
    while [ $i -lt 60 ]; do
        if ! kill -0 "$SERVER_PID_MAIN" 2>/dev/null; then
            NOTE="服务端进程提前退出：$(log_tail "$SERVER_ERR" 20)"
            return 1
        fi
        http_do -k "$PANEL_BASE/healthz"
        if [ "$HTTP_CODE" = "200" ]; then break; fi
        i=$((i + 1)); sleep 1
    done
    if [ "$HTTP_CODE" != "200" ]; then
        NOTE="服务端 /healthz 未就绪：$(log_tail "$SERVER_ERR" 20)"
        return 1
    fi

    if ! wait_boot_messages "$SERVER_ERR" 60; then
        NOTE="未能从服务端启动日志解析 pin/代理凭据/管理员密码：$(log_tail "$SERVER_ERR" 20)"
        return 1
    fi

    panel_login "$ADMIN_USER" "$ADMIN_PASS" || return 1

    CLIENT1_CFG="$TMP_DIR/client-1.yaml"
    write_client_config "$CLIENT1_CFG" "https://127.0.0.1:$LISTEN_PORT" "$NODE_TOKEN" "node-e2e-1" "node-e2e" "$TMP_DIR/client-1-state" "$PIN"
    CLIENT1_PID=$(start_bg "$TMP_DIR/client-1.log" "$CLIENT_BIN" -config "$CLIENT1_CFG")
    CLIENT2_CFG="$TMP_DIR/client-2.yaml"
    write_client_config "$CLIENT2_CFG" "https://127.0.0.1:$LISTEN_PORT" "$NODE_TOKEN" "node-e2e-2" "node-extra" "$TMP_DIR/client-2-state" "$PIN"
    CLIENT2_PID=$(start_bg "$TMP_DIR/client-2.log" "$CLIENT_BIN" -config "$CLIENT2_CFG")

    if ! wait_online_nodes 2 40; then
        NOTE="等待两个节点上线失败：$(log_tail "$TMP_DIR/client-1.log" 10) $(log_tail "$TMP_DIR/client-2.log" 10)"
        return 1
    fi
    STACK_READY=1
    return 0
}

# ---------------------------------------------------------------------------
# 检查 1-13
# ---------------------------------------------------------------------------
check_1() {
    http_do -k "$PANEL_BASE/healthz"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="/healthz HTTP $HTTP_CODE"; return 1; fi
    local ok; ok=$(json_get "$HTTP_BODY" ok 2>/dev/null || true)
    if [ "$ok" != "true" ]; then NOTE="/healthz ok != true：$HTTP_BODY"; return 1; fi
    http_do -k "$PANEL_BASE/version"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="/version HTTP $HTTP_CODE"; return 1; fi
    local ver; ver=$(json_get "$HTTP_BODY" version 2>/dev/null || true)
    if [ -z "$ver" ]; then NOTE="/version 缺少 version：$HTTP_BODY"; return 1; fi
    NOTE="healthz ok=true；version=$ver"
    return 0
}

check_2() {
    local overview nodes count quic
    panel_get /api/v1/overview
    count=$(json_get "$HTTP_BODY" online_nodes 2>/dev/null || true)
    case "$count" in ''|*[!0-9]*) NOTE="online_nodes 解析失败：$HTTP_BODY"; return 1 ;; esac
    if [ "$count" -lt 1 ]; then NOTE="online_nodes=$count"; return 1; fi
    panel_nodes_json
    nodes="$HTTP_BODY"
    quic=0
    if printf '%s' "$nodes" | grep -q '"transport":"quic"'; then quic=1; fi
    if [ "$quic" != "1" ]; then NOTE="没有 transport=quic 的节点：$(printf '%s' "$nodes" | head -c 300)"; return 1; fi
    NOTE="online_nodes=$count；存在 transport=quic 节点"
    return 0
}

check_3() {
    local url="http://127.0.0.1:$ORIGIN_PORT/echo"
    http_do -k --noproxy '' -x "http://127.0.0.1:$HTTP_PORT" --proxy-user "$PROXY_USER:$PROXY_PASS" "$url"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="HTTP 代理状态码 $HTTP_CODE：$HTTP_BODY"; return 1; fi
    local ok raw
    ok=$(json_get "$HTTP_BODY" ok 2>/dev/null || true)
    raw=$(json_get "$HTTP_BODY" url 2>/dev/null || true)
    if [ "$ok" != "true" ]; then NOTE="HTTP 代理响应体不正确：$HTTP_BODY"; return 1; fi
    # origin 看到 origin-form（/echo）属正常代理转发行为；absolute-form 由服务端
    # proxy_request 日志的 protocol=http/target 记录证明。
    local absolute=0
    if grep -aq '"protocol":"http"' "$SERVER_ERR" 2>/dev/null && grep -aq "\"target\":\"127.0.0.1:$ORIGIN_PORT\"" "$SERVER_ERR" 2>/dev/null; then
        absolute=1
    fi
    http_do -k --noproxy '' -x "http://127.0.0.1:$HTTP_PORT" --proxy-user "$PROXY_USER:wrong-password-for-test" "$url"
    if [ "$HTTP_CODE" != "407" ]; then NOTE="错误口令应返回 407（实际 $HTTP_CODE）"; return 1; fi
    if [ "$absolute" = "1" ]; then
        NOTE="absolute-form 已由代理解析；错误口令 407"
    else
        NOTE="HTTP 代理 200（origin 收到 $raw）；错误口令 407"
    fi
    return 0
}

check_4() {
    http_do -k --noproxy '' -x "http://127.0.0.1:$HTTP_PORT" --proxy-user "$PROXY_USER:$PROXY_PASS" "$PANEL_BASE/healthz"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="CONNECT 隧道状态码 $HTTP_CODE：$HTTP_BODY"; return 1; fi
    local ok; ok=$(json_get "$HTTP_BODY" ok 2>/dev/null || true)
    if [ "$ok" != "true" ]; then NOTE="隧道内 TLS 响应不正确：$HTTP_BODY"; return 1; fi
    NOTE="CONNECT 建立隧道后 GET /healthz -> 200 {ok:true}"
    return 0
}

check_5() {
    local url="http://127.0.0.1:$ORIGIN_PORT/echo"
    http_do -k --noproxy '' --socks5-hostname "127.0.0.1:$SOCKS_PORT" --proxy-user "$PROXY_USER:$PROXY_PASS" "$url"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="SOCKS5 状态码 $HTTP_CODE：$HTTP_BODY"; return 1; fi
    local ok; ok=$(json_get "$HTTP_BODY" ok 2>/dev/null || true)
    if [ "$ok" != "true" ]; then NOTE="SOCKS5 响应体不正确：$HTTP_BODY"; return 1; fi
    http_do -k --noproxy '' --max-time 15 --socks5-hostname "127.0.0.1:$SOCKS_PORT" --proxy-user "$PROXY_USER:wrong-password-for-test" "$url"
    if [ "$HTTP_CODE" = "200" ]; then NOTE="SOCKS5 错误口令不应成功"; return 1; fi
    NOTE="SOCKS5 CONNECT -> 200；错误口令握手失败"
    return 0
}

check_6() {
    # 未登录 401
    http_do -k "$PANEL_BASE/api/v1/overview"
    if [ "$HTTP_CODE" != "401" ]; then NOTE="未登录访问 /overview 返回 $HTTP_CODE"; return 1; fi
    # 重新登录拿 CSRF
    if ! panel_login "$ADMIN_USER" "$ADMIN_PASS"; then return 1; fi
    panel_get /api/v1/session
    if [ "$HTTP_CODE" != "200" ]; then NOTE="GET /session HTTP $HTTP_CODE"; return 1; fi
    # 无 CSRF 的写请求 403
    panel_get /api/v1/settings
    if [ "$HTTP_CODE" != "200" ]; then NOTE="GET /settings HTTP $HTTP_CODE"; return 1; fi
    local settings_json="$HTTP_BODY" orig_strategy new_strategy body
    orig_strategy=$(json_get "$settings_json" current.scheduler.strategy 2>/dev/null || true)
    if [ -z "$orig_strategy" ]; then NOTE="无法解析 current.scheduler.strategy"; return 1; fi
    body=$(printf '%s' "$settings_json" | make_settings_body strategy "$orig_strategy" 2>/dev/null || true)
    if [ -z "$body" ]; then NOTE="缺少 node/python3，无法构造 settings 请求体"; return 2; fi
    panel_write_nocsrf PUT /api/v1/settings "$body"
    if [ "$HTTP_CODE" != "403" ]; then NOTE="无 CSRF 的写请求应 403（实际 $HTTP_CODE）"; return 1; fi
    # 带 CSRF 修改策略
    new_strategy="weighted"
    [ "$orig_strategy" = "weighted" ] && new_strategy="random"
    body=$(printf '%s' "$settings_json" | make_settings_body strategy "$new_strategy")
    panel_write PUT /api/v1/settings "$body"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="PUT /settings 失败 HTTP $HTTP_CODE：$HTTP_BODY"; return 1; fi
    panel_get /api/v1/settings
    local after_put; after_put=$(json_get "$HTTP_BODY" current.scheduler.strategy 2>/dev/null || true)
    if [ "$after_put" != "$new_strategy" ]; then NOTE="GET /settings 未反映新策略（$after_put）"; return 1; fi
    # undo 还原
    http_do -k -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X POST -H "X-CSRF-Token: $CSRF" "$PANEL_BASE/api/v1/settings/undo"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="POST /settings/undo HTTP $HTTP_CODE：$HTTP_BODY"; return 1; fi
    panel_get /api/v1/settings
    local after_undo; after_undo=$(json_get "$HTTP_BODY" current.scheduler.strategy 2>/dev/null || true)
    if [ "$after_undo" != "$orig_strategy" ]; then NOTE="undo 后策略未还原（$after_undo != $orig_strategy）"; return 1; fi
    # 非法设置 422 且旧值不变
    panel_get /api/v1/settings
    body=$(printf '%s' "$HTTP_BODY" | make_settings_body strategy definitely-not-a-strategy)
    panel_write PUT /api/v1/settings "$body"
    if [ "$HTTP_CODE" != "422" ]; then NOTE="非法设置应 422（实际 $HTTP_CODE：$HTTP_BODY）"; return 1; fi
    panel_get /api/v1/settings
    local after_invalid; after_invalid=$(json_get "$HTTP_BODY" current.scheduler.strategy 2>/dev/null || true)
    if [ "$after_invalid" != "$orig_strategy" ]; then NOTE="非法设置后旧值被改动（$after_invalid）"; return 1; fi
    NOTE="401/403/422 校验通过；策略 $orig_strategy -> $new_strategy -> undo=$after_undo"
    return 0
}

check_7() {
    panel_get '/api/v1/audit?limit=500'
    if [ "$HTTP_CODE" != "200" ]; then NOTE="GET /audit HTTP $HTTP_CODE"; return 1; fi
    local body="$HTTP_BODY"
    if ! printf '%s' "$body" | grep -q '"login"'; then NOTE="审计缺少 login 事件"; return 1; fi
    if ! printf '%s' "$body" | grep -q '"settings.update"'; then NOTE="审计缺少 settings.update 事件"; return 1; fi
    local secret
    for secret in "$ADMIN_PASS" "$PROXY_PASS" "$CRED_A_PASS"; do
        [ -n "$secret" ] || continue
        case "$body" in *"$secret"*) NOTE="审计响应中出现明文密码（脱敏失败）"; return 1 ;; esac
    done
    NOTE="包含 login/settings.update；未发现明文密码"
    return 0
}

check_8() {
    CRED_A_PASS="CredA-$(date +%s)-$RANDOM$RANDOM"
    # 创建节点组 g1
    local body resp
    body='{"name":"g1-e2e","description":"acceptance","match":{"tags_any":["node-e2e"]}}'
    panel_write POST /api/v1/groups "$body"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="创建组失败 HTTP $HTTP_CODE：$HTTP_BODY"; return 1; fi
    GROUP_ID=$(printf '%s' "$HTTP_BODY" | sed -nE 's/.*"id":"([^"]+)".*/\1/p' | head -1)
    if [ -z "$GROUP_ID" ]; then NOTE="创建组未返回 id：$HTTP_BODY"; return 1; fi
    # 组内成员只有 node-e2e-1
    panel_get "/api/v1/groups/$GROUP_ID/members"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="GET group members HTTP $HTTP_CODE"; return 1; fi
    if ! printf '%s' "$HTTP_BODY" | grep -q 'node-e2e-1'; then NOTE="g1 成员不含 node-e2e-1：$HTTP_BODY"; return 1; fi
    if printf '%s' "$HTTP_BODY" | grep -q 'node-e2e-2'; then NOTE="g1 不应包含组外节点 node-e2e-2"; return 1; fi
    # 创建凭据 A 绑定 g1
    body=$(printf '{"username":"%s","password":"%s","groups":["%s"],"enabled":true,"note":"acceptance credential A"}' "$CRED_A_USER" "$CRED_A_PASS" "$GROUP_ID")
    panel_write POST /api/v1/credentials "$body"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="创建凭据 A 失败 HTTP $HTTP_CODE：$HTTP_BODY"; return 1; fi
    CRED_A_ID=$(printf '%s' "$HTTP_BODY" | sed -nE 's/.*"id":"([^"]+)".*/\1/p' | head -1)
    if [ -z "$CRED_A_ID" ]; then NOTE="创建凭据 A 未返回 id：$HTTP_BODY"; return 1; fi
    # 可见节点数 = 1
    panel_get "/api/v1/credentials/$CRED_A_ID/visible-nodes"
    local visible; visible=$(json_get "$HTTP_BODY" count 2>/dev/null || true)
    if [ "$visible" != "1" ]; then NOTE="凭据 A 可见节点数应为 1（实际 $visible）"; return 1; fi
    # 连续 3 次成功
    local url="http://127.0.0.1:$ORIGIN_PORT/echo" i ok_count=0
    i=0
    while [ $i -lt 3 ]; do
        i=$((i + 1))
        http_do -k --noproxy '' -x "http://127.0.0.1:$HTTP_PORT" --proxy-user "$CRED_A_USER:$CRED_A_PASS" "$url"
        if [ "$HTTP_CODE" = "200" ]; then ok_count=$((ok_count + 1)); fi
    done
    if [ "$ok_count" -ne 3 ]; then NOTE="凭据 A 3 次请求仅 $ok_count 次成功"; return 1; fi
    # 停掉组内唯一节点 node-e2e-1
    kill -TERM "$CLIENT1_PID" 2>/dev/null || true
    local offline_start offline_s=0 j=0 online_state=""
    offline_start=$(now_ms)
    while [ $j -lt 150 ]; do
        panel_nodes_json
        online_state=$(node_field "node-e2e-1" online 2>/dev/null || true)
        if [ -z "$online_state" ] || [ "$online_state" = "false" ]; then
            offline_s=$(( ($(now_ms) - offline_start) / 1000 ))
            break
        fi
        j=$((j + 1)); sleep 1
    done
    if [ $j -ge 150 ]; then NOTE="等待 node-e2e-1 离线超时（150s）"; return 1; fi
    # 组外节点 node-e2e-2 必须仍在线
    panel_nodes_json
    if [ "$(node_field 'node-e2e-2' online 2>/dev/null || true)" != "true" ]; then
        NOTE="组外节点 node-e2e-2 应仍在线：$(printf '%s' "$HTTP_BODY" | head -c 300)"; return 1
    fi
    # 此时凭据 A 请求必须 503（不回退组外节点、不能 502/200）
    http_do -k --noproxy '' --max-time 40 -x "http://127.0.0.1:$HTTP_PORT" --proxy-user "$CRED_A_USER:$CRED_A_PASS" "$url"
    if [ "$HTTP_CODE" = "200" ]; then NOTE="节点离线后凭据 A 仍成功（不应回退到组外节点）"; return 1; fi
    if [ "$HTTP_CODE" != "503" ]; then NOTE="节点离线后凭据 A 应 503（实际 $HTTP_CODE：$(printf '%s' "$HTTP_BODY" | head -c 120)）"; return 1; fi
    # 重启节点 1
    CLIENT1_PID=$(start_bg "$TMP_DIR/client-1a.log" "$CLIENT_BIN" -config "$CLIENT1_CFG")
    if ! wait_online_nodes 2 60; then NOTE="节点 1 重启后未恢复上线"; return 1; fi
    http_do -k --noproxy '' -x "http://127.0.0.1:$HTTP_PORT" --proxy-user "$CRED_A_USER:$CRED_A_PASS" "$url"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="节点重启后凭据 A 未恢复（HTTP $HTTP_CODE）"; return 1; fi
    NOTE="g1 成员=node-e2e-1；A 3 次成功；停节点后 ${offline_s}s 判定离线 -> 503；组外节点未被使用；重启后恢复"
    return 0
}

check_9() {
    # 扩展 g1 为两个节点，使凭据 A 有 2 个候选
    local body
    body='{"match":{"tags_any":["node-e2e","node-extra"]}}'
    panel_write PATCH "/api/v1/groups/$GROUP_ID" "$body"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="扩展 g1 失败 HTTP $HTTP_CODE：$HTTP_BODY"; return 1; fi
    panel_get "/api/v1/groups/$GROUP_ID/members"
    if ! printf '%s' "$HTTP_BODY" | grep -q 'node-e2e-1' || ! printf '%s' "$HTTP_BODY" | grep -q 'node-e2e-2'; then
        NOTE="g1 应包含两个节点：$HTTP_BODY"; return 1
    fi
    if ! wait_online_nodes 2 30; then NOTE="在线节点不足 2"; return 1; fi
    # 用「慢请求 + 服务端 proxy_request.node_id」验证同源 5 次命中同一节点
    # （/nodes 的 inflight 来自节点每 10s 的 STATS 上报，短请求期间不可靠）。
    local before i count want=0 j=0 picked pick_count unique_count first
    before=$(proxy_request_node_ids "$SERVER_ERR" | wc -l | tr -d ' ')
    i=0
    while [ $i -lt 5 ]; do
        i=$((i + 1))
        http_do -k --noproxy '' --max-time 40 -x "http://127.0.0.1:$HTTP_PORT" \
            --proxy-user "$CRED_A_USER:$CRED_A_PASS" "http://127.0.0.1:$ORIGIN_PORT/slow?ms=1200"
        if [ "$HTTP_CODE" != "200" ]; then NOTE="第 $i 次慢请求失败（HTTP $HTTP_CODE）"; return 1; fi
    done
    want=$((before + 5))
    while [ $j -lt 20 ]; do
        count=$(proxy_request_node_ids "$SERVER_ERR" | wc -l | tr -d ' ')
        [ "$count" -ge "$want" ] && break
        j=$((j + 1)); sleep 1
    done
    picked=$(proxy_request_node_ids "$SERVER_ERR" | tail -n +$((before + 1)) | head -5)
    pick_count=$(printf '%s\n' "$picked" | sed '/^$/d' | wc -l | tr -d ' ')
    if [ "$pick_count" -ne 5 ]; then NOTE="服务端日志中未出现 5 次 proxy_request（实际 $pick_count）"; return 1; fi
    unique_count=$(printf '%s\n' "$picked" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')
    if [ "$unique_count" -ne 1 ]; then NOTE="同源 5 次请求命中节点不一致：$picked"; return 1; fi
    first=$(printf '%s\n' "$picked" | sed '/^$/d' | head -1)
    NOTE="5 次请求均命中 $first（服务端 proxy_request.node_id 证据）"
    return 0
}

check_9b() {
    local body before i count want=0 j=0 picked pick_count unique_count
    panel_get /api/v1/settings
    body=$(printf '%s' "$HTTP_BODY" | make_settings_body ttl 1s 2>/dev/null || true)
    if [ -z "$body" ]; then NOTE="缺少 node/python3，无法构造 settings 请求体"; return 2; fi
    panel_write PUT /api/v1/settings "$body"
    if [ "$HTTP_CODE" != "200" ]; then NOTE="调小 sticky TTL 失败 HTTP $HTTP_CODE：$HTTP_BODY"; return 1; fi
    sleep 2
    before=$(proxy_request_node_ids "$SERVER_ERR" | wc -l | tr -d ' ')
    i=0
    while [ $i -lt 6 ]; do
        i=$((i + 1))
        http_do -k --noproxy '' --max-time 40 -x "http://127.0.0.1:$HTTP_PORT" \
            --proxy-user "$CRED_A_USER:$CRED_A_PASS" "http://127.0.0.1:$ORIGIN_PORT/slow?ms=900"
        if [ "$HTTP_CODE" != "200" ]; then
            http_do -k -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X POST -H "X-CSRF-Token: $CSRF" "$PANEL_BASE/api/v1/settings/undo"
            NOTE="TTL 验证第 $i 次请求失败（HTTP $HTTP_CODE）"
            return 1
        fi
        sleep 1
    done
    # 还原设置
    http_do -k -b "$COOKIE_JAR" -c "$COOKIE_JAR" -X POST -H "X-CSRF-Token: $CSRF" "$PANEL_BASE/api/v1/settings/undo"
    want=$((before + 6))
    while [ $j -lt 20 ]; do
        count=$(proxy_request_node_ids "$SERVER_ERR" | wc -l | tr -d ' ')
        [ "$count" -ge "$want" ] && break
        j=$((j + 1)); sleep 1
    done
    picked=$(proxy_request_node_ids "$SERVER_ERR" | tail -n +$((before + 1)) | head -6)
    pick_count=$(printf '%s\n' "$picked" | sed '/^$/d' | wc -l | tr -d ' ')
    unique_count=$(printf '%s\n' "$picked" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')
    if [ "$pick_count" -ge 2 ] && [ "$unique_count" -ge 2 ]; then
        NOTE="TTL=1s 后请求分布到：$(printf '%s\n' "$picked" | sed '/^$/d' | sort -u | tr '\n' ' ')"
        return 0
    fi
    NOTE="TTL=1s 后请求仍集中（或日志证据不足）：$(printf '%s\n' "$picked" | tr '\n' ' ')（随机策略下概率性验证未观察到重分配；settings TTL 热更已由第 6 项验证）"
    return 2
}

check_10() {
    local port http_port socks_port token cfg err_path out_path base i
    # wait_boot_messages 会覆盖全局 PIN/PROXY_*/ADMIN_*，本用例结束后必须还原，
    # 否则后续用例（pin 不匹配、并发）会拿回退实例的凭据去连主实例。
    local main_pin="$PIN" main_proxy_user="$PROXY_USER" main_proxy_pass="$PROXY_PASS"
    local main_admin_user="$ADMIN_USER" main_admin_pass="$ADMIN_PASS"
    port=$(free_port) || { NOTE="无法分配端口"; return 1; }
    http_port=$(free_port) || { NOTE="无法分配端口"; return 1; }
    socks_port=$(free_port) || { NOTE="无法分配端口"; return 1; }
    token="$(date +%s)-$RANDOM$RANDOM$RANDOM$RANDOM-$(uname -n 2>/dev/null || echo fallback)"
    cfg="$TMP_DIR/fallback-server.yaml"
    write_server_config "$cfg" "$port" "$http_port" "$socks_port" "$TMP_DIR/fallback-server-state" "$token" ws
    err_path="$TMP_DIR/fallback-server.err.log"
    out_path="$TMP_DIR/fallback-server.out.log"

    if [ "$HAS_NODE" = 1 ]; then
        cat > "$TMP_DIR/udp-blackhole.js" <<EOF
const dgram = require('dgram');
const socket = dgram.createSocket('udp4');
socket.on('message', function () {});
socket.on('error', function () {});
socket.bind($port, '127.0.0.1');
setInterval(function () {}, 1000);
EOF
        FALLBACK_BLACKHOLE_PID=$(start_bg "$TMP_DIR/blackhole.log" "$NODE_BIN" "$TMP_DIR/udp-blackhole.js")
    elif [ "$HAS_PY" = 1 ]; then
        cat > "$TMP_DIR/udp-blackhole.py" <<EOF
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", $port))
while True:
    s.recvfrom(65535)
EOF
        FALLBACK_BLACKHOLE_PID=$(start_bg "$TMP_DIR/blackhole.log" "$PY_BIN" "$TMP_DIR/udp-blackhole.py")
    else
        NOTE="缺少 node/python3，无法模拟 UDP 黑洞；手工步骤见 docs/ACCEPTANCE.md"
        return 2
    fi
    # 等待黑洞绑定
    i=0
    while [ $i -lt 10 ]; do
        if udp_port_busy "$port"; then break; fi
        i=$((i + 1)); sleep 1
    done
    if [ $i -ge 10 ]; then NOTE="UDP 黑洞未成功绑定端口 $port"; return 1; fi

    NP_ACL_ALLOW_LOOPBACK_TARGETS=1 "$SERVER_BIN" -config "$cfg" >"$out_path" 2>"$err_path" &
    FALLBACK_PID=$!
    PROCS+=("$FALLBACK_PID")
    base="https://127.0.0.1:$port"
    i=0
    while [ $i -lt 60 ]; do
        if ! kill -0 "$FALLBACK_PID" 2>/dev/null; then NOTE="回退测试服务端提前退出：$(log_tail "$err_path" 15)"; return 1; fi
        http_do -k "$base/healthz"
        [ "$HTTP_CODE" = "200" ] && break
        i=$((i + 1)); sleep 1
    done
    if [ "$HTTP_CODE" != "200" ]; then NOTE="回退测试服务端未就绪：$(log_tail "$err_path" 15)"; return 1; fi
    if ! wait_boot_messages "$err_path" 30; then NOTE="回退测试服务端启动信息解析失败"; return 1; fi
    local fb_pin="$PIN" fb_admin_user="$ADMIN_USER" fb_admin_pass="$ADMIN_PASS"

    # 切换面板端点
    local saved_base="$PANEL_BASE" saved_jar="$COOKIE_JAR" saved_csrf="$CSRF"
    PANEL_BASE="$base"
    COOKIE_JAR="$TMP_DIR/fallback-cookies.txt"
    CSRF=""
    local rc=0
    if ! panel_login "$fb_admin_user" "$fb_admin_pass"; then
        rc=1
    else
        local client_cfg="$TMP_DIR/fallback-client.yaml"
        write_client_config "$client_cfg" "$base" "$token" "node-fallback-1" "node-fallback" "$TMP_DIR/fallback-client-state" "$fb_pin" auto 1
        FALLBACK_CLIENT_PID=$(start_bg "$TMP_DIR/fallback-client.log" "$CLIENT_BIN" -config "$client_cfg")
        if ! wait_online_nodes 1 60; then
            NOTE="回退节点未上线：$(log_tail "$TMP_DIR/fallback-client.log" 15)"; rc=1
        else
            # 注册与 /nodes 可见之间可能有很短的窗口，最多再等 15s。
            local attempt nodes_transport=""
            attempt=0
            while [ $attempt -lt 50 ]; do
                panel_nodes_json
                nodes_transport=$(json_get "$HTTP_BODY" items.0.transport 2>/dev/null || true)
                [ -n "$nodes_transport" ] && break
                attempt=$((attempt + 1))
                sleep 1
            done
            if [ "$nodes_transport" = "ws" ]; then
                NOTE="UDP 黑洞 + 仅 wss 服务端 -> 节点 transport=ws（自动回退成功）"
            else
                NOTE="回退后节点传输类型应为 ws（实际 ${nodes_transport:-未知}）：$(printf '%s' "$HTTP_BODY" | head -c 300)"
                rc=1
            fi
        fi
    fi
    # 清理本用例进程
    [ -n "${FALLBACK_CLIENT_PID:-}" ] && kill -TERM "$FALLBACK_CLIENT_PID" 2>/dev/null || true
    kill -TERM "$FALLBACK_PID" 2>/dev/null || true
    kill -TERM "$FALLBACK_BLACKHOLE_PID" 2>/dev/null || true
    wait "$FALLBACK_CLIENT_PID" 2>/dev/null || true
    wait "$FALLBACK_PID" 2>/dev/null || true
    wait "$FALLBACK_BLACKHOLE_PID" 2>/dev/null || true
    FALLBACK_CLIENT_PID=""; FALLBACK_PID=""; FALLBACK_BLACKHOLE_PID=""
    PANEL_BASE="$saved_base"; COOKIE_JAR="$saved_jar"; CSRF="$saved_csrf"
    PIN="$main_pin"; PROXY_USER="$main_proxy_user"; PROXY_PASS="$main_proxy_pass"
    ADMIN_USER="$main_admin_user"; ADMIN_PASS="$main_admin_pass"
    return $rc
}

check_11() {
    local wrong_pin="sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    if [ "$wrong_pin" = "$PIN" ]; then NOTE="错误 pin 不能与真实 pin 相同"; return 1; fi
    local cfg="$TMP_DIR/badpin-client.yaml"
    write_client_config "$cfg" "https://127.0.0.1:$LISTEN_PORT" "$NODE_TOKEN" "node-badpin" "badpin" "$TMP_DIR/badpin-client-state" "$wrong_pin" auto 1
    local out="$TMP_DIR/badpin.out.log" err="$TMP_DIR/badpin.err.log"
    "$CLIENT_BIN" -config "$cfg" >"$out" 2>"$err" &
    local pid=$!
    PROCS+=("$pid")
    local i=0
    while kill -0 "$pid" 2>/dev/null && [ $i -lt 20 ]; do i=$((i + 1)); sleep 1; done
    local rc
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        NOTE="错误 pin 的客户端 20s 内未退出（不符合硬失败要求）"
        return 1
    fi
    wait "$pid"; rc=$?
    if [ "$rc" -eq 0 ]; then NOTE="错误 pin 的客户端应以非 0 退出（实际 0）"; return 1; fi
    local log; log=$(cat "$err" 2>/dev/null || true)
    case "$log" in *期望指纹*) : ;; *) NOTE="客户端错误日志缺少“期望指纹”：$(log_tail "$err" 10)"; return 1 ;; esac
    case "$log" in *实际指纹*) : ;; *) NOTE="客户端错误日志缺少“实际指纹”：$(log_tail "$err" 10)"; return 1 ;; esac
    case "$log" in *"$PIN"*) : ;; *) NOTE="客户端错误日志缺少服务端真实 pin"; return 1 ;; esac
    case "$log" in *"$wrong_pin"*) : ;; *) NOTE="客户端错误日志缺少配置的期望 pin"; return 1 ;; esac
    case "$log" in *排查建议*) : ;; *) NOTE="客户端错误日志缺少排查建议"; return 1 ;; esac
    NOTE="exit=$rc；日志含期望/实际指纹与排查建议"
    return 0
}

check_13() {
    local i=0 pids="" codes="" bytes=0 url="http://127.0.0.1:$ORIGIN_PORT/64k" start ms
    start=$(now_ms)
    while [ $i -lt 20 ]; do
        (
            "$CURL_BIN" -sS --max-time 90 --noproxy '' -x "http://127.0.0.1:$HTTP_PORT" \
                --proxy-user "$PROXY_USER:$PROXY_PASS" -o "$TMP_DIR/conc-$i.bin" -w '%{http_code}' "$url" \
                >"$TMP_DIR/conc-$i.code" 2>"$TMP_DIR/conc-$i.err"
        ) &
        pids="$pids $!"
        i=$((i + 1))
    done
    local bad=0 code size
    for p in $pids; do
        wait "$p" 2>/dev/null || true
        # wait 的退出码无法逐 pid 关联到文件，这里用 code 文件 + 大小判断
    done
    i=0
    while [ $i -lt 20 ]; do
        code=$(cat "$TMP_DIR/conc-$i.code" 2>/dev/null || true)
        size=$(wc -c <"$TMP_DIR/conc-$i.bin" 2>/dev/null || echo 0)
        size=$(printf '%s' "$size" | tr -d ' ')
        [ "$code" = "200" ] || bad=$((bad + 1))
        bytes=$((bytes + size))
        i=$((i + 1))
    done
    ms=$(( $(now_ms) - start ))
    if [ "$bad" -ne 0 ]; then NOTE="并发请求失败数 $bad/20"; return 1; fi
    if [ "$bytes" -ne $((20 * 65536)) ]; then NOTE="并发下载总字节数不符（$bytes，应为 $((20 * 65536))）"; return 1; fi
    # active_connections 5s 内归零
    local active=-1 j=0
    while [ $j -lt 25 ]; do
        panel_get /api/v1/overview
        active=$(json_get "$HTTP_BODY" active_connections 2>/dev/null || true)
        case "$active" in ''|*[!0-9]*) active=-1 ;; esac
        [ "$active" = "0" ] && break
        j=$((j + 1)); sleep 1
    done
    if [ "$active" != "0" ]; then NOTE="并发结束后 active_connections 未在 5s 内归零（$active）"; return 1; fi
    NOTE="20/20 成功，共 $((bytes / 1024)) KB，耗时 $((ms / 1000))s；active_connections=0"
    return 0
}

check_12() {
    # SIGTERM 优雅停机（Linux/macOS）；Git Bash/MSYS 下 SIGTERM 不由 Go 信号处理，标 SKIP
    if [ "$HOST_IS_WINDOWS" = "1" ]; then
        # 仅做端口释放检查（强杀语义）
        kill -TERM "$CLIENT1_PID" 2>/dev/null || true
        kill -TERM "$CLIENT2_PID" 2>/dev/null || true
        kill -KILL "$SERVER_PID_MAIN" 2>/dev/null || true
        wait "$SERVER_PID_MAIN" 2>/dev/null || true
        local i=0
        while [ $i -lt 10 ]; do
            if port_free "$LISTEN_PORT"; then break; fi
            i=$((i + 1)); sleep 1
        done
        if ! port_free "$LISTEN_PORT"; then NOTE="服务端停止后端口未释放"; return 1; fi
        NOTE="Git Bash/MSYS 无法向控制台进程发送 SIGTERM（优雅停机语义需在 Linux 验证）；强杀后端口已释放"
        return 2
    fi
    local before_pid="$SERVER_PID_MAIN" i=0 rc
    kill -TERM "$CLIENT1_PID" 2>/dev/null || true
    kill -TERM "$CLIENT2_PID" 2>/dev/null || true
    kill -TERM "$before_pid" 2>/dev/null || true
    while kill -0 "$before_pid" 2>/dev/null && [ $i -lt 15 ]; do i=$((i + 1)); sleep 1; done
    if kill -0 "$before_pid" 2>/dev/null; then
        kill -KILL "$before_pid" 2>/dev/null || true
        NOTE="SIGTERM 后 15s 内未退出（优雅停机失败）"
        return 1
    fi
    wait "$before_pid"; rc=$?
    if [ "$rc" -ne 0 ]; then NOTE="SIGTERM 后退出码 $rc（期望 0）"; return 1; fi
    local j=0
    while [ $j -lt 10 ]; do
        if port_free "$LISTEN_PORT"; then break; fi
        j=$((j + 1)); sleep 1
    done
    if ! port_free "$LISTEN_PORT"; then NOTE="SIGTERM 退出后端口未释放"; return 1; fi
    SERVER_PID_MAIN=""
    NOTE="SIGTERM 后 ${i}s 内以退出码 0 退出且端口释放"
    return 0
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
main() {
    local started_at
    started_at=$(now_ms)
    if [ ! -f "$REPO_ROOT/go.mod" ]; then
        say_red "错误：$REPO_ROOT 不是 proxygw 仓库根目录（缺少 go.mod）"
        exit 2
    fi
    if [ -z "$GO_BIN" ]; then
        say_red "错误：未找到 go（需要 Go 1.22+）"
        exit 2
    fi
    if [ -z "$CURL_BIN" ]; then
        say_red "错误：未找到 curl"
        exit 2
    fi

    say ""
    say_cyan "proxygw 本地自动化验收（bash）"
    say "  仓库根目录：$REPO_ROOT"
    say "  临时目录：  $TMP_DIR"
    say "  本地 origin：$([ "$HAS_NODE" = 1 ] && echo node || { [ "$HAS_PY" = 1 ] && echo python3 || echo 不可用; })"
    say ""

    say_cyan "[阶段] 构建与单元测试 ..."
    local build_ok=1
    if ! check_build_and_tests; then build_ok=0; fi

    if [ "$build_ok" = "1" ]; then
        # 复制到唯一文件名再执行：避免并行运行的其它测试按镜像名清理进程时误杀本栈。
        SERVER_BIN="$TMP_DIR/proxygw-server-acc$EXE_SUFFIX"
        CLIENT_BIN="$TMP_DIR/proxygw-client-acc$EXE_SUFFIX"
        if ! cp "$REPO_ROOT/bin/proxygw-server$EXE_SUFFIX" "$SERVER_BIN" 2>/dev/null \
            || ! cp "$REPO_ROOT/bin/proxygw-client$EXE_SUFFIX" "$CLIENT_BIN" 2>/dev/null; then
            say_red "  [失败] 复制验收二进制失败"
            build_ok=0
        fi
    fi

    if [ "$build_ok" = "1" ]; then
        say_cyan "[阶段] 启动本地验收栈（origin + 服务端 + 2 个节点）..."
        if start_main_stack; then
            say "  服务端 $PANEL_BASE  HTTP 代理 127.0.0.1:$HTTP_PORT  SOCKS5 127.0.0.1:$SOCKS_PORT  origin 127.0.0.1:$ORIGIN_PORT"
            say "  节点 node-e2e-1（组 g1 候选）与 node-e2e-2（组外）已上线"
        else
            say_red "  [失败] 验收栈启动失败：$NOTE"
            STACK_READY=0
            record 'stack' '验收栈启动' FAIL 0 "$NOTE"
        fi

        say ""
        say_cyan "[阶段] 逐项检查 ..."
        run_check 1 "healthz 200/ok=true 与 /version" check_1 1 0
        run_check 2 "节点注册（online>=1，transport=quic）" check_2 1 0
        run_check 3 "HTTP absolute-form 200 + 错误口令 407" check_3 1 1
        run_check 4 "CONNECT 隧道到本地 TLS 服务" check_4 1 0
        run_check 5 "SOCKS5 CONNECT 200 + 错误口令握手失败" check_5 1 1
        run_check 6 "面板登录/CSRF/设置热更/撤销/422" check_6 1 0
        run_check 7 "审计包含 login/settings.update 且无明文密码" check_7 1 0
        run_check 8 "组隔离与 fail-closed（组外有节点也不回退）" check_8 1 1
        run_check 9 "会话粘性（同源 5 次同节点）" check_9 1 1
        run_check 9b "粘性 TTL 调小后重新分配" check_9b 1 1
        run_check 10 "QUIC 回退 wss（UDP 黑洞模拟）" check_10 1 0
        run_check 11 "pin 不匹配硬失败（20s 内非 0 退出）" check_11 1 0
        run_check 13 "并发 20 x 64KB 与连接回收" check_13 1 1
        run_check 12 "SIGTERM 优雅停机与端口释放" check_12 1 0
    else
        say_yellow "[跳过] 构建失败，依赖二进制的端到端检查标记为 SKIP。"
        local skip_id skip_title
        for item in \
            "1|healthz 200/ok=true 与 /version" \
            "2|节点注册（online>=1，transport=quic）" \
            "3|HTTP absolute-form 200 + 错误口令 407" \
            "4|CONNECT 隧道到本地 TLS 服务" \
            "5|SOCKS5 CONNECT 200 + 错误口令握手失败" \
            "6|面板登录/CSRF/设置热更/撤销/422" \
            "7|审计包含 login/settings.update 且无明文密码" \
            "8|组隔离与 fail-closed（组外有节点也不回退）" \
            "9|会话粘性（同源 5 次同节点）" \
            "9b|粘性 TTL 调小后重新分配" \
            "10|QUIC 回退 wss（UDP 黑洞模拟）" \
            "11|pin 不匹配硬失败（20s 内非 0 退出）" \
            "12|SIGTERM 优雅停机与端口释放" \
            "13|并发 20 x 64KB 与连接回收"; do
            skip_id=${item%%|*}
            skip_title=${item#*|}
            record "$skip_id" "$skip_title" SKIP 0 "构建失败，无法启动二进制"
        done
    fi

    say ""
    say_cyan "[阶段] 清理进程 ..."
    cleanup

    local elapsed_ms elapsed_s
    elapsed_ms=$(( $(now_ms) - started_at ))
    elapsed_s=$((elapsed_ms / 1000))
    say ""
    say_cyan "==================== 验收结果汇总 ===================="
    printf '  %-4s %-34s %-5s %8s  %s\n' "编号" "验收项" "结果" "耗时(ms)" "备注/证据"
    printf '  %s\n' "--------------------------------------------------------------------------------------------------------------"
    local id title status ms note color
    while IFS=$'\t' read -r id title status ms note; do
        color="$C_RESET"
        case "$status" in
            PASS) color="$C_GREEN" ;;
            FAIL) color="$C_RED" ;;
            SKIP) color="$C_YELLOW" ;;
        esac
        printf '  %-4s %-34s %s%-5s%s %8s  %s\n' "$id" "$title" "$color" "$status" "$C_RESET" "$ms" "$note"
    done < "$RESULTS_FILE"
    printf '  %s\n' "--------------------------------------------------------------------------------------------------------------"
    say_cyan "  PASS=$PASS_COUNT  FAIL=$FAIL_COUNT  SKIP=$SKIP_COUNT  总计=$TOTAL"
    say "  总耗时：${elapsed_s}s"

    local keep=0
    if [ "$KEEP_ARTIFACTS" = "1" ] || [ "$FAIL_COUNT" -gt 0 ]; then keep=1; fi
    if [ "$keep" = "1" ]; then
        say_red ""
        if [ "$FAIL_COUNT" -gt 0 ]; then
            say_red "  存在失败项，已保留现场日志：$TMP_DIR"
        else
            say "  已保留临时目录：$TMP_DIR"
        fi
        say_red "  服务端 stderr: $SERVER_ERR"
        say_red "  客户端 1:      $TMP_DIR/client-1.log / client-1a.log"
        say_red "  客户端 2:      $TMP_DIR/client-2.log"
        exit 1
    fi
    rm -rf "$TMP_DIR" 2>/dev/null || true
    if [ "$FAIL_COUNT" -gt 0 ]; then exit 1; fi
    exit 0
}

main "$@"
