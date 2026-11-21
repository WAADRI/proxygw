# proxygw — 多节点代理聚合网关

把没有公网 IP、分散在不同网络、不同运营商的机器，变成一个**统一管理、可观测、可容错**的代理出口池。

- **服务端**（单二进制）：对外提供统一的 HTTP / HTTPS(CONNECT) / SOCKS5 代理入口、wss/QUIC 隧道服务、Web 管理面板与 Prometheus 指标。
- **节点客户端**（单二进制）：部署在任何能出网的机器上，主动外连服务端（无需公网 IP、无需入站端口），收到任务后从自身网络出口建立真实 TCP 连接并双向转发。

服务端只做「接入 + 鉴权 + 调度 + 转发」，真实连接一律由节点发起，因此**节点所在网络的出口 IP 就是最终出口 IP**。

```
浏览器 / 应用（携带代理账号密码）
   │  HTTP / CONNECT / SOCKS5
   ▼
服务端（公网）                              ┌─ Web 面板 /metrics /healthz（同一 TCP 端口）
 ├─ 代理入口：认证 → 凭据 → 节点组授权 → ACL → 调度
 ├─ 调度器：策略 / 会话粘性 / 粘性黑名单 / 熔断 / 限流
 ├─ 节点注册表：出口 IP、地域、ASN、负载、健康度、出口去重
 ├─ 隧道服务：QUIC(UDP) + wss(TCP) 同端口，多平面复用
 └─ 持久化：JSON/JSONL（无数据库、无 Redis）
   │  wss:// 或 QUIC（ALPN proxygw/1）长连接，多平面多路复用
   ├──────────────► 节点 A（组 us-residential，出口 1.2.3.4，2 条传输连接）
   ├──────────────► 节点 B（组 us-residential，出口 5.6.7.8）
   └──────────────► 节点 C（组 jp-datacenter，出口 9.9.9.9）
                         │ 节点本地发起 TCP 连接
                         ▼
                     目标站点
```

## 特性一览

| 领域 | 能力 |
|---|---|
| 传输层 | `Transport` 接口抽象；QUIC（默认主用）与 WebSocket 回退共享同一套流语义；同一端口 UDP/QUIC + TCP/wss；2s 回退与 1/2/4…10 分钟退避；多平面（默认 2，1–8）按哈希分流；会话/流状态机与附件超时表逐条对齐 |
| 代理入口 | HTTP absolute-form 普通转发、CONNECT、Upgrade/101 透传、keep-alive、分块传输；SOCKS5（RFC1928/1929，仅 CONNECT）；三入口共用同一条认证→授权→选点→建流→转发管线 |
| 授权 | 凭据多套、argon2id、组绑定、fail-closed（组内无节点返回 503，绝不回退全部节点）、禁用/过期即时踢会话、来源 CIDR/协议/并发/带宽限制 |
| 调度 | random / least_inflight / fastest / weighted(SWRR)；会话粘性（TTL 滑动、每节点 key 上限）；粘性黑名单（目标与节点两维度，优先级最高）；熔断 closed/open/half_open；令牌桶限流；响应首字节前透明重试一次 |
| 节点元数据 | 出口 IP 三级来源（手工 > 隧道对端 > https 回声）；出口去重与「独立出口 IP 数」；MMDB + preset/template/schema 三层归属地 provider（禁止格式嗅探）；字段级 source；SSRF 防护；provider 测试按钮；节点拨测（ping/tcping/http/dns）；DNS 专项转发 |
| 面板 | 登录（argon2id + JWT + 登录限速/锁定 + 可选 TOTP）、总览三指标、节点/组/凭据/规则 CRUD、运行设置热更+撤销、审计查询、SSE 实时推送 + 3s 轮询兜底 |
| 可观测 | Prometheus 指标（请求/失败/延迟/连接/在线/唯一出口/隧道/熔断/限流/重试）、结构化 slog、`/healthz`、`/version`（ldflags 注入）、15 分钟内存趋势、Webhook 告警 |
| 安全 | SPKI pin（多 pin + pin_next 轮换窗口）、ca 模式、自签证书自动生成、私钥权限校验、证书热重载、mTLS、per-node 令牌（常量时间比较、即时吊销）、ACL 强制默认拒绝清单、PROXY protocol v2、HttpOnly/Secure/SameSite Cookie、CSRF、CSP |
| 增强 | IPv6 双栈、zstd 压缩、trace id 贯穿、TopN 目标统计、时钟偏移检测、一键接入脚本、Docker/compose/systemd |

## 快速开始

### 1. 编译

```bash
go build -o bin/proxygw-server ./cmd/proxygw-server
go build -o bin/proxygw-client ./cmd/proxygw-client
# 版本注入（可选）
make build VERSION=v1.0.0
```

要求 Go 1.22+（无 CGO、无外部运行时依赖）。

### 2. 启动服务端

```bash
cp config.server.example.yaml config.server.yaml
# 按需修改：域名、端口、TLS 模式
./bin/proxygw-server -config config.server.yaml
# 仅校验配置：
./bin/proxygw-server -config config.server.yaml -check-config
```

首次启动（pin 模式）会自动生成 ECDSA P-256 自签证书并打印 **SPKI 指纹**、自动生成随机管理员密码与节点接入令牌（各只打印一次，哈希持久化到 `state/`）。

### 3. 启动节点

```bash
cp config.client.example.yaml config.client.yaml
# 填入 server_url / token / 服务端打印的 pin
./bin/proxygw-client -config config.client.yaml -check-config
./bin/proxygw-client -config config.client.yaml
```

也可以用一键接入脚本：`scripts/install-node.sh`（Linux）或 `scripts/install-node.ps1`（Windows）。

### 4. 使用代理

```bash
# HTTP / CONNECT（用户名密码为服务端首次启动生成的代理凭据，或面板中创建的凭据）
curl -x http://user:pass@SERVER_IP:8080 https://example.com -o /dev/null -w '%{http_code}\n'
# SOCKS5
curl --socks5-hostname user:pass@SERVER_IP:1080 https://example.com -o /dev/null -w '%{http_code}\n'
# 只走 SOCKS5 的 DNS 转发场景见「DNS 专项转发」
```

面板：`https://SERVER_IP:443/`（自签证书时浏览器提示不受信任是预期行为；推荐绑定域名 + CA 证书）。

### 5. 环境变量覆盖（示例）

服务端统一 `NP_` 前缀，按配置路径自动映射（`.`→`_` 大写）：

```bash
NP_SERVER_LISTEN_ADDR=":443" \
NP_TLS_MODE=pin \
NP_ADMIN_USERNAME=admin \
NP_SETTINGS_SCHEDULER_STRATEGY=weighted \
NP_LOG_LEVEL=debug \
./bin/proxygw-server -config config.server.yaml
```

客户端常用直观变量：`SERVER_URL`、`AUTH_TOKEN`、`CLIENT_ID`、`TAGS`、`ALIAS`、`REGION`、`WEIGHT`、`TRANSPORT`、`QUIC_FALLBACK`、`PLANES`、`STATE_DIR`、`TLS_MODE`、`TLS_PIN`、`TLS_PINS`、`TLS_CA_FILE`、`TLS_SERVER_NAME`、`TRUST_ON_FIRST_USE`、`EGRESS_IP`、`EGRESS_IP6`、`LOG_LEVEL`、`LOG_FORMAT`、`COMPRESSION`、`ALLOW_INSECURE_DEFAULTS`。

## 配置说明

完整字段与中文注释见 [`config.server.example.yaml`](config.server.example.yaml) 与 [`config.client.example.yaml`](config.client.example.yaml)。核心字段：

### 服务端

| 字段 | 默认 | 说明 |
|---|---|---|
| `state_dir` | `./state` | 证书、凭据、组、规则、审计、运行覆盖等持久化目录 |
| `server.listen_addr` | `:443` | TCP：面板 HTTPS + wss；UDP：QUIC（同端口） |
| `server.public_url` | 空 | 面板生成安装命令用外部地址 |
| `server.proxy_protocol` | false | 接受 PROXY protocol v2（CDN/LB 之后时启用） |
| `proxy.http_listen` / `proxy.socks5_listen` | `:8080` / `:1080` | 入口监听；置空关闭 |
| `proxy.auth_mode` | `required` | `none`（仅回环）/`optional`/`required` |
| `tunnel.transport` | `auto` | 服务端接受的传输 |
| `tls.mode` | `pin` | `pin`/`ca`/`insecure` |
| `tls.client_auth` | `none` | `require` 开启 mTLS（需 `tls.ca_file`） |
| `nodes.mtls` / `nodes.tokens` | false / 空 | 节点接入鉴权；空令牌时首启自动生成共享令牌 |
| `admin.password_hash` | 空 | 空 = 首启生成随机管理员密码并打印一次 |
| `admin.totp_secret` | 空 | 可选 TOTP 二次验证（base32） |
| `settings.*` | 见示例 | 运行设置默认值，面板修改后写入 `runtime-overrides.json` 覆盖 |
| `geo.*` | 见示例 | 出口 IP 回声、MMDB、provider、隐私开关、缓存/限流 |
| `observability.webhook_url` | 空 | 告警 Webhook（节点离线/错误率/证书或 GeoIP 临近过期） |

### 客户端

| 字段 | 默认 | 说明 |
|---|---|---|
| `server_url` | 必填 | `https://host[:port]` 或 `wss://host[:port][/path]` |
| `token` | 必填* | 节点接入令牌（mTLS 客户端证书时可为空） |
| `client_id` | 空 | 空 = 首启生成并持久化 |
| `tags` / `region` / `isp_label` / `weight` | 空/100 | 标签、手工地区/ISP 标签（优先于自动识别）、调度权重 |
| `transport` | `auto` | `auto`/`quic`/`ws` |
| `quic_fallback` | `2s` | QUIC 握手回退阈值（1–5s） |
| `planes` | `2` | 传输连接条数（1–8） |
| `tls.mode` / `tls.pin` / `tls.pins` / `tls.ca_file` | pin / 空 / 空 / 空 | 服务端身份校验；`pins` 支持新旧两枚用于轮换 |
| `tls.trust_on_first_use` | false | 首次连接记录指纹（显式开启、打印告警） |
| `egress.manual_v4/v6` | 空 | 手工出口 IP（覆盖自动探测） |

> 客户端**不开放**心跳、握手、并发、退避等行为参数；配置中出现这些键会被显式忽略并在 stderr 告警，避免节点行为漂移破坏隧道状态机语义。

## 隧道协议

### WebSocket 帧

`type(1) | stream_id(4 BE) | length(4 BE) | payload(≤64 KiB)`

| type | 名称 | 说明 |
|---|---|---|
| 0x01 | OPEN | 服务端→节点，payload = OPEN 头 |
| 0x02 / 0x03 | OPEN_OK / OPEN_ERR | 节点→服务端，建流结果（payload 含 code+消息） |
| 0x04 | DATA | 流数据 |
| 0x05 | FIN | 半关闭本端写方向（不是关闭） |
| 0x06 | WINDOW | 流控增量；stream_id=0 为连接级窗口 |
| 0x07 / 0x08 | PING / PONG | 连接级保活（15s / 连续 3 次缺失判失联） |
| 0x09 | STATS | 节点每 10s 上报（并发、字节、延迟、出口 IP、传输类型、版本） |
| 0x0A | RST | 异常复位（非 EOF） |
| 0x10 / 0x11 | HELLO / HELLO_ACK | 注册与准入结果（epoch/settings/pin_next） |
| 0x12 | KICK | shutdown/replaced/revoked/disabled |
| 0x13 | STATS_REQ | 立即上报统计 |
| 0x14 / 0x15 | PROBE / PROBE_RESULT | 节点拨测与 DNS 转发 |

### OPEN 头（两路径一致）

`ver(1) | proto(1) | addr_type(1) | addr(v) | port(2) | trace_id(16) | flags(1)`

### QUIC 路径

- TLS 1.3 + 自定义 ALPN `proxygw/1`；每条被代理连接对应一条**原生双向流**（流控、丢包恢复、拥塞控制交给 QUIC）。
- 建流结果：节点在**同一条流的反向首字节**写状态码（`code(1) | msg_len(2) | msg`）。
- 控制流：首条 client-initiated 双向流承载 HELLO/HEARTBEAT/STATS/PROBE。
- 0-RTT 仅控制流；数据流等待握手确认后建立；开启 datagram 扩展预留 UDP 能力（本版不承载业务流量）；可选 qlog、拥塞控制可配（cubic/bbr 默认 cubic）。
- 多平面：每节点 N 条 QUIC 连接，服务端按 trace id 哈希选平面。

### 关键超时（附件为准）

| 名称 | 默认 | 可配 |
|---|---|---|
| QUIC 回退阈值 | 2s | 是（客户端 1–5s） |
| 传输握手 | 10s | 否 |
| HELLO 认证 | 5s | 否 |
| 心跳间隔 / 判失联 | 15s / 3 次（45s） | 否 |
| 建流（OPEN→ACK） | 10s | 是 |
| 入口读头 | 10s | 是 |
| 空闲 | 30min | 是 |
| 写阻塞 | 30s | 是 |
| 窗口停滞 | 30s | 是 |
| 半关闭 linger | 30s | 是 |
| 排空（draining） | 10s | 是 |
| 流表清理 | 5s | 否 |

### 错误码映射（附件第 7 章）

| 内部错误 | OPEN_ERR | HTTP | SOCKS5 |
|---|---|---|---|
| DNS 解析失败 | 1 | 502 | 0x04 host unreachable |
| 连接被拒 | 2 | 502 | 0x05 connection refused |
| 连接超时 | 3 | 504 | 0x06 TTL expired |
| 策略拒绝 | 4 | 403 | 0x02 not allowed |
| 节点过载 | 5 | 503 | 0x01 general failure |
| 协议不支持 | 6 | 405 | 0x07 command not supported |
| 节点内部错误 | 7 | 502 | 0x01 general failure |
| 组为空 / 无候选节点（本地判定） | — | **503** | 0x04 host unreachable |
| 建流超时（服务端侧） | — | 504 | 0x06 TTL expired |

> 502 表示「上游坏了」，503 表示「当前没有可用资源」；组为空**必须**走 503，且绝不回退到全部节点。

## 证书、pin 与轮换

- 服务端只维护一个身份证书，QUIC / wss / 面板共用。首次启动自动生成：ECDSA P-256、有效期 1 年、SAN 覆盖配置的域名与 IP；私钥 0600。
- `pin` 模式校验 **SPKI（SubjectPublicKeyInfo）的 SHA-256**，格式统一为 `sha256/<base64>`（也接受 64 位十六进制输入并自动归一化）。保留密钥对重新签发证书时指纹不变，全网节点无需改动。
- 支持多枚 pin 同时生效（当前 + 下一枚）；面板展示 `pin` 与 `pin_next`，提供复制与「生成安装命令」。
- pin 不匹配**硬失败**：错误信息同时包含期望指纹、实际指纹与排查建议；不会自动降级为不校验，也不会无限重连刷日志。
- `ca` 模式支持手工证书文件 + 热重载（文件变化或 SIGHUP，新握手用新证书，已有连接不受影响）；ACME 由外部客户端（如 certbot）签发后热加载，见「非目标」。
- 轮换建议：**换证书不换密钥 = 无感**；换密钥则先在面板预生成新 pin、下发到节点、等全部节点同时接受新旧两枚 pin 后再切换。
- 私钥权限过宽（如 0644）时服务端拒绝启动（Windows 只告警，因为 POSIX 权限位不可靠）。

> **nginx/反向代理限制**：QUIC 无法穿过普通反向代理。要让 QUIC 可用，证书与 443/UDP 必须由本进程直接持有；若把服务端放在 nginx 之后，就只能走 `wss`（TCP）。不要再问「为什么永远走 WS」——这是部署形态决定的。

## 管理面板

- 登录：用户名/密码（argon2id 哈希），成功后签发 JWT（HttpOnly + Secure + SameSite Cookie）；登录失败按 IP 限速与锁定；可选 TOTP。
- 页面：总览（在线节点数 / 独立出口 IP 数 / 活跃连接数 + 趋势 sparkline）、节点、节点组、凭据、规则（路由策略/粘性/黑名单/ACL/熔断/限流/超时/压缩）、运行设置、审计、节点接入。
- 实时性：SSE 推送 + 3s 轮询兜底。
- 运行设置热生效并持久化到 `runtime-overrides.json`，重启后覆盖配置文件；非法配置被拒绝且保留旧值；支持「撤销上次修改」。
- 节点拨测：单节点 Ping（隧道 RTT）/ TCPing / HTTP GET / DNS，结果写审计。
- 审计：登录、配置变更、凭据与组变更、节点上下线、强制下线写入 `runtime-audit.jsonl`，敏感字段脱敏，支持按时间/类型/操作者过滤。

## 节点元数据

- 出口 IP 优先级：节点手工 `egress.manual_v4/v6` > 服务端看到的隧道对端地址 > 节点请求 https IP 回声端点（IPv4/IPv6 分别探测，2s 超时，失败降级）。IP 回声端点只做固定规则提取（纯文本第一个合法 IP / JSON `ip` 字段 / cloudflare trace `ip=` 行），无需配置映射。
- 「IP 回声」与「归属地查询」是两个独立配置项；归属地查询采用三层 provider，**禁止自动嗅探响应格式**：
  - `preset`：内置适配器 `ipinfo` / `ip-api` / `ipwho.is` / `cloudflare` / 本地 MMDB；
  - `template`：URL + 声明式字段映射，支持 `$.data.country` 形式的嵌套路径/数组下标，纯文本可用 `regex:country=([A-Z]{2})`；
  - `schema`：用户端点返回项目标准 JSON：`{"country":"JP","region":"Tokyo","city":"Tokyo","asn":2516,"asn_org":"KDDI","isp":"KDDI"}`。
  - 路径解析失败/字段缺失会报明确配置错误（面板可见、可测试），不静默返回空值。
- 归一化：国家 ISO 3166-1 alpha-2 大写；`AS15169` → `15169`；ISP/AS 组织保留原文；时间 RFC3339。
- 合并：本地 MMDB 为主，在线 provider 只补缺失字段，每个字段记录 `source` 与 `fetched_at`（面板可展开）。
- 缓存 24h；在线 provider 有令牌桶与并发上限；连续失败 5 次自动摘除并告警，可手动恢复；**只在节点注册或出口 IP 变化时解析一次**，绝不在请求热路径查询。
- 同一公网 IP 的多个节点标记 `duplicate_of`；面板同时展示「节点数」与「独立出口 IP 数」。
- 手工 `region` / `isp_label` 优先于自动识别；精度预期：国家准确率高，城市/ISP 有偏差，ASN 相对可靠。
- 安全：自定义 URL 仅允许 https、校验解析后目标并拒绝内网/回环/链路本地/云元数据地址、重定向 ≤2 且再次校验、响应 ≤64KB、超时 3s；默认只用本地 MMDB，启用远程 provider 需显式 `geo.remote_consent: true`（会把节点 IP 发给第三方）。
- **DNS 专项转发**：节点代为发起一次 UDP/53 查询（一问一答、2s 超时、响应 ≤4KB、可带缓存），用于「实际只需要 DNS」的 UDP 需求；通用 UDP 中继不在本版范围（SOCKS5 UDP ASSOCIATE 返回 `command not supported`）。

## 部署

### Docker

```bash
docker build -f deploy/Dockerfile.server -t proxygw-server:latest .
docker build -f deploy/Dockerfile.client -t proxygw-client:latest .

# 服务端（注意 443 UDP 也要映射）
docker run -d --name proxygw-server --restart unless-stopped \
  -p 443:443/tcp -p 443:443/udp -p 8080:8080 -p 1080:1080 \
  -v $PWD/config.server.yaml:/etc/proxygw/config.server.yaml:ro \
  -v proxygw-state:/var/lib/proxygw/state \
  proxygw-server:latest -config /etc/proxygw/config.server.yaml
```

docker-compose：`deploy/docker-compose.server.yml`、`deploy/docker-compose.client.yml`（参数全走环境变量）。

节点侧 Docker 的完整步骤（单机多节点、QUIC/wss、验证与排障）见 **[docs/DOCKER_NODE.md](docs/DOCKER_NODE.md)**，最短路径：

```bash
docker build -f deploy/Dockerfile.client \
  --build-arg GOPROXY=https://goproxy.cn,direct -t proxygw-client:1.0.4 .

docker run -d --name proxygw-node-1 --restart unless-stopped \
  -e SERVER_URL=https://node.proxy.waadri.top:443 \
  -e AUTH_TOKEN='<节点接入令牌>' \
  -e CLIENT_ID=node-docker-1 -e TAGS='docker,test' \
  -e TRANSPORT=auto -e PLANES=2 -e TLS_MODE=ca \
  -v proxygw-node-1-state:/var/lib/proxygw/state \
  proxygw-client:1.0.4
```

镜像内置「环境变量优先」的默认配置（`deploy/config.client.docker.yaml`），通常无需挂载配置文件；节点只主动外连 TCP/UDP 443，不需要映射任何入站端口。

### systemd

```bash
install -m 0755 bin/proxygw-server /usr/local/bin/
install -d /etc/proxygw /var/lib/proxygw/state
install -m 0600 config.server.yaml /etc/proxygw/
install -m 0644 deploy/systemd/proxygw-server.service /etc/systemd/system/
useradd --system --home /var/lib/proxygw --shell /usr/sbin/nologin proxygw
chown -R proxygw:proxygw /var/lib/proxygw
systemctl daemon-reload && systemctl enable --now proxygw-server
```

Windows 服务见 [`deploy/windows-service.md`](deploy/windows-service.md)。

### 节点一键接入

```bash
sudo ./scripts/install-node.sh --server https://gw.example.com:443 \
  --token <令牌> --pin sha256/<指纹> --client-id node-us-1 --tags us-residential
```

## 安全说明

- 默认 `proxy.auth_mode=required`；首次启动自动生成随机代理凭据、管理员密码、节点接入令牌，各只打印一次（哈希持久化）。
- 检测到示例令牌、空密码、默认口令时拒绝启动；本地开发需显式 `security.allow_insecure_defaults=true`（启动打印醒目告警）。
- `auth_mode=none`（开放代理）仅允许回环监听。
- 密码只存哈希；日志与指标中只出现用户名，绝不出现密码/哈希/令牌。
- ACL 强制默认拒绝清单（不可关闭、只可追加）：回环、私有网段、链路本地、云元数据地址（`169.254.169.254`）、高风险端口（25/135/139/445/6379），防 SSRF 与滥用。
- 面板：HttpOnly + Secure + SameSite Cookie、CSRF 防护、CSP、登录失败锁定；不提供节点 shell/文件浏览等远程执行能力。
- 客户端默认校验证书；`insecure` 模式需显式确认并每次打印告警。

## 可观测性

- `/metrics`（Prometheus）：请求数与失败数（协议/节点/凭据）、活跃连接、在线节点、独立出口 IP、上下行字节、隧道建立延迟直方图、熔断触发、限流触发、重试次数、会话状态/流状态/接管/重连/window stall/geo 查询等。凭据维度只对显式注册的凭据打标签，节点标签在节点数 ≥500 时自动折叠为 64 个稳定桶。
- 结构化日志（`log/slog`，JSON/text），统一字段：request_id/trace_id、credential（用户名）、node_id、group、protocol、target、duration_ms、error；禁止记录令牌与密码。
- `/healthz`（进程 + 关键组件）、`/version`（ldflags 注入 version/commit/build_time/go）。
- 告警 Webhook：节点离线、错误率突增、证书/GeoIP 库临近过期。
- 轻量趋势：内存环形缓冲保存 15 分钟吞吐与错误率，面板 sparkline，不引入 TSDB。

## 设计决策与取舍

1. **附件优先**：超时、错误码、状态机、并发不变量严格按《隧道层状态机与时序》实现；主规格与之冲突处以附件为准。组为空在 HTTP 侧必须 503（附件第 7 章注），SOCKS5 侧按主规格 C.4 回 `0x04 host unreachable`（附件表中同名「策略拒绝」用于 OPEN_ERR 策略码，本地无候选不产生 OPEN_ERR）。
2. **OPEN 头/建流结果编码**：两条路径共享同一份 OPEN 元信息与结果格式；WebSocket 用 OPEN/OPEN_OK/OPEN_ERR 帧承载，QUIC 用原生流 + 长度前缀承载（流本身由 QUIC 分帧）。结果格式统一为 `code(1)|msg_len(2)|msg`，保证两路径外部行为一致。
3. **面板、wss、QUIC 共端口**：默认 443 TCP（面板 HTTPS + wss 隧道）与 UDP 443（QUIC）；代理入口独立 8080/1080。面板路径 `/`，隧道升级路径 `/tunnel`。放在 nginx 后只能 wss（已在部署文档醒目说明）。
4. **ACME**：不内置 ACME 客户端（需要域名商 DNS API 依赖，超出允许依赖与单二进制约束）；`ca` 模式 + 证书文件热重载可对接 certbot 等外部客户端，证书到期前 30 天面板/日志告警。`insecure` 仅回环/开发并强制告警。
5. **pin 模式的 `InsecureSkipVerify`**：Go 的 `crypto/tls` 只会在 `InsecureSkipVerify=true` 时才调用 `VerifyPeerCertificate`；pin 模式必须设置它并**同时**实现强制 SPKI 比对，否则无法在无 CA 场景校验自签证书。这不是「跳过校验」，`ca` 模式禁止该标志。
6. **节点鉴权**：支持 per-node 令牌（sha256 哈希常量时间比较、面板/API 即时吊销）与 mTLS（ca 模式 + require client cert）。推荐组合使用：配置了令牌时，mTLS 连接**同时**校验令牌（证书身份+令牌双因素，避免任一受信证书冒充任意 node_id）；纯 mTLS 部署可不配令牌。首启自动生成的共享令牌为**一次性注册令牌**：首次认证后绑定到该 node_id 并持久化，其他 node_id 复用会被拒绝；显式配置 `node_id: "*"` 的静态令牌才是共享秘密模式（启动日志告警，生产不推荐）。
7. **组语义**：成员 =（选择器匹配 ∪ nodes_add）− nodes_remove；空选择器不匹配任何节点（避免「显式列表组」意外包含全网节点）；凭据未绑定任何组 = 全部节点；绑定组但组内无在线节点 = fail-closed 503。
8. **粘性黑名单**：目标维度与节点维度任一命中即生效，优先级高于粘性；面板提供「试算命中哪条规则」。
9. **0-RTT**：协议与 QUIC 配置开启 0-RTT 会话恢复，但数据流必须等握手确认；控制流允许 0-RTT。本版未实现 QUIC 0-RTT 完整回放防护之外的业务优化，README 明确标注。
10. **PROXY protocol v2**：服务端在 CDN/LB 之后时从 PROXY 头取真实源/对端地址；未启用时使用 TCP 对端地址。
11. **透明重试**：仅在向客户端提交响应首字节前重试（HTTP 状态行未写、CONNECT 未回 200、SOCKS5 未回成功），最多按 `settings.scheduler.retry.max_attempts` 换节点；已提交后绝不重试。
12. **客户端行为参数固定**：心跳/握手/退避/并发内置，配置出现即忽略并告警；`quic_fallback` 作为传输选择参数保留可配（1–5s）。
13. **测试专用豁免**：内部集成测试需要把回环地址作为代理目标，通过环境变量 `NP_ACL_ALLOW_LOOPBACK_TARGETS=1` 仅在测试中豁免 ACL 强制拒绝清单；生产默认关闭，README 明确标注。
14. **未实现/降级项**：通用 UDP 中继（非目标，SOCKS5 UDP ASSOCIATE 返回 0x07）、插件系统与 JS 热加载、多租户计费、多服务端共享节点池、面板远程执行、自更新（可选进阶项未实现，README 标注）。ACME 自动签发、qlog/DPLPMTUD 依赖 quic-go 版本能力，若构建环境 API 不支持则以注释与日志标注。
15. **quic-go v0.48.2 的能力边界**：该版本公共 API 已移除 `Config.CongestionControl`，因此 `tunnel.quic_cc: bbr` 会被接受但**实际不生效**（默认 CUBIC 由 quic-go 内部决定）；DPLPMTUD 在该版本默认启用、没有独立开关，代码未禁用它；qlog 通过 `QLogDir` 启用。若必须可选 BBR，需要升级 quic-go 并做 API 迁移，本版不为此引入回归风险。
16. **WebSocket 流 ID 与 epoch**：WS 路径流 ID = `epoch<<20 | seq`；seq 按角色奇偶分配（dialer 奇数、listener 偶数）避免双向同时开流的 ID 碰撞。transport 严格按客户端 HELLO_ACK 中下发的 epoch 过滤迟到帧；在 `SetEpoch` 之前允许任意 epoch（节点在 HELLO_ACK 前已启动 accept 循环，服务端在 ACK 前完成 `SetEpoch`，避免误丢合法首流）。
17. **WS 半关闭与 CloseRead**：WS 线上协议用 FIN 表示单向半关闭（双向 FIN 后释放）；协议没有「只停读」帧，`CloseRead` 表现为本地丢弃接收并回补窗口，RST 表示整条流异常终止，对端看到 `StreamResetError` 而非 EOF。QUIC 路径分别映射 `Close()`/`CancelRead`/`CancelWrite`。
18. **zstd 压缩协商**：压缩必须三方交集——服务端运行设置 `compression_enabled`、节点 HELLO `compression=true`、HELLO capability 含 `zstd`；服务端只在协商成立时在 OPEN 头置压缩位并在流上包装 zstd，节点仅对带压缩位的流解压/压缩。OPEN 元信息与建流结果永远不压缩；字节统计按压缩前明文计。
19. **时钟偏移**：服务端每节点采样 HELLO/STATS 时间戳的中位数偏移（local-remote，窗口 32），仅观测与面板/告警提示，**不进行任何校时**；节点重连后重建采样窗口。
20. **面板认证细节**：面板 JWT Cookie + CSRF 双提交 Cookie（`np_csrf` 与 `X-CSRF-Token` 常量时间比较，因 auth 层 JWT 不携带 csrf claim，采用等价的双提交方案）；DELETE 组时若被凭据引用返回 409；安装命令中的节点令牌始终为占位符，绝不回显真实令牌。
21. **安全加固上限**：注册节点数上限 4096（`registry`），并发隧道会话上限 4096（`tunnel`），节点自报字段全部限幅（weight 1..10000、文本 128B、tags ≤64、inflight/bytes/latency 上限）；`tunnel.max_frame_bytes` 固定 65536（节点分帧上限与协议一致，避免调小导致互操作断裂）。
22. **窗口停滞看门狗**：WS 发送侧等待 WINDOW 信用超过 `timeouts.window_stall`（默认 30s）即复位该流并累加 `tunnel_window_stalls_total{node}`；传输层看门狗在连接建立时读取设置，热改需重连/重启（文档化）。
23. **0-RTT**：QUIC 服务端与客户端均开启 0-RTT 会话恢复（`Allow0RTT`）；控制流可走 early data，数据流建流时若握手未确认会在 OPEN 超时内等待确认再继续，而不是返回 502。
24. **告警与审计**：webhook 覆盖节点离线、证书到期（<30 天每 24h）、错误率突增、geo provider 降级；隧道侧认证失败/版本不兼容/节点发起非法流/接管冷却写入同一审计库（JSONL）。
25. **pin 轮换**：面板 `POST /cert/rotate-pin` 生成下一把密钥并把新 SPKI pin 立即写入 `certs.Status.PinNext` 与 HELLO_ACK（热更新，无需重启）；节点继续用旧 pin 连接，待全部节点已知新 pin 后再切换证书。
26. **代理转发细节**：请求 framing 由代理重建（不复用客户端 `Content-Length`，避免重复头被严格 origin 拒绝）；keep-alive 复用同一上游流，请求循环在认证/ACL/候选/限流等前置失败时会释放已持有的上游流。pin 模式不校验证书有效期（密钥未变即受信，保留密钥续期便利），需要有效期校验请用 ca 模式。

## 目录结构

```
cmd/proxygw-server        服务端入口（装配、信号、优雅停机）
cmd/proxygw-client        节点入口
internal/version|logx|config|model|store|protocol|fsm|certs|transport|tunnel|nodeagent
internal/registry|nodesauth|auth|groups|rules|acl|sched|proxy|geo|probe
internal/metrics|audit|settings|panel|health|identity|app|integration
web/                      内嵌前端（embed.FS）
deploy/                   Dockerfile/compose/systemd/Windows 服务
scripts/                  一键接入、验收脚本
docs/PLAN.md              实施计划与模块契约
docs/DOCKER_NODE.md       节点侧 Docker 部署指南（多节点/排障）
docs/REMOTE_TEST_REPORT.md 远程真实服务器全功能测试报告
```

## 第三方依赖

| 模块 | 版本 | 用途 |
|---|---|---|
| github.com/quic-go/quic-go | v0.48.2 | QUIC 传输（TLS1.3 + 自定义 ALPN） |
| github.com/gorilla/websocket | v1.5.3 | wss 回退传输 |
| gopkg.in/yaml.v3 | v3.0.1 | 配置解析 |
| github.com/klauspost/compress | v1.17.11 | zstd 压缩 |
| github.com/golang-jwt/jwt/v5 | v5.2.1 | 面板 JWT |
| github.com/prometheus/client_golang | v1.20.5 | Prometheus 指标 |
| golang.org/x/crypto | v0.31.0 | argon2id / bcrypt 口令哈希 |
| github.com/oschwald/maxminddb-golang | v1.13.1 | 本地 GeoIP MMDB |

前端为原生 HTML/CSS/JS，构建时 `embed.FS` 内嵌；JSON 路径提取自研（不引额外依赖）。除配置文件外无外部运行时依赖，不依赖 Node.js、数据库、Redis。

## 验收自测结果

> 验收环境：Windows Server（Go 1.27.0，Windows amd64），另附 Linux 验收脚本 `scripts/acceptance.sh`（dash/bash，覆盖 SIGTERM 优雅停机等 Windows 不可测项）。
> 详细逐条命令与输出见 `docs/ACCEPTANCE.md`；M2 只读审查问题处理见 `docs/REVIEW_M2_FIXES.md`。

### 1. 最终门禁（代码冻结时实测）

| 命令 | 结果 |
|---|---|
| `gofmt -l .` | 无输出（全部已格式化） |
| `go build ./...` | exit 0 |
| `go vet ./...` | exit 0 |
| `go test -race -count=1 ./...` | **28/28 包 ok**，0 fail；`internal/integration` 24.9s，其余包 1.4–9.0s |

### 1b. 一键验收脚本（`scripts/acceptance.ps1` / `scripts/acceptance.sh`）

| 脚本 | 环境 | 结果 | 耗时 |
|---|---|---|---|
| `scripts/acceptance.ps1` | Windows 11 / Windows PowerShell 5.1 / Go 1.27.0 | **PASS=16 FAIL=0 SKIP=1**，退出码 0 | 131.2s（2026-11-21 修复后复跑） |
| `scripts/acceptance.sh` | Git Bash（Linux/macOS 为正式目标） | **PASS=16 FAIL=0 SKIP=1**，退出码 0 | 125s（2026-11-21 修复后复跑） |

脚本覆盖：go vet/test/构建、双二进制启动、首启 pin/凭据/面板密码解析、QUIC 注册、HTTP/CONNECT/SOCKS5 三入口与错误口令、面板登录/CSRF/设置热更与回滚/非法设置 422、审计无明文密码、组隔离 fail-closed（停节点后 503 且不越组）、粘性与 TTL、QUIC→wss 回退、pin 不匹配硬失败、并发 20×64KB 与活跃连接归零。唯一 SKIP 为 Windows 无法发送 SIGTERM/Ctrl+C（`check 12`）；Linux/macOS 由 `.sh` 用 `kill -TERM` 断言优雅停机。本机无直连外网，外网项（PS7 安装、example.com、在线 geo provider）按「无外网即跳过」处理并已标注。

### 1c. 远程真实服务器全功能测试（2026-11-21）

在真实公网服务器（Ubuntu 26.04 / 2 vCPU / Let's Encrypt 证书）上完成部署与全功能测试，详见 **[docs/REMOTE_TEST_REPORT.md](docs/REMOTE_TEST_REPORT.md)**。摘要：

- 部署：交叉编译 Linux 二进制 + systemd 单元，`443/tcp`（面板 HTTPS + wss）、`443/udp`（QUIC）、`8080`（HTTP 代理）、`1080`（SOCKS5），公共 CA 证书校验通过；
- 拓扑：`node-a`/`node-b` 双节点 QUIC 双平面 + zstd，外加一次性公网 Windows 客户端验证 wss 回退与真实大文件转发；
- 覆盖：三入口代理、认证/错误码、大文件/chunked/并发、压缩（1MiB 下载线上仅 +659B）、限速、IPv6 目标、组隔离 fail-closed、粘性、故障转移、节点 kick/禁用/拨测、面板全部页面与 API、设置热更/undo/reset、审计、指标、TopN、Geo provider、TOTP、PROXY protocol v2、mTLS、QUIC→wss 回退、SIGTERM 优雅停机排空、重启恢复——**约 91 项断言 0 FAIL**；
- 公网 QUIC（云安全组放行 UDP 443 后补测）：外部 Windows 节点 2 条 QUIC 平面 64ms 建连；经其转发 1MiB 0.41s（~20.7 Mbit/s）、10MiB 0.70s（~119 Mbit/s）、POST 1MiB 0.51s、20 并发 64KiB 2.60s，多流分布两个平面；IPv6 字面量 QUIC 接入与拨测通过；空闲 45s 心跳保持、30×1MiB 连续传输 30/30 成功且无重连；同一条件下 wss 对照为 0.54s/0.77s/0.66s/3.16s，QUIC 全面更优；
- 测试过程中发现并修复 4 个真实缺陷（KICK 帧丢失导致 60s 重连、HELLO_ACK 拒绝原因丢失导致错误令牌无限重试且无审计、`proxy_protocol` 配置未接线、overview `retries` 把失败当重试），均已补回归测试并重新部署复测通过；另有 3 项配置/文档建议（见远程报告第 5 节）。


### 2. 进程内端到端集成测试（真实 server + node agent + QUIC/WS 传输，`-race` 通过）

| 用例 | 覆盖 |
|---|---|
| `TestQUICPrimaryRegistration` | QUIC 主传输注册、双平面、epoch |
| `TestWSFallbackWhenOnlyWebSocketEnabled` | 仅 wss 时回退成功 |
| `TestQUICUDPBlackholedFallsBackToWS` | UDP 黑洞 2s 回退 wss |
| `TestPinMismatchIsFatal` | pin 不匹配硬失败（不降级） |
| `TestZstdCompressedProxy` | zstd 三方协商端到端：100KB 随机 POST 回显一致、~288KB 可压缩 POST、CONNECT+TLS、keep-alive 复用、线上字节远小于明文 |
| `TestM3E2EProxyEntries` | HTTP GET/keep-alive 复用、POST 64KB 逐字节回显、chunked 响应、CONNECT+TLS、SOCKS5 用户名密码、认证失败（407/0xFF）、无认证模式 |
| `TestM3E2EFailClosedGroupIsolation` | 组 g1 只含 node-a：10 次全经 node-a；cancel node-a 后请求**恰好 503** 且 node-b 计数为 0；节点恢复后恢复 200 |
| `TestM5E2EPanelAPI` | 未登录 401、CSRF 写保护 403、登录、节点/组 CRUD、设置热更与 undo、非法设置 422 保旧值、审计无密码明文、overview/topn/cert/sessions、安全响应头 |
| `TestM3M6E2EStickyAndFailover` | fastest+sticky 同源命中同一节点；cancel 后 failover（14ms 200）；节点离线后经另一节点恢复 |
| `TestM3M6E2EConcurrentAndGracefulShutdown` | 30 并发 64KB 全部正确；`ActiveStreams` 2s 内归零；cancel 后 Run 6.6ms 返回 nil、端口拒绝新连接 |

### 3. 真实二进制冒烟（Windows，非进程内）

- 双二进制启动：服务端首启打印代理凭据/面板管理员密码/SPKI pin；客户端 pin 连接、QUIC 注册、双平面就绪。
- 代理入口：HTTP GET、HTTP POST 60000B/300000B（含 zstd 压缩，origin 逐字节确认）、HTTP chunked 100000B、CONNECT + TLS 目标（`tls-ok`）、SOCKS5 用户名密码，全部成功。
- 面板：`POST /api/v1/login`（JWT+CSRF）、`GET /overview`（requests/errors/transport_mix/trend/clock_skew_ms/cert）、`GET /stats/topn`（targets/nodes/credentials 各计数与字节准确）、`GET /cert`（pin/pin_next/not_after）、`GET /tunnel/sessions`（node/transport/state/planes/epoch）、`GET /` 返回内嵌 SPA（26.5KB HTML）、`GET /static/app.js` 200、`GET /healthz` 全 ok。
- 热更新：`PUT /settings`（完整 Settings 包装）即时生效、版本自增、写审计；`POST /settings/undo` 还原；`POST /cert/rotate-pin` 立即更新 `/cert.pin_next` 且 HELLO_ACK 热下发。
- 安全默认：未设置测试豁免时，回环目标被 ACL 强制拒绝（403 + 审计 `proxy.acl_denied`），符合 SSRF 防护预期。
- 审计：登录、设置变更、ACL 拒绝、`proxy_request` 均有记录，无密码/令牌明文。

### 4. 已知边界与偏差（完整列表见「设计决策与取舍」15–26）

- `tunnel.quic_cc: bbr` 在 quic-go v0.48.2 下被接受但不生效（该版本无公共拥塞控制配置 API，默认 CUBIC），启动不报错、文档标注。
- ACME 未内置（ca 模式 + 证书热重载对接外部 certbot）。
- 面板与 mTLS 隧道共用 TCP 监听：启用 mTLS 时浏览器访问面板也需客户端证书（启动告警 + 部署文档说明，建议面板独立入口）。
- pin 模式按 SPKI 信任、不校验证书有效期（密钥未变即受信）；需要有效期校验用 ca 模式。
- 传输层 window stall 看门狗在连接建立时读取运行设置，热改需重连/重启生效。
- drain 预算以服务端为准（节点 KICK 后按自身默认 10s 关闭；服务端设置的 drain 不通过 HELLO_ACK 下发）。
- 通用 UDP 中继、插件系统、面板远程执行、自更新为明确非目标/进阶项。
- **硬杀节点的离线判定时延**：QUIC 节点被 `kill -9`/强杀后，服务端依赖心跳丢失（15s×3≈45s）判定会话失效并置离线，实测面板/registry 判定离线约 58–72s（含心跳调度余量）；判定离线后调度立即停止向该节点分配，组隔离 fail-closed 不受影响。判死前若有在途请求可能返回 502/504，客户端重试即可。这是附件心跳机制的固有边界，未额外缩短心跳（避免正常抖动误杀），已由验收脚本记录并纳入 `docs/ACCEPTANCE.md`。

## 故障排查

| 现象 | 排查顺序 |
|---|---|
| 节点一直离线 | 服务端 TCP+UDP 443 是否放行 → `server_url` 是否正确 → token 是否吊销 → pin 是否与服务端控制台一致 → 客户端日志 `journalctl -u proxygw-client` |
| 永远走 wss 不回 QUIC | UDP 443 被丢/被墙 → 客户端日志查看回退原因 → 10 分钟后台重探 → 面板节点传输类型；放在 nginx 后只能 wss（预期） |
| pin 不匹配硬失败 | 对比错误中的期望/实际指纹；确认服务端证书未更换密钥；轮换期间同时配置新旧两枚 pin |
| HTTP 返回 407 | 凭据缺失/错误/被禁用/过期/来源 IP 不在白名单 |
| HTTP 返回 503 | 凭据绑定组内无可用节点（fail-closed）或全局无候选；查看节点是否全部离线/熔断；**不会**回退全部节点 |
| HTTP 返回 403 | ACL 拒绝或命中强制默认拒绝清单（回环/私有网段/高风险端口） |
| 面板打不开 | 自签证书浏览器告警是预期；确认 443/tcp 放行；`curl -k https://IP/healthz` |
| 面板登录被锁 | 等待 `admin.login_lock_window` 或重启清空内存限速计数 |
| 归属地 unknown | 未配置 MMDB 且未开启远程 provider；检查 `geo.remote_consent`、provider 测试按钮的原始响应与路径 |
| 出口 IP 重复 | 面板「独立出口 IP 数」与 `duplicate_of` 标记；同一 NAT 后的多节点属正常 |
| 大文件传输失败 | 检查空闲/写超时、节点带宽限制、`window_stall` 日志；用面板拨测节点连通性 |
| 服务端启动失败 | 私钥权限过宽（0644）、ca 证书文件缺失、弱令牌未显式确认、端口占用、配置字段校验错误（错误信息含字段名与期望值） |

## 非目标

- 不做通用 UDP 中继（本版）；QUIC datagram 扩展已开启作为未来预留通道，SOCKS5 UDP ASSOCIATE 返回 `command not supported`。DNS 场景由 DNS 专项转发覆盖。
- 不做插件系统、JS 热加载。
- 不做多租户计费、用户体系（管理员 + 代理凭据即可）。
- 不引入数据库与 Redis；运行态数据用 JSON/JSONL 文件持久化。
- 不做面板内节点远程执行。
- 单实例模式即可满足需求；多服务端 + 共享节点池（状态外置）明确为非目标。
- 自更新（校验和验证 + 原子替换 + 失败回滚）为可选进阶项，本版未实现。

## 开发与测试

```bash
go build ./...            # 编译
go vet ./...              # 静态检查
go test ./...             # 单元测试
go test -race ./...       # 竞态检测
go test ./internal/integration/ -v   # 进程内端到端集成测试
pwsh -File scripts/acceptance.ps1    # 验收自测（Windows）
```

测试矩阵：调度策略/粘性/黑名单/熔断、组过滤与 fail-closed、ACL、帧编解码/窗口、会话与流 FSM、配置加载、凭据校验、证书与 pin、provider 解析/SSRF、HTTP/CONNECT/SOCKS5 端到端；集成测试用进程内服务端 + 2 个模拟节点 + 本地 echo/HTTP 服务覆盖三种代理、组隔离、故障转移与透明重试。

## 许可证

内部交付示例项目，未附带开源许可证文件；按需求约定不得引用/改编任何外部同类项目代码或文档。
