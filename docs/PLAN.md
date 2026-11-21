# 实施计划（M1–M7）

本文件是内部实施计划与模块契约，最终交付文档见 `README.md`。
规格冲突时以附件 `tunnel-state-machine.md` 为准；歧义取舍见 README「设计决策」一节。

## 0. 技术基线

- 语言：Go（module `proxygw`，go 1.22 指令），单仓库双二进制：
  - `cmd/proxygw-server`：公网服务端（代理入口 + 隧道服务 + 面板 + 指标）
  - `cmd/proxygw-client`：节点客户端（主动外连服务端，从本机网络出口建连）
- 前端：原生 HTML/CSS/JS，`embed.FS` 内嵌进服务端二进制；运行态仅 JSON/JSONL 文件。
- 依赖（锁定版本，README 说明用途）：

| 模块 | 版本 | 用途 |
|---|---|---|
| github.com/quic-go/quic-go | v0.48.2 | QUIC 传输（TLS1.3 + 自定义 ALPN `proxygw/1`） |
| github.com/gorilla/websocket | v1.5.3 | wss 回退传输 |
| gopkg.in/yaml.v3 | v3.0.1 | 配置解析 |
| github.com/klauspost/compress | v1.17.11 | zstd 压缩（可选开关） |
| github.com/golang-jwt/jwt/v5 | v5.2.1 | 面板 JWT |
| github.com/prometheus/client_golang | v1.20.5 | /metrics |
| golang.org/x/crypto | v0.31.0 | argon2id / bcrypt 口令哈希 |
| github.com/oschwald/maxminddb-golang | v1.13.1 | 本地 GeoIP MMDB |

JSON Path 提取（`$.a.b[0]`）自研实现，避免额外依赖。

## 1. 目录与模块职责

```
cmd/proxygw-server       服务端装配与生命周期
cmd/proxygw-client       节点装配与生命周期
internal/version         ldflags 注入的 version/commit/build_time
internal/logx            slog 初始化、统一字段、脱敏
internal/config          三层配置（env > yaml > default）、默认值、校验、热更设置类型
internal/model           全仓共享数据结构（Node/Group/Credential/StickyRule/ACLRule/Settings/Audit...）
internal/store           JSON 原子持久化（tmp+fsync+rename，backup 回退）
internal/protocol        隧道线上协议：WS 帧编解码、OPEN 头、错误码、控制消息 JSON
internal/certs           自签证书、SPKI pin、pin_next、CA 模式、热重载、客户端 TLS 校验
internal/transport       Transport/Conn/Stream 接口 + quic / ws 两实现
internal/tunnel          会话 FSM、流 FSM、多平面、server 会话/注册接入、client agent、回退退避
internal/registry        节点注册表（在线、健康、出口 IP、去重、组归属计算）
internal/auth            代理凭据存储/校验（argon2id、组、过期、并发、带宽、来源网段）、面板登录 JWT/TOTP
internal/acl             ACL 顺序匹配 + 强制默认拒绝清单
internal/sched           四种路由策略、会话粘性、粘性黑名单、熔断器、令牌桶限流
internal/proxy           HTTP/CONNECT/SOCKS5 三入口共用管线
internal/geo             出口 IP 解析、MMDB + preset/template/schema provider、归一化、SSRF 防护
internal/probe           节点拨测（Ping/TCPing/HTTP GET/DNS）、DNS 专项转发
internal/metrics         Prometheus 指标 + 15min 环形趋势
internal/audit           JSONL 审计
internal/settings        运行设置热生效、持久化、撤销
internal/panel           面板 HTTP API、鉴权中间件、SSE、内嵌前端资源
internal/integration     进程内集成测试
web/                     内嵌前端静态资源
deploy/                  Dockerfile×2、compose×2、systemd、Windows 服务说明
scripts/                 一键接入脚本、验收脚本、演示脚本
docs/                    计划与设计文档
```

## 2. 线上协议契约

### 2.1 WS 帧头（QUIC 路径不需要帧；控制流复用同一编解码）

| 字段 | 长度 | 说明 |
|---|---|---|
| type | 1 | 帧类型 |
| stream_id | 4 | 大端；`0` 为连接级控制帧；高 12 位编码 epoch，低 20 位为序号 |
| length | 4 | 载荷长度，≤ 64 KiB，超限=协议错误并断开 |
| payload | length | 数据或元信息 |

帧类型：

| type | 名称 | 方向 | 说明 |
|---|---|---|---|
| 0x01 | OPEN | S→C（WS 路径） | payload=OPEN 头 |
| 0x02 | OPEN_OK | C→S | 建流成功（无载荷） |
| 0x03 | OPEN_ERR | C→S | payload=`code(1) + message(v)` |
| 0x04 | DATA | 双向 | 流数据 |
| 0x05 | FIN | 双向 | 半关闭本端写方向 |
| 0x06 | WINDOW | 双向 | `stream_id=0` 为连接级；payload=uint32 增量 |
| 0x07 | PING | 双向 | 连接级保活 |
| 0x08 | PONG | 双向 | 保活响应 |
| 0x09 | STATS | C→S | 节点统计 JSON |
| 0x0A | RST | 双向 | 异常复位（非正常结束） |
| 0x10 | HELLO | C→S | 控制消息 JSON（注册） |
| 0x11 | HELLO_ACK | S→C | 控制消息 JSON（epoch/settings/pin_next） |
| 0x12 | KICK | S→C | 控制消息 JSON（reason：shutdown/replaced/revoked/disabled） |
| 0x13 | STATS_REQ | S→C | 请求节点上报统计 |
| 0x14 | PROBE | 双向 | 控制消息 JSON（节点拨测/DNS 转发请求） |
| 0x15 | PROBE_RESULT | 双向 | 控制消息 JSON |

### 2.2 OPEN 头（两路径一致，附件 3.3）

`ver(1) | proto(1) | addr_type(1) | addr(v) | port(2) | trace_id(16) | flags(1)`

- ver：协议版本，当前 `1`；不兼容明确报错。
- proto：`1=TCP`（本版仅 TCP；DNS 由 PROBE 扩展承载）。
- addr_type：`1=IPv4(4B)`、`2=IPv6(16B)`、`3=域名(1B len + n)`。
- flags：bit0 = 压缩；其余保留必须为 0（非 0 视为协议错误）。
- 域名长度 ≤ 255；未压缩时所有长度上限见协议常量。

### 2.3 控制消息（JSON）

- `HELLO{ver, token, client_id, alias, tags[], region, weight, transport, egress_ips{v4,v6}, version, planes, epoch_hint, ts}`
- `HELLO_ACK{ver, ok, error, epoch, transport, heartbeat_ms, settings{...}, pin_next, server_time}`
- `STATS{inflight, bytes_in, bytes_out, latency_ms, transport, version, egress_ips, active_streams, ts}`
- `KICK{reason, message}`
- `PROBE{kind, target, payload_b64} / PROBE_RESULT{ok, error, latency_ms, result_b64}`

### 2.4 流 ID 与 epoch

- WS 路径流 ID：`(epoch & 0xFFF) << 20 | seq`；seq 从 1 递增，0 保留给控制。
- QUIC 路径无流 ID（原生流），epoch 在会话注册时确定，迟到流通过会话隔离天然丢弃。
- 会话重建 epoch+1；旧 epoch 帧按协议错误丢弃并记安全日志。

## 3. 核心数据结构（internal/model）

- `Node`：id、alias、region、tags、weight、enabled、online、egress_ip{v4,v6,source,updated_at}、geo{country,region,city,asn,asn_org,isp,sources}、inflight、bytes_in/out、latency_ewma、breaker_state、last_heartbeat、version、groups、transport、planes、duplicate_of、created_at、updated_at。
- `Group`：id、name、description、match{tags_any,regions_any}、nodes_add、nodes_remove、created_at、updated_at。
- `Credential`：id、username、password_hash(argon2id)、groups、enabled、expires_at、max_concurrent、bandwidth_kbps、allowed_protocols、source_cidrs、note、last_used_at、usage_bytes、created_at、updated_at。
- `StickyRule`：id、enabled、note、target{cidrs,domains}、node_groups、node_ids。
- `ACLRule`：id、order、src_cidrs、domains、ports、protocols、action、created_at、updated_at。
- `Settings`（运行态热更）：scheduler{strategy,sticky{enabled,ttl,max_keys_per_node},breaker{failure_threshold,failure_rate,min_samples,open_timeout},retry{enabled,max_attempts}}、limits{global_down_kbps,per_node_down_kbps,per_credential_down_kbps}、timeouts{open,read_header,idle,write_block,linger,drain,window_stall}、compression_enabled。
- `AuditEvent`：time、actor、source_ip、action、object、result、detail（脱敏）。

## 4. 里程碑门禁

每个里程碑结束跑：`go build ./...`、`go vet ./...`、`go test ./...`；M7 后跑 `go test -race ./...`。全绿才进入下一阶段。

**当前状态（全部里程碑完成）**：M1–M7 已全部实现并通过门禁，最终验收记录见 `README.md`「验收自测结果」与 `docs/ACCEPTANCE.md`；M2 只读审查的 30 条问题处理结果见 `docs/REVIEW_M2_FIXES.md`。

| 里程碑 | 交付 | 验证 |
|---|---|---|
| M1 | 目录、配置、日志、版本、model/store、health、双二进制可启动 | build/vet/test + 启动冒烟 |
| M2 | 协议、证书、双传输、会话/流 FSM、多平面、回退、注册鉴权 | 编解码/窗口/FSM 单测；UDP 丢弃回退、pin 硬失败集成 |
| M3 | 三入口、凭据/组、fail-closed、ACL | 单测 + curl 端到端 |
| M4 | 四策略、粘性/黑名单、熔断、限流、透明重试、故障转移 | 集成测试 |
| M5 | 出口 IP、去重、geo provider、归一化、拨测、DNS 转发 | provider/SSRF 单测；元数据集成 |
| M6 | 面板、热设置回滚、审计、指标、内嵌前端 | API 测试 + 浏览器可用 |
| M7 | IPv6、PROXY v2、TOTP、Webhook、TopN、trace、接入脚本、时钟偏移、zstd | 全量 -race 验收 |

## 5. 执行分工（Agent Teams）

- Lead：规格裁决、公共契约（model/config/protocol/接口）、集成门禁、验收、README。
- Teammates：按里程碑以**互不重叠的包目录**并行实现；每人交付前在本包内 build/vet/test 通过；
  跨包接口只允许改自己包内实现，公共契约变更需回到 Lead。
- 共享任务板记录 write scope 与依赖，避免同时改同一文件。
