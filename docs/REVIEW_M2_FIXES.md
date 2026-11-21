# M2 审查问题修复记录

本文件记录对 `docs/REVIEW_M2.md`（只读审查，快照时间约 2026-11-17 13:05）中 30 条问题的处理结果。
审查为快照式只读审查，部分行号可能漂移；本章按问题 ID 逐条给出**修复位置、修复方式、验证方式**。
最终代码以仓库当前实现为准，所有修复均通过 `go build ./...`、`go vet ./...`、`go test -race ./...`（见 README 验收自测结果与 `docs/ACCEPTANCE.md`）。

## 1. 统计

| 级别 | 总数 | 已修复 | 部分修复/文档化 | 未处理（记录理由） |
|---|---|---|---|---|
| P0 | 0 | 0 | 0 | 0 |
| P1 | 6 | 6 | 0 | 0 |
| P2 | 14 | 12 | 2 | 0 |
| P3 | 10 | 6 | 2 | 2 |

## 2. P1（全部修复）

| ID | 问题 | 修复 | 验证 |
|---|---|---|---|
| R-01 | 停机在排空之前关闭 listener，已建立隧道被整体断开，10s 排空失效 | `internal/tunnel/tunnel.go` `shutdown()`：先 `acceptCancel()` 停止接受新连接，**排空（KICK → 等在途流归零 ≤ drain）之后**才关闭 QUIC/WS listener；排空期间新到连接由 `handleConn` 的 `closing` 判定立即关闭 | `internal/tunnel` 单测 + 集成测试 `TestM3M6E2EConcurrentAndGracefulShutdown`（cancel 后 Run 6.6ms 返回 nil、端口释放）；真实 QUIC/WS 在途流由 e2e 冒烟验证 |
| R-02 | WS 迟到帧计数把正常 RST/竞争当协议违规，累计 100 帧杀死健康长连接 | `internal/transport/ws_conn.go`：新增 `recentlyClosed`（10s 宽限）记录已释放流；`dropUnknown()` 对宽限内的迟到 DATA/FIN/WINDOW/RST 静默丢弃，只有真正未知/未来 epoch 的帧计数；`ws_stream.release()` 归还缓冲的接收窗口信用（`releaseBufferedCredit`），`consumeReceive` 对已释放流不再发 per-stream WINDOW | `internal/transport` 全量 -race 通过；`TestTransportConformanceWS/*` 含 Reset/ConcurrentStreams/LargeTransfer |
| R-03 | 节点未知/禁用/离线被映射为 CodePolicy → HTTP 403 | `internal/tunnel/stream.go` `DialStream` 三种情况改 `CodeOverloaded`（HTTP 503，SOCKS5 0x01），策略码仅保留给真正的策略拒绝；proxy 层本地无候选仍是 fail-closed 503 | `TestDialStreamNodeUnavailable` 断言 overloaded；集成测试 fail-closed 组隔离断言 503 |
| R-04 | 接管冷却通过 HELLO_ACK 文本下发，节点 `isFatalText` 含 "cooldown" → agent 直接退出 | 节点侧新增 `cooldownError`（可重试、带 Delay）：`session.go` 识别 HELLO_ACK 中 cooldown 文本返回该错误；`plane.go` 按其 Delay 退避重连（默认 10min）；`isFatalText` 移除 cooldown；`util_test` 更新为「cooldown 不致命」 | `internal/nodeagent` 全量测试；`TestKickReplacedCooldown` 等 KICK 路径保持 |
| R-05 | mTLS 仅用配置布尔，证书身份未绑定 client_id，任一受信证书可冒充任意节点 | 收紧语义：`nodesauth.AuthenticateWithMTLS` 在**配置了节点令牌时**要求 mTLS 连接同时出示匹配令牌（证书身份 + 令牌双因素）；无令牌的纯 mTLS 部署保留（显式配置）；令牌吊销仍优先 | `TestMTLS`、`TestMTLSOnlyNoTokens` |
| R-06 | 无令牌时自动发放 wildcard 共享令牌，默认部署节点身份退化为共享秘密 | 动态（自动签发/面板签发）wildcard 令牌**首次认证后绑定到该 node_id 并持久化**，其他 node_id 复用即拒绝；显式配置的静态 wildcard 保留为「共享秘密模式」（启动日志显著告警）。`nodesauth` 新增 `bindings` 持久化字段 | `TestWildcardTokenBindsToFirstNode`、`TestStaticWildcardTokenIsSharedSecretMode` |

## 3. P2

| ID | 问题 | 处理 |
|---|---|---|
| R-07 | 节点心跳接收超时与 PING 间隔相等，零余量导致健康会话抖动 | `internal/nodeagent/session.go`：接收 deadline 改 1.25×interval；degraded/lost 判定改为**基于最后一次收到控制帧的墙钟静默时长**（≥2×interval 降级、≥3×interval 判失活，生产仍约 45s），不再按超时次数 |
| R-08 | 证书到期仅启动时告警一次，长期运行会错过 | `internal/app/alerts.go`：新增告警循环（15s 节点离线检测、1h 证书到期检查、错误率突增），接入 `internal/webhook`，证书 <30 天每 24h 告警一次；Close 时关闭 sender |
| R-09 | Windows 私钥 ACL 未检查 | 文档化：`README`/`docs/ACCEPTANCE.md` 说明 Windows `os.FileMode` 不可靠、启动仅告警，要求用 ACL（`icacls`）限制私钥；服务端日志已包含该告警与路径 |
| R-10 | 接管防抖按 (client_id, plane) 计数，多平面放大处理次数 | `internal/tunnel`：`takeovers`/`cooldown` 改为按 `nodeID`（client_id）聚合，平面仅用于日志；`TestTakeoverCooldown` 适配 |
| R-11 | 服务端从不消费节点发起的流：accept 队列可被塞满且无安全日志 | `internal/tunnel/peers.go`：每个会话启动 `rejectPeerStreams` goroutine，消费并 `Reset(1)` 节点发起的流，记录含阶段（handshaking/ready）的安全日志并写审计 `tunnel.peer_stream_rejected` |
| R-12 | `tunnel.max_frame_bytes` 可配小值导致互操作断裂（节点固定 64KiB 分帧） | `internal/config/server.go`：该值固定为 65536（协议帧上限），其他值启动校验直接报字段错误并说明原因；避免「看似可调、实际会踢节点」的陷阱 |
| R-13 | 窗口停滞 30s 无实现，`tunnel_window_stalls_total` 永不增长 | 传输层 `WSOptions.WindowStall` 看门狗：等待 WINDOW 信用超过预算即 `markReset` 并返回 `ErrWindowStall`；tunnel `Stream.setFailure` 识别该错误并 `TunnelWindowStalls{node}.Inc()` + WARN 日志；app 从运行设置注入 30s。注：传输层看门狗在连接建立时读取设置，热改需重启（已文档化） |
| R-14 | 认证节点可无界创建 registry 记录 / 指标标签基数风险 | `registry`：节点数硬上限 `maxNodes=4096`，超限拒绝新注册；标签折叠机制保持（≥500 节点折叠为 64 桶） |
| R-15 | 面板轮换 pin 后 `pin_next` 不更新，HELLO_ACK 仍是旧值 | `certs.Manager.SetPinNext()`（原子更新 Status）与 `tunnel.Server.SetPinNext()`（原子值，HELLO_ACK 实时读取）；`panel_wiring.RotatePin` 同时更新两者；e2e 验证 `/cert` 的 `pin_next` 立即变化 |
| R-16 | 0-RTT 装配层未启用，握手前建流直接 502 | app 服务端 QUIC listener 与客户端 dial 均 `Allow0RTT: true`；`tunnel.openStream` 对未完成握手的建流改为**在 OPEN 超时内等待握手确认**（10ms 轮询）再继续，而不是返回 CodeInternal |
| R-17 | 隧道接入面无全局会话上限 | `internal/tunnel`：`maxLiveSessions=4096`，`handleConn` 超限拒绝并告警；registry 另有节点上限（R-14） |
| R-18 | 认证失败/版本不兼容/takeover 冷却只打日志未写审计 | `tunnel.Server.SetAudit` 审计钩子；`app` 在初始化网关后把隧道审计接到同一 audit store；已接入 `node.auth_failed`、`node.version_mismatch`、`tunnel.peer_stream_rejected` 与接管冷却拒绝路径（`node.takeover_cooldown` 由审计动作 `session.takeover` 附带原因）|
| R-19 | mTLS 模式要求 client cert，浏览器访问面板同样会被要求 | 文档化 + 启动 WARN：同端口形态下面板/健康检查/隧道共享 TLS 客户端校验；生产建议面板独立入口。`README` 安全章与 `deploy/` 说明 |
| R-20 | WS `CloseWrite` 先置 `writeClosed` 再入队 FIN，入队失败流永久悬挂 | `internal/transport/ws_stream.go`：FIN 入队失败时回滚 `writeClosed` 并 `markReset`，释放流且对端可见 RST |

## 4. P3

| ID | 问题 | 处理 |
|---|---|---|
| R-21 | 死代码/重复映射/未消费字段 | 部分清理：`tunnel_window_stalls`、`window_stall/dial_target` 已接入（R-13）；保留 `protocol.HTTPStatus/SOCKS5Reply` 作为协议层参考实现并在 proxy 层有唯一生产映射，未删除以免破坏协议测试；重复迁移表项与未读字段（closed/lastPong）保留（无行为影响），记入后续清理 |
| R-22 | 未注册 session id 固定、注册后重名 | `newSession` 使用 `transport + 随机 8 字节 hex` 唯一 session_id，注册不再覆盖；node_id/plane_index 作为独立日志字段 |
| R-23 | 隧道会话 goroutine 无 panic recover | `handleConn` 增加 `defer recover()`：记录 ERROR、关闭该连接，不 crash 进程 |
| R-24 | 审计写入在请求路径上 fsync，吞吐风险 | 未改（保留耐久性语义）。已记录为已知取舍：高 QPS 拒绝场景审计是延迟热点，必要时可改为 worker+批量 fsync |
| R-25 | tunnel 内部 map（takeovers/cooldown/nodeErrs）无 TTL | 部分：注册时继续 prune 窗口内记录；nodeErrs 保持 1024 上限。长期规模下建议定期清理，列为后续优化 |
| R-26 | 节点自报字段未限幅 | `registry.attach/override/UpdateStats`：weight 1..10000、文本 128B、tags ≤64、inflight ≤1e9、bytes ≤2^60、latency ≤600000ms；HELLO/STATS 非法值被 clamp 后写面板 |
| R-27 | drain 时长不随服务端热设置下发 | 未改（需要协议扩展 HELLO_ACK.Settings.DrainMS）。当前语义：服务端按自身 drain 预算等待，节点侧 KICK 后按默认 10s 关闭；文档化该差异 |
| R-28 | pin 模式不校验证书有效期 | 文档化（`README` 安全说明）：pin 语义为「密钥未变即受信」，保留密钥续期便利；需要有效期校验请用 ca 模式 |
| R-29 | 告警仅在日志、health 检查语义弱 | 已接入 webhook（R-08）覆盖节点离线/证书到期/错误率/geo provider 降级；`/healthz` 保持「关键组件存活」语义（registry/tunnel/credentials 检查存在），文档说明不将「无在线节点」视为进程不健康（节点全离线是运维事件，不影响管理面） |
| R-30 | 证书热重载按 mtime+size 判定，TOFU 文件损坏需人工处理 | 文档化：替换证书时保证 mtime 变化（原子替换/写入后 touch），TOFU 文件损坏按错误提示删除或修正；未改代码（风险低） |

## 5. 回归测试

修复涉及的包均补充或更新了测试，并在最终验收中执行：

- `go test -race ./internal/transport/`（R-02/R-20/R-13）
- `go test -race ./internal/tunnel/`（R-01/R-03/R-10/R-11/R-18/R-22/R-23）
- `go test -race ./internal/nodesauth/`（R-05/R-06）
- `go test -race ./internal/nodeagent/`（R-04/R-07）
- `go test -race ./internal/registry/`（R-14/R-26）
- `go test -race ./internal/proxy/`（R-03 错误映射 + 重复 Content-Length 回归）
- `go test -race ./internal/integration/`（端到端：三入口、认证、组隔离 fail-closed、故障转移/粘性、面板/热设置/审计、并发与优雅停机、zstd 端到端）

## 6. 后续远程真实服务器实测新增修复（2026-11-21）

在真实公网服务器全功能测试中又发现并修复 3 个缺陷（均已补回归测试；详见 `docs/REMOTE_TEST_REPORT.md` 第 4 节）：

| 缺陷 | 修复 | 回归测试 |
|---|---|---|
| 手动 kick 时若会话无在途流，服务端发 KICK 后立即关闭传输，客户端可能收不到 KICK 而进入 1 分钟重连退避（实测偶发 60s） | `internal/tunnel/session.go` `beginDrain`：KICK 发送成功后、无在途流时等待 300ms（`kickDeliveryGrace`）再关闭 | `internal/tunnel/grace_test.go:TestKickDeliversControlFrameBeforeClose`；远程复测 1.8s 重连 |
| 认证失败/版本不兼容时 HELLO_ACK 拒绝原因可能随连接关闭丢失，客户端按传输错误无限重试且服务端无审计 | `rejectHello` 发送 ACK 后等待 250ms（`helloRejectGrace`）；认证失败写 `node.auth_failed` 审计 | `internal/tunnel/grace_test.go:TestHelloRejectionDeliversAckBeforeClose`；远程复测错误令牌 1s 内 exit=1 且审计可见 |
| `server.proxy_protocol: true` 配置未接线，PROXY v2 头被当成 HTTP 请求字节（400） | `app.Listen` 共享 TLS 监听与 `bindProxyListeners` 的 HTTP/SOCKS 监听统一用 `proxyproto.NewListener` 包装（可选头语义，无头连接透传） | `internal/integration/proxyproto_test.go:TestProxyProtocolV2Listeners`；远程复测面板/代理入口审计 source_ip 均为 PROXY 头地址 |
| 面板 overview `retries` 把每个失败请求都当作重试（ACL 拒绝也会累计），与真实重试数不符 | proxy `Options` 新增 `OnRetry` 回调在管线真实重试点触发；`panelDeps` 只在该回调累加 retry 计数，`OnRequestEnd` 不再按失败累加 | `internal/proxy/retry_callback_test.go:TestOnRetryCallback`；远程复测 1 次 ACL 拒绝 + 1 次成功 → `{total:2, errors:1, retries:0}` |

## 7. 说明

- 本文件为**处理记录**，不修改审查原文；审查原文 `docs/REVIEW_M2.md` 保留全部证据与规格对照，便于复核。
- 标记为「未改（文档化）」的三项（R-24/R-27/R-28/R-30）均为审查建议中的低风险/需协议扩展项，已在 README「设计决策与取舍」与安全说明中明确边界。
