# proxygw M2 只读审查报告（状态机 / 并发 / 安全 / 规格一致性）

- 审查人：teammate `reviewer`（task-14）
- 审查时间：2026-11-17 12:46–13:05（Asia/Shanghai）
- 审查方式：**只读**。除本文件 `docs/REVIEW_M2.md` 外未创建/修改/删除任何文件；未执行 `go mod tidy`、`gofmt -w`、任何 `git` 操作。
- 结论速览：**P0=0，P1=6，P2=14，P3=10**。没有发现可远程无凭证触发的 P0；但存在 2 处会让「用户可见的流被非预期中断」的 P1（优雅停机排空失效、WS 迟到帧计数误杀长连接）、2 处与附件 2.2/第 7 章直接冲突的 P1（接管冷却被客户端致命化、节点不可用返回 403）、2 处安全类 P1（mTLS 身份未绑定、默认共享通配令牌）。

> **审查基线声明**：审查期间仓库处于多 agent 并行开发状态（task-2 transport、task-9 proxy、task-10/11 panel、task-12/13 M7 均为 in_progress；`internal/app/{gateway,panel_wiring}.go`、`internal/tunnel/session.go`、`internal/transport/*`、`internal/proxy/*` 在 12:46–13:02 之间被其他 agent 持续修改）。本报告基于 12:46–12:57 的阅读/验证快照；13:02 复验时 `go build ./...`、`go vet ./internal/...` 与核心包 `-race` 测试均已恢复绿色（见 1.2 第 10 行），说明 12:56/13:00 的 vet 失败是并发编辑瞬态。**合并后请由 lead 在最终稳定树上复跑 `go build ./... && go vet ./... && go test -race ./...`。**

---

## 1. 审查范围与方法论

### 1.1 输入

| 类别 | 内容 |
|---|---|
| 规格（附件优先） | `tunnel-state-machine.md`（第 2/3/6/7/8/9/10/11/12/13 章为重点）；`go-multi-node-proxy-prompt.md`（A/B/C/D/G/I/K 章、验收标准） |
| 实现（M2 范围） | `internal/protocol`、`internal/fsm`、`internal/certs`、`internal/transport`、`internal/tunnel`、`internal/registry`、`internal/nodesauth`、`internal/nodeagent`、`internal/app`、`internal/config`、`internal/stats`、`internal/groups`、`internal/rules`、`internal/audit`、`internal/settings` |
| 装配 | `cmd/proxygw-server`、`cmd/proxygw-client`、`internal/integration/integration_test.go` |
| 辅助核对 | `internal/model`、`internal/metrics`、`internal/store`、`internal/identity`、`internal/health`、`internal/logx`、`internal/proxy`（仅错误码映射一致性） |

方法：先以 `grep`/`read` 通读实现（不采信注释），逐条对照附件状态机迁移表、超时总表、错误码表、并发不变量与边界用例；再用只读命令验证可编译/可测试性；对每个疑似缺陷给出文件/符号级证据与最小修复建议。**没有**做 gofmt/vet 修复、没有改实现。

### 1.2 执行的只读命令与结果摘要

| # | 命令 | 时间 | 结果 |
|---|---|---|---|
| 1 | `go build ./...` | 12:46 | **exit 0** |
| 2 | `go vet ./internal/...` | 12:47 | **exit 0**（当时快照） |
| 3 | `go test -race -count=1 ./internal/{protocol,fsm,certs,transport,tunnel,registry,nodesauth,nodeagent,app,config,stats,groups,rules,audit,settings,integration}/` | 12:46–12:49 | **全部 ok**；app 无测试文件；integration 13.689s；transport 3.4s、nodeagent 5.1s |
| 4 | 同上 10 个核心包 `-race -count=2`（flaky 复测） | 12:56–12:57 | **全部 ok**（transport 5.0s、tunnel 1.9s、certs 4.6s、nodeagent 8.0s、registry/nodesauth/fsm/protocol/config/stats 均 ok） |
| 5 | `go build ./...`（第二轮） | 12:56 | **exit 0** |
| 6 | `go run ./cmd/proxygw-server -check-config -config config.server.example.yaml` | 12:52 | **exit 0**（示例配置通过校验，含 4 条预期告警） |
| 7 | `go run ./cmd/proxygw-client -check-config -config config.client.example.yaml` | 12:52 | **exit 0**（含 transport 非 quic 的提示） |
| 8 | `go vet ./...` | 12:56 | **exit 1**：`go: updates to go.mod needed; to update it: go mod tidy` —— 与 13:00 观察到的 `compressionAgreed undefined` 一样，均为他人在途编辑引起；本审查按要求不执行 `go mod tidy`。**待稳定树复验** |
| 9 | `go vet ./cmd/...`（稳定树观察） | 13:00 | exit 1：`internal\tunnel\session.go:276:14: s.compressionAgreed undefined`（在途编辑，非缺陷） |
| 10 | 复验：`go build ./...` + `go vet ./internal/...` + `go test -race -count=1 ./internal/{tunnel,transport,nodeagent,certs}/` | 13:02 | **全部通过**（vet exit 0；tunnel 2.4s、transport 3.3s、nodeagent 5.1s、certs 2.7s），确认 #8/#9 的失败确为并发编辑瞬态；此时 M7 压缩协商已由其他 agent 接入 tunnel/nodeagent/proxy（不在 M2 审查判定内） |

补充证据（外部依赖行为核对）：quic-go v0.48.2 `server.go:138-146` 明确说明 —— 由 `Listened` 便捷函数（`quic.ListenAddr` 内部创建 Transport）返回的 Listener，其 `Close()` 会**立即关闭已建立的连接**；`qlog.NewConnectionTracer` 会在连接关闭时 `Close()` 传入的 writer（`qlog/connection_tracer.go:118-121,128-130`），故 qlog 未引入额外依赖、无 fd 泄漏。

---

## 2. 问题清单

> 级别定义：**P0** 静默丢数据/资源泄漏/安全漏洞且可远程触发；**P1** 功能与规格不符、会造成用户可见错误或安全弱点；**P2** 边界/健壮性/可观测性缺陷；**P3** 建议。
> 位置为审查快照下的 `文件:行号`（部分文件在审查期间被他人修改，行号可能漂移，已同时给出函数/符号名）。

| ID | 级别 | 位置 | 问题描述 | 复现/证据 | 最小修复建议 |
|---|---|---|---|---|---|
| **R-01** | **P1** | `internal/tunnel/tunnel.go:401-426`（`shutdown`）、`internal/transport/ws.go:174-197`（`WSListener.Close`）、`internal/transport/quic.go:159-165`（`quicListener.Close`） | **优雅停机在排空前就关闭了 listener，已建立的 QUIC/WS 隧道连接被整体立即关闭，10s 排空窗口形同虚设**：SIGTERM 时在途下载被立即中断，附件第 10 章「停止接受新连接 → KICK → 等待活跃流归零 ≤10s → 关闭连接」不成立。`shutdown()` 先对两个 listener 调 `Close()`（tunnel.go:413-420），随后才 `beginDrain`（426）并等 `activeStream`（438）；WS listener 的 `Close()` 会对 `l.conns` 里每条连接 `closeWithError(ErrListenerClosed)`；QUIC listener 因由 `quic.ListenAddr` 创建，`Close` 会立即关闭所有 established 连接（quic-go v0.48.2 `server.go:138-146` 文档原文）。因此排空等待只能看到已被 `teardown` 失败的流。 | 代码路径如上；`internal/tunnel/stream_test.go:388 TestGracefulCloseDrains` 之所以通过，是因为 `internal/tunnel/fake_test.go:71-74` 的 fakeListener.Close 只关闭 accept，不断开已有 fakeConn，掩盖了真实传输语义。 | 把 listener 关闭移到排空**之后**（或监听侧仅停止 Accept/Upgrade：WS 用「拒绝新 upgrade 但保留既有连接」的判定，QUIC 改用显式 `quic.Transport` 自持 UDP socket，排空后 `transport.Close`）；补一个使用**真实** QUIC/WS listener 的停机测试（SIGTERM 时有在途流，断言流能自然结束）。 |
| **R-02** | **P1** | `internal/transport/ws_conn.go:429-434`（`dropLate`）、`:381-425`（`dispatch`）、`:504-567`（onData/onFin/onWindow/onReset）、`internal/transport/ws_stream.go:275-338`（CloseWrite/Reset）、`internal/transport/ws.go:20-21、28` | **WS 的「迟到帧」累计计数把正常 RST/数据竞争判成协议错误，会杀死健康的长连接**：RST（及 OPEN_ERR）走高优先级 `ctrlCh`（ws_stream.go:334 `enqueueCtrlFrame`，ws_conn.go:624-637），而 DATA/FIN 走 `dataCh`（容量默认 64）。本端 `Reset` 先把 RST 写出、随后 `markReset→release` 移除流；对端收到 RST 也释放该流，此时之前已入队尚未发出的 DATA/FIN/WINDOW 才到达对端 → 对端 `lookupStream==nil → dropLate+1`。计数器 `late` **永不重置**，超过 `wsMaxLateFrames=100` 就以 `ErrProtocol` 关闭整条连接（ws_conn.go:430）。高吞吐下每次客户端中途取消/节点 RST 可产生数十个「迟到帧」，几次即可到 100。另：`CloseRead()` 在 `markReset` 释放流之后仍会 `consumeReceive` 并对已注销的流发 WINDOW（ws_stream.go:305-322、435-447），对端同样按迟到帧计数。 | 计数器语义与阈值见 `internal/transport/ws.go:29-31`（`wsMaxLateFrames=100`）、`ws_conn.go:429-434`；测试 `internal/transport/ws_test.go:341-373 TestWSUnknownStreamFrameDrop`（注入 10 帧后计数=10）、`:288-339 TestWSLateEpochFrames`（>100 帧关闭连接）证明该计数是连接致命的。附件第 8 章要求「迟到帧直接丢弃」，并**不要求**把同 epoch 的本地已复位流帧视为协议违规。 | 维护 `recentlyClosed map[streamID]expiry`（释放后保留数秒），对已关闭流的迟到 DATA/FIN/WINDOW **静默丢弃**而不计数；只对真正未知/未来 epoch 的帧计数并改为周期性衰减或更高的流内容忍；RST 发送前先让 dataCh 对该流排空，或 RST 与 DATA 同队列保序。 |
| **R-03** | **P1** | `internal/tunnel/stream.go:285-304`（`DialStream`）、`internal/proxy/errors.go:240-241`（映射终点） | **错误码映射不一致：节点未知/被禁用/离线被隧道层当作「策略拒绝（CodePolicy=4）」，最终 HTTP 客户端看到 403 Forbidden、SOCKS5 0x02**。附件第 7 章规定 CodePolicy 只对应 ACL/组为空（403/503、SOCKS5 0x02），而「全部候选不可用」应返回 502/503；节点在调度后被面板禁用/掉线（竞态）属于基础设施不可用，不是客户端策略问题。运维与客户端重试逻辑都会被 403 误导（客户端可能认为「禁止访问该目标」而停止重试）。 | `tunnel/stream.go:292/295/298` 三处 `protocol.NewError(protocol.CodePolicy, ...)`；`proxy/errors.go:240-241` 将 `CodePolicy` 映射 403/0x02。附件第 7 章 + 6.6；`protocol/errors.go:46-63` 的 `HTTPStatus()` 也把 CodePolicy 定为 403（该函数目前仅测试使用）。 | 把 tunnel 层的 unknown/offline/disabled 改为 `CodeOverloaded`（503）或新增 `CodeUnavailable` 映射 503；`CodePolicy` 仅保留给真正的策略拒绝（ACL/组为空在 proxy 层已有 503 fail-closed）。补隧道层单测断言这三种场景的 code。 |
| **R-04** | **P1** | `internal/tunnel/session.go:313-358`（`register` 冷却/波动拒绝，走 `rejectHello`）、`internal/nodeagent/session.go:145-147`（`!ack.OK` → `FatalError`）、`internal/nodeagent/agent.go:266-280`（`isFatalText` 含 "cooldown"）、`internal/protocol/control.go:22-23` | **接管冷却（附件 2.2：同 client_id 60s 内第 4 次接管 → 拒绝并冷却 10 分钟）在节点侧被当成致命错误，agent 直接退出而不是冷却 10 分钟后重连**：服务端冷却拒绝通过 `HELLO_ACK{ok:false, error:"takeover cooldown..."}` 下发；nodeagent `hello()` 对任何 `!ack.OK` 都返回 `FatalError`，`Run` 立即返回错误、进程退出（systemd 若配置重启则变成短周期重启-被拒循环）。服务端从不下发 `KICK(takeover_cooldown)`，因此 nodeagent 里为冷却准备的 `kickRetryDelay(KickCooldown)`（agent.go:1003-1011）是永远不会走到的死路径。 | tunnel/session.go:334-358 `rejectHello`；nodeagent/session.go:145-147；agent.go:220-222 注释明确把 "takeover cooldown" 列为 fatal——这是与附件 2.2 冷却语义冲突的**设计取舍**而非实现遗漏。 | 服务端在 HELLO_ACK 里用机器可读的 error code（而非纯文本）区分 `auth/version/pin/cooldown`；nodeagent 对 cooldown 返回可重试错误并退避 ≥ `TakeoverCooldown`（10min）后重连；fatal 只保留 pin 不匹配/认证失败/版本不兼容。 |
| **R-05** | **P1（安全）** | `internal/tunnel/session.go:260`、`internal/nodesauth/nodesauth.go:173-218`（`AuthenticateWithMTLS`，尤其 :187）、`internal/config/server.go:353-368`（现有缓解校验） | **mTLS 模式下节点身份没有与 client_id 绑定：任一受信 CA 签发的客户端证书都能冒充任意 node_id 注册**。tunnel 调用 `AuthenticateWithMTLS(nodeID, hello.Token, s.auth.MTLSEnabled())`，第三个参数本应是「本连接是否已出示被 TLS 验证的客户端证书」，这里却直接传了**配置布尔**；`AuthenticateWithMTLS` 在 `a.mtls && mtls` 时无条件放行，不校验证书 CN/SAN/指纹与 `nodeID` 的对应关系，也不要求客户端同时带 token。配置校验（`nodes.mtls=true` 必须 `tls.client_auth=require` 且 `tls.mode=ca` + `ca_file`）能阻止「无证书直接绕过」，但阻止不了**一个合法节点证书冒充其它节点**（接管其平面、接收原本属于别人的用户流量/出口身份），且与 token 模式（每节点独立令牌）相比是安全回退。 | tunnel/session.go:260；nodesauth.go:173-190（revoked 检查后 `if a.mtls && mtls return nil`）；config/server.go:364-368。 | 读取 TLS 连接状态导出客户端证书（`transport.Conn` 增加 `PeerCertificate()/TLSState()`），把证书指纹/CN/SAN 与 node_id 的映射做校验（或每个节点配置 client cert pin）；`mtls` 参数改为来自连接事实。无法短期实现时至少在文档/面板把 mTLS 标注为「整池互信」，并建议与 per-node token 叠加（token 为必选、mTLS 为加强）。 |
| **R-06** | **P1（安全）** | `internal/app/server.go:120-127`（启动自动 `Issue("*")`）、`internal/nodesauth/nodesauth.go:205-212`（通配令牌对任意 nodeID 生效）、`internal/registry/registry.go:139-157`（任意 id 建节点记录） | **默认部署发放共享 wildcard token `*`，节点身份退化为「所有节点共享一个秘密」**：任何拿到该令牌的人（一台被入侵的节点即等价）可以任意 `client_id` 注册、冒充其它节点、触发接管（服务端只能靠接管防抖/日志发现），并可以伪造任意 node_id 让 registry 新建节点记录、刷指标标签。规格 G.3 要求「每节点独立令牌或 mTLS（推荐 mTLS）」；C.1 的「首启自动生成随机凭据并只打印一次」针对的是代理凭据，不应把节点接入也退化为全局共享令牌。 | app/server.go:120-127：无 `nodes.tokens` 且未启用 mTLS 时 `authn.Issue("*", ...)` 并打印；nodesauth.go:205-212 通配令牌兜底任意 nodeID；registry.go:139-157 首次 AttachPlane 即建记录、断开后仅置 `Online=false` 永不删除（见 R-14）。 | 首启时生成**绑定到某个 node_id 的令牌**（配合安装脚本/面板为每台节点签发），或要求配置 `nodes.tokens`/mTLS 才能启动（安全默认）；wildcard 共享令牌改为显式 opt-in（如 `nodes.allow_shared_token: true`）并在启动日志醒目告警；配合 R-14 限制节点数量。 |
| **R-07** | P2 | `internal/nodeagent/session.go:244-292`（`controlLoop`，:250 `interval := s.heartbeat`）、`:154-156`（心跳间隔取自 HELLO_ACK）、`internal/tunnel/session.go:617-645`（服务端 `heartbeatLoop` 每 15s 发 PING） | **节点侧心跳超时零余量：`Recv` 超时 = 服务端 PING 周期（15s），健康链路也会周期性超时**。节点等待下一帧的 deadline 是「上一帧到达时刻 + 15s」，而服务端下一次 PING 是在「上一次发送时刻 + 15s」后才发出，二者差值约为网络抖动（可正可负）；一旦抖动为正，节点就先超时：`misses=1 → fire(SessEvHeartbeatMiss) → 打 WARN「服务端心跳迟到，会话降级」`，下一帧到达再恢复。生产 WAN 上可能每几十秒一次的 ready↔degraded 抖动与告警刷屏（虽然 3 次连续超时才会断链，不会误断）。现有单测 `agent_test.go:453-487 TestHeartbeatKeepsSessionAlive` 用 8ms PING / 20ms 超时（60% 余量），掩盖了零余量问题。 | nodeagent/session.go:250-280；tunnel/session.go:617-645、`sendHeartbeatPing`；协议 `HelloSettings.HeartbeatMS` = 服务端 `times.Heartbeat`（tunnel/session.go:446-453）。 | 接收超时取 `2×interval` 或改为「距最后一次收到控制帧的墙钟时间 ≥45s 才判死」；degraded 判定用「一个完整 PING 周期内无任何帧」但统计口径加容差（如 >1.25×）；单测覆盖 1.0× 边界（可选 jitter 注入）。 |
| **R-08** | P2 | `internal/certs/server.go:195、361、365-378`（`warnIfExpiring` 只在加载/重载时调用）、`:406-449`（`Watch` 只在文件变化时 Reload） | **证书到期没有周期性检查**：`warnIfExpiring` 只在 `NewServerManager` 和 `Reload()` 时执行；`Watch` 每秒轮询但只在文件 mtime/size 变化时触发 Reload。若证书不轮换、进程长期运行，**永远不会有「30 天内到期」告警**；到期后 pin 模式仍可用（客户端只比 SPKI），但 ca 模式客户端会拒连。规格 K.7「到期前 30 天开始告警」、H.4「证书/GeoIP 临近过期可推送 Webhook」要求。 | certs/server.go:195、361；Watch 循环 406-449 只处理 stamp 变化。 | Watch 内增加每日 ticker 检查 `Status.NotAfter` 并告警（一次/天），或启动独立 `expiryLoop`；接 Webhook（M7 `internal/webhook` 已具备）。 |
| **R-09** | P2 | `internal/certs/identity.go:274-295`（`checkPrivateKeyPermissions`，:289 `runtime.GOOS == "windows"`） | **Windows 上私钥权限过宽只告警、不拒绝启动**，验收标准第 23 条（私钥被改成 0644 时服务端拒绝启动）在本项目当前主平台无法满足。POSIX 行为正确（`perm&0o077!=0` 直接报错）；Windows 的 os.FileMode 权限位不可靠，代码选择只告警并提示用 ACL，这是合理取舍，但应在 README/验收说明里显式标注平台差异，并尽量用 Windows ACL 检查补强。 | certs/identity.go:277-295；`checkPrivateKeyPermissions` 在 `loadIdentity`（299）与客户端 mTLS（client.go:59）均被调用。 | 文档记录平台差异（验收 #23 在 Windows 上改为「告警 + ACL 检查」）；可用 `golang.org/x/sys/windows` 读取 DACL 校验仅当前用户/管理员可读，或在 Windows 上把该检查纳入安全自检输出。 |
| **R-10** | P2 | `internal/tunnel/tunnel.go:182-187`（`sessionKey{nodeID, planeIndex}`）、`internal/tunnel/session.go:313-358`（接管窗口 `s.takeovers[key]`、冷却 `s.cooldown[key]`） | 附件 2.2 的接管防抖是**按 client_id**（「同 client_id 60s 内第 4 次接管」），实现按 (client_id, plane_index) 分槽计数：默认 2 平面的节点可以在 60s 内完成 3×2=6 次接管才触发冷却，多平面（最多 8）可放大到 24 次。双 agent 互踢时最多多踢若干轮才被兜住（仍会最终冷却，非无限）。 | tunnel/tunnel.go:182-187；session.go:313-356 的 `key := sess.key()`。 | 接管统计/冷却 key 改为仅 `nodeID`（跨平面聚合），plan 仅用于日志；或在文档中说明该取舍。 |
| **R-11** | P2 | `internal/tunnel`（全包无任何 `conn.AcceptStream` 调用，`grep` 仅 fake 实现）、`internal/transport/ws_conn.go:454-475`（`onOpen`）、`:204-219`（`AcceptStream`）、`internal/transport/ws.go:28`（accept 队列 256） | **服务端没有实现「handshaking 阶段收到 OPEN 一律拒绝并记一条安全日志」**（附件 2.3.1，服务端视角）。服务端从不消费 peer-initiated streams：WS 上节点发来的 OPEN 帧会被 `onOpen` 放进 `acceptCh`（256 上限）而无人读取；发 257 个 OPEN 后 `onOpen` 阻塞读循环 → 控制帧/心跳不再处理，只能等 45s 心跳丢失关闭，且**没有任何安全日志**。QUIC 上 peer-initiated bidi 流会堆在 quic-go accept 队列（默认上限 4096）同样不拒绝不记录。只有 nodeagent 侧实现了注册前拒绝（nodeagent/stream.go:22-57，符合 2.3.1 的客户端半边）。 | tunnel 包 `AcceptStream` 仅出现在 `fake_test.go:497`；ws_conn.go:454-475/469-474；报文路径与 `MaxIncomingStreams`（transport/quic.go:19-23）。规格 2.3.1「服务端在 handshaking 阶段收到 OPEN 一律拒绝并记一条安全日志」。 | 会话 handshake 成功/失败后都应启动（或复用）一个「对端发起流」的 drain 循环：读 OPEN、记安全日志、`Reset`；WS 侧需要消费 acceptCh 防止读循环阻塞；同时给 `onOpen` 增加「会话尚未注册」的显式拒绝回调。 |
| **R-12** | P2 | `internal/nodeagent/session.go:154-159`（只消费 HeartbeatMS/MaxStreams）、`internal/app/server.go:157-161、177`（服务端把 `tunnel.max_frame_bytes` 传给 WSOptions/tunnel）、`internal/config/server.go:327-329`（允许 1024–65536） | **`tunnel.max_frame_bytes` 配小于 64KiB 时互操作断裂**：服务端用该值设置 WS 读限制与 tunnel 控制帧上限（合法配置范围 1024..65536），但 nodeagent 忽略 `HELLO_ACK.Settings.MaxFrameBytes`，WS 端固定按 `protocol.MaxFramePayload`（64KiB）分帧发送 DATA；服务端收到超限帧 → `ErrProtocol` 关连接（transport/ws_conn.go:290-298、failRead:307-320）。运维把该值调小以省内存时，所有节点会被反复踢下线，错误信息只有协议违规。 | nodeagent/session.go:154-159；app/server.go:157-161；`wsReadLimit`（ws_conn.go:117-123）。 | 节点在 HELLO_ACK 后按 `Settings.MaxFrameBytes` 设置发送分片上限（transport 需支持 SetMaxFrame 或 WSOptions 动态），或服务端在控制面显式拒绝与 64KiB 不一致的配置（例如校验必须等于 65536，或文档标注只影响控制帧）。 |
| **R-13** | P2 | `internal/model/model.go:400、442`（`Timeouts.WindowStall=30s`）、`internal/metrics/metrics.go:34、100-102`（`TunnelWindowStalls` 指标）、附件第 3.7/6/11 章 | **「窗口长期为 0（30s 未收到 WINDOW）→ 记 window_stall 并复位该流」没有显式实现**：`timeouts.window_stall` 没有任何生产消费方；`tunnel_window_stalls_total` 指标从未 `Inc()`。当前只能靠 relay 的 30s 写超时兜底（错误路径会 reset 流），语义上接近但**无法区分「目标不消费」与「窗口停滞」**，面板/告警也看不到该指标（附件 11 明确要求）。 | `grep -r "WindowStall"` 仅 model/settings 测试；`TunnelWindowStalls` 仅在 metrics.go 注册。 | 在 WS 发送侧增加窗口停滞看门狗：等待 WINDOW 超过 `settings.Timeouts.WindowStall` 时对**该流** `Reset` 并 `TunnelWindowStalls.WithLabelValues(node).Inc()`；设置值从 `s.settings()` 读取以支持热更。 |
| **R-14** | P2 | `internal/registry/registry.go:139-157`（AttachPlane 建记录）、`:203-227`（DetachPlane 只置 Online=false）、`:414-426`（OnlineCount/UniqueEgressCount）、`internal/metrics/metrics.go:172-182`（NodeLabel 原样用 node_id） | **认证节点可以无界创建 registry 节点记录**：`nodes` map 中的记录在节点断开后永久保留（只有覆盖/重连会更新）；配合 R-06 的 wildcard token 或任何能注册新 client_id 的节点，可以持续制造新 id 使内存/`/api` 列表无界增长。指标标签也有基数风险：`NodeLabel` 在节点数 <500 时直接使用 node_id，500 个伪造 id 即可产生大量 label series（超过 500 才折叠成 64 桶）。 | registry.go:139-157、203-227；`SetNodeCount`（metrics.go:163-167）只在 recompute 时更新；`NodeLabel`（172-182）。 | 给注册节点数设硬上限（如 `max_nodes`，默认 512）或按 `nodes.tokens` 白名单限制可注册 node_id；离线记录设置保留上限+LRU/过期清理；指标标签始终用哈希桶（不要暴露原始 id）或在 `len(nodes)` 未稳定前统一哈希。 |
| **R-15** | P2 | `internal/app/panel_wiring.go:312-317`（`certAPIAdapter.RotatePin`）、`internal/certs/server.go:141-144、178-186`（`Status.PinNext` 只来自构造参数）、`internal/certs/server.go:337-363`（`Reload` 不更新 PinNext）、`internal/tunnel/tunnel.go:173、276、287-291`（`PinNext` 构造期固定，HELLO_ACK 下发） | **面板「轮换 pin」生成的新密钥不会更新 `pin_next` 的对外展示与 HELLO_ACK**：`RotatePin()` 只是调用 `certs.GenerateAdditionalKey` 把新密钥写到 `state/certs/next` 并返回 pin；`certs.Manager.Status().PinNext` 仍是启动时配置值，`tunnel.Server` 的 `pinNext` 也是构造期快照，`HELLO_ACK.pin_next` 与面板 cert status 都保持旧值/空值，必须重启后才生效（重启后由 `tls.pin_next` 配置决定，与面板生成的文件也没有绑定）。附件 K.4/K.11 的「先下发新 pin、等全部节点接受双 pin 再切换」工作流因此断了。 | panel_wiring.go:312-317；certs/server.go:178-186（PinNext 取自 opts）；tunnel/session.go 的 ack 组装 `PinNext: s.pinNext`（约 :283）。 | `Manager` 增加 `SetPinNext(pin)`（原子存储并持久化到 state），`RotatePin` 成功后更新 Manager 与 tunnel 的 pin_next（tunnel 改为 `func() string` 或可热更接口）；Status 同步更新。 |
| **R-16** | P2 | `internal/app/client.go:112-125`（`DialQUIC` 未设 `Allow0RTT`）、`internal/app/server.go:140-150`（`ListenQUIC` 未设 `Allow0RTT`）、`internal/transport/quic.go:47-80`、`internal/tunnel/stream.go:325-327` | **0-RTT 能力实现了传输层但装配层从未启用**（附件 A.11、边界用例 #9「0-RTT 数据早于握手确认：控制流可 0-RTT，数据流必须等 1-RTT」无法覆盖/无法验证）。同时 tunnel 对 `!HandshakeComplete()` 的建流直接返回 `CodeInternal`（→HTTP 502），若将来启用 0-RTT，握手完成前到达的代理请求会被当成节点内部错误，而不是等待 1-RTT 完成。 | app/client.go:115-124、app/server.go:142-150 均未设置 `Allow0RTT`；transport/quic.go:68-74 只在使用方开启时才 DialAddrEarly；tunnel/stream.go:325-327。 | 控制流使用 0-RTT（`Allow0RTT=true` + 控制流在 early data 中），数据流路径在 `openStream` 里对 `HandshakeComplete()==false` 等待 `conn.Context()`/握手确认（带上 OPEN 超时）而不是直接 502；补边界 #9 的集成测试。 |
| **R-17** | P2 | `internal/tunnel/tunnel.go:352-387`（`acceptLoop`/`handleConn` 无全局连接/会话上限）、`internal/config/server.go`（无 max_sessions 配置项） | **隧道接入面没有全局并发上限**：未认证对端可以完成 TLS/QUIC 握手后保持 handshaking 达 10s，每连接占用 goroutine + 控制流/会话对象；没有连接/会话计数上限或接入令牌桶（只有每节点错误日志上限、代理入口 MaxConcurrent，与本层无关）。公网部署时这是低成本的半开连接/资源耗尽面（配合 G.6 限长与安全默认值）。 | tunnel.go:382-386 每连接一个 goroutine，`s.live` 无上限；`DefaultHandshakeTimeout=10s` 只限制时长不限制并发。 | 增加 `tunnel.max_sessions`（默认如 4096）与握手并发上限，超限在 Accept 后立即 `CloseWithError`；按远端 IP 做接入速率限制（可选）。 |
| **R-18** | P2 | `internal/tunnel/session.go:210-311`（认证失败/版本不兼容仅 slog）、`internal/tunnel`（无 audit 依赖） | **附件 2.2 要求「认证失败/版本不兼容 → 关闭，原因写入审计」，实现只写结构化日志，没有写 `runtime-audit.jsonl`**。运维在面板审计里看不到节点接入失败/冒充尝试；仅能在日志里找。 | tunnel/session.go:243-265 只有 `s.logger.Warn`；tunnel 包无 audit 依赖（grep）。 | 与 proxy 相同，向 `tunnel.ServerOptions` 注入 `Audit func(action string, detail map[string]string)`，在认证失败/版本不兼容/接管冷却/协议违规处写审计（注意 `remote`、`node_id` 脱敏规则）。 |
| **R-19** | P2 | `internal/app/server.go:249-262`（面板/health/wss 共用同一 TLS listener，`baseTLS` 含 `ClientAuth`）、`internal/config/server.go:353-368` | **mTLS 配置组合的副作用**：`nodes.mtls=true` 要求 `tls.client_auth=require`，而该 TLS 配置被同一 listener 用于面板、`/healthz`、`/metrics`、wss —— 浏览器管理面板将无法访问（没有客户端证书），健康检查/负载均衡探针同样会失败。这是「单一 listener 承载全部 TLS 服务」的设计副作用，规格未展开，但会直接影响部署可用性。 | app/server.go:249-262：`baseTLS := s.certMgr.TLSConfig()` → `tls.NewListener(ln, baseTLS)`，`ClientAuth=RequireAndVerifyClientCert` 对所有 ALPN 生效。 | 文档明确 mTLS 模式下面板需内网/单独明文回环端口；或拆分 listener：面板独立端口/独立 TLS 配置（`client_auth` 只作用于 tunnel ALPN）；至少启动时对该组合打 INFO/WARN 说明。 |
| **R-20** | P2 | `internal/transport/ws_stream.go:275-303`（`CloseWrite`） | **`CloseWrite` 先把 `writeClosed=true` 再入队 FIN；入队失败（队列 deadline 到期/连接关闭）时 FIN 永远发不出去、且 `maybeRelease` 不会被调用**：对端读方向收不到 EOF 只能等空闲/linger 超时；本端流状态已半关闭，无法再 CloseWrite 重试，极端情况下流表项悬挂到连接结束。 | ws_stream.go:285-299：`s.writeClosed.Store(true)` 在 `enqueueDataFrame(FrameFin...)` 之前，失败直接 return err 不 reset 状态。 | 入队失败时回滚 `writeClosed` 或直接 `markReset` 释放流；FIN 与数据同队列入队失败应视为连接级错误（当前 enqueue 错误会带连接错误，建议统一 `Reset`）。 |
| **R-21** | P3 | 多处 | **死代码/重复定义**：`Timeouts.drainTimeout()`（tunnel.go:143-148）无调用方；`fsm.SessionFSM.closed`（fsm.go:76、112）写入后从不读取；`session.lastPong`（session.go:73、550）写不读；`fsm.StreamTransitions` 重复项（fsm.go:179 与 :190 `{HalfLocal, RemoteFIN, Closed}`）；`protocol.OpenErrorCode.HTTPStatus/SOCKS5Reply`（protocol/errors.go:46-85）仅测试使用而真实映射在 proxy/errors.go（双份映射有漂移风险）；`config.Tunnel.AllowPlainWS` 只有告警（config/server.go:462-464）而服务端从不提供明文 ws；`model.Timeouts.WindowStall/DialTarget` 未消费（见 R-13）；`app.Client.statsTr`、`serverURLHost` 未使用。 | 上述符号 grep 无生产调用。 | 清理死代码；错误码映射保留唯一实现（协议层定义表、入口层只做协议转换），删除另一份或从协议层生成。 |
| **R-22** | P3 | `internal/tunnel/tunnel.go:541`（`sess.id = sess.transport + "-conn"`） | 未注册阶段的 session 日志 `session_id` 固定为 `"ws-conn"/"quic-conn"`，同类型多发连接无法区分；附件第 11 章要求结构化日志含可定位的 `session_id`、`epoch`。注册后 `sess.id = nodeID:plane` 又会与同一 (node, plane) 的历史会话重名（接管/重连时旧连接日志仍在外）。 | tunnel.go:541；`sess.id` 在 handshake 内重写（session.go:241 附近）。 | 生成一次性的 `session_id`（随机/递增），node/plane 放独立字段；日志 hook 使用该 id。 |
| **R-23** | P3 | `internal/tunnel/tunnel.go:494-526`（`handleConn` → `handshake`/`readyLoop`/heartbeat goroutine） | 会话处理 goroutine 没有 panic recover：registry/metrics/hook/协议解码任何一处 panic 会**终止整个服务进程**（Go 中未恢复的 goroutine panic 直接 crash）。nodeagent 的数据流/探测/egress 都有 recover，隧道侧缺失。规格「请求路径上不允许 panic」的精神应覆盖隧道。 | tunnel 包内无 `recover()`（grep）；对比 nodeagent/stream.go:63-68、probe.go:52-59、agent.go:921-925。 | `handleConn`/`readyLoop`/心跳循环入口加 `defer recover()` + ERROR 日志 + 关闭该会话（不要 crash 进程）；session FSM hook 内同样防御。 |
| **R-24** | P3 | `internal/audit/audit.go:60-99`（`Log` 每事件 open+write+fsync+close，且持 `s.mu`） | 审计写在**请求路径**上（ACL 拒绝、限流、认证失败都会写），每条记录一次 open+fsync；高 QPS 拒绝场景下 fsync（机械盘/云盘可达 ms 级）会成为延迟热点，并且持锁串行化所有审计写入。功能正确、耐久性满足规格，但吞吐风险明显。 | audit.go:80-98 在锁内 OpenFile/Write/Sync/Close。 | 保留 fsync 语义但改为「单 worker + 有界 channel 批量 append+定期 fsync」；或按级别异步（安全事件同步、访问类异步）。 |
| **R-25** | P3 | `internal/tunnel/tunnel.go:215-216、283-285、580-596` | 内部 map 无 TTL/上限：`takeovers`/`cooldown` 只在与同 key 重注册时 prune，节点再也不回来后残留；`nodeErrs` 有 1024 上限但无过期。规模小但长期运行/大量临时节点时是缓慢泄漏（与 R-14 同源）。 | tunnel.go:283-285 `takeovers: make(map[sessionKey][]time.Time)`、`cooldown`；`setNodeError` 上限 1024 但无 TTL。 | 定期（或每次注册时顺带）清理超过窗口/冷却期的 key；nodeErrs 加 TTL 或与节点记录一起回收。 |
| **R-26** | P3 | `internal/tunnel/session.go:230-259`（HELLO 字段校验）、`internal/registry/registry.go:251-304`（UpdateStats） | 节点自报字段多数未做范围校验：`hello.Weight` 任意 int（>0 即写进 registry，可被用来把 weighted 调度权重调到极大；客户端 config 限制 0..10000 但服务端不校验）、HELLO 的 `Alias/Region/ISPLabel` 无长度上限（受 64KiB 帧限制但会被面板/日志原样展示）、STATS 的 `BytesIn/Out/LatencyMS` 直接采信（`Inflight` 负数已 clamp）。`client_id` 不可信是设计前提，但这些字段会被运维界面/调度使用，建议服务端侧限幅。 | tunnel/session.go:230-259；registry.go:172-174（Weight）、267-279（Inflight/Latency）、271-272（Bytes 直接赋值）。 | 服务端对 weight 做 `1..10000` clamp、字符串截断（如 128B）、Latency/Bytes 做上限（防指标溢出）；非法 STATS/HELLO 记录安全日志。 |
| **R-27** | P3 | `internal/tunnel/tunnel.go:339-350`（服务端 drain 用运行时设置）、`internal/nodeagent/agent.go:490-491、1123-1128`（节点 drain 只取本地 `Options.Settings`/默认 10s；app 未向节点注入服务端 settings） | 排空时长不随服务端热设置下发：服务端 `timeouts.drain` 被面板调大（如 30s）后，节点 KICK 后仍按自身默认 10s 关闭连接，服务端等待的尾部流会被节点提前断开；反之调小时节点会多等。附件第 6 章 drain 为可配项。 | tunnel.go:339-350 读 `s.settings().Timeouts.Drain`；nodeagent 的 `drainTimeout` 来自 `resolveTimings(cfg, settings,...)`，而 `app.NewClient` 未传 `Settings`（nodeagent.Options.Settings=nil → `model.DefaultSettings()`）。 | HELLO_ACK.Settings 增加 `drain_ms`（以及 `write_block_ms`），节点按服务端策略执行；或文档说明 drain 以服务端强制关闭为准。 |
| **R-28** | P3 | `internal/certs/client.go:96-146`（pin/TOFU 只比 SPKI）、`internal/certs/server.go:365-378` 注释 | pin 模式客户端 `InsecureSkipVerify=true` + 只比较 SPKI，**不校验证书有效期**：过期/尚未生效的证书仍能通过 pin 校验（pin 语义下密钥未变即受信，代码注释已说明这是有意设计）。需在 README/安全说明中明确，避免运维误以为「pin 模式也会检查有效期」。 | certs/client.go:113-132；server.go:366-368 注释「pin mode ignores certificate validity」。 | 文档显式说明；如希望更严格，可在 SPKI 匹配后额外校验 `NotBefore/NotAfter`（会破坏「保留密钥无限续期」的便利，需权衡）。 |
| **R-29** | P3 | `internal/tunnel/session.go:625-646`（心跳丢失）、`:340-358`（接管冷却）、`internal/app/server.go:113、182-187`（health 检查是空实现） | 附件/H.4 要求的告警（节点离线、接管冷却、证书到期）目前只有 slog WARN：`internal/webhook`（M7）尚未接入隧道/证书事件；`/healthz` 的 registry/tunnel/geo 检查函数均返回 nil（只有进程存活语义），无法反映「隧道不可用」等关键组件故障。 | app/server.go:113、182-187、206；tunnel/session.go 各 WARN 分支。 | 把节点离线/冷却/证书到期接 webhook；health 检查至少反映 registry 可用性与最近一次 accept 错误。 |
| **R-30** | P3 | `internal/certs/server.go:463-475`（`currentFileStamp` = mtime+size）、`internal/certs/client.go:179-203`（TOFU 文件） | 证书热重载以 `mtime(ns)+size` 判变化，若用「同大小且 mtime 相同/精度不足」的方式原子替换会漏检（Linux ext4 ns 级、Windows 一般足够，低风险）；TOFU 文件若被误删/损坏需要人工删除或修文件才能恢复，错误信息已给出指引（可接受）。 | server.go:463-475；client.go:186-201。 | 可选：watch 同时比较 inode/文件内容 hash（每 1s 一次读文件成本高，可每 N 秒）；文档补充「替换证书时保留 mtime 变化」的注意事项。 |

---

## 3. 规格对照表

### 3.1 附件（tunnel-state-machine.md）逐章

| 附件章节 | 实现 | 结论 | 说明/证据 |
|---|---|---|---|
| 2.1 会话状态集 | `internal/fsm` + `internal/tunnel/session.go` | **符合** | 6 个状态齐全，`fsm.SessionTransitions` 覆盖迁移表；会话/流状态机唯一实现。 |
| 2.2 迁移表：握手 10s | `tunnel/session.go:210-227` | 符合 | `handshakeCtx=times.Handshake(10s)`；HELLO 5s。 |
| 2.2 认证失败/版本不兼容 → 关闭+审计 | `tunnel/session.go:243-265` | **部分** | 关闭与 slog 安全日志有；**未写审计**（R-18）。 |
| 2.2 心跳 15s/45s、degraded/恢复 | `tunnel/session.go:617-690` | 符合（服务端） | 缺失 1 次→degraded、3 次/45s→摘除；客户端侧有零余量问题（R-07）。 |
| 2.2 KICK → draining ≤10s → closed | `session.beginDrain:692`、`shut` | 符合 | KICK 后停止调度、等在途流归零或 10s 超时后以 code 0 关闭。**但服务停机路径被 R-01 破坏**。 |
| 2.2 接管 + 60s/3 次 + 10min 冷却 | `tunnel/session.go:313-393` | **部分** | 计数/冷却/告警齐全，但按平面维度计数（R-10）；冷却拒绝被节点致命化（R-04）。 |
| 2.3.1 注册前数据流拒绝+安全日志 | nodeagent 有；**服务端无** | **不符合**（服务端半边） | nodeagent/stream.go:22-57 有；tunnel 从不 AcceptStream（R-11）。 |
| 2.3.2 接管防抖 | 同上 | 部分 | R-10。 |
| 2.3.3 draining 不立即断 | `beginDrain` | 符合（逻辑） | 但真实停机路径失效（R-01）。 |
| 2.3.4 只关闭本会话流 | `session.teardown` → `st.fail` | 符合 | 流按 session 表失败，不误伤其他节点。 |
| 2.4/2.5 首连/2s 回退 | `nodeagent/selector.go`、`app/client.go` | **符合** | 2s 回退（可配 1–5s）、wss 成功 10min 后重探、连续 2 次成功+30s 间隔滞回、切回 60s 内失败回退；集成测试覆盖 UDP 黑洞回退。 |
| 2.6 重连/epoch+1/退避 1-2-4-8-10m | `registry.AttachPlane`、`nodeagent/agent.go` | 符合 | registry epoch 单调递增；nodeagent 全局 gate 退避序列正确（并发平面失败不会双跳）。 |
| 3.1 流状态集 | `internal/fsm` + `tunnel/stream.go` | 部分 | 状态集齐全；但 OPEN 超时的流没有真实 Stream/FSM 对象（FSM 只在 OPEN 成功后补记 SentOpen/AckOK），超时流无 `draining` 状态与状态日志。 |
| 3.2 迁移表 | 同上 | 部分 | 表项基本可走通；`draining` 的 30s 清理超时未实现（流 cleanup 为立即 detach，无 30s 兜底定时器）。 |
| 3.3 两种编码绑定 | `protocol/open.go` + `transport/*` | 符合 | OPEN 头双路径一致；QUIC 用 2B 长度前缀 + 反向首字节结果；WS 用帧；半关闭/RST/窗口语义齐。 |
| 3.4/3.5 正常 CONNECT/目标失败 | proxy（M3）+ nodeagent | 符合 | 节点拨号失败映射 1/2/3/7，proxy 映射 502/502/504/502；计入 `sched` 熔断（proxy `RecordResult`）。 |
| 3.6 半关闭 + linger 30s | proxy/relay.go（M3） | 符合 | `relayDuplex` 单向结束先 `CloseWrite`，等待另一向 ≤`linger`（默认 30s）。 |
| 3.7 RST/写超时/窗口停滞/流表满 | 多处 | **部分** | RST≠EOF ✓、写超时 30s ✓、流表满→overloaded ✓；**窗口停滞无显式实现/指标**（R-13）。 |
| 第 6 章超时总表 | 见 3.2 | **部分** | 握手/HELLO/心跳/OPEN/读头/空闲/写阻塞/linger/drain 均有；**窗口停滞 30s 缺实现**、**流表清理 5s 缺兜底定时器**、节点 drain 不随服务端热设置（R-27）。 |
| 第 7 章错误码表 | protocol/nodeagent/tunnel/proxy | **部分** | 1/2/3/5/6/7 全链路一致；**节点不可用被映射为 4→403**（R-03）；组为空 503 与「不回退全部节点」在 proxy 已 fail-closed（符合，见 3.2）。 |
| 第 8 章并发不变量 | 见 3.2 | 部分 | 1/2/3/6/7/8/10 基本成立；4 背压无死锁（有界队列+deadline）成立；5 epoch 实现但线上基本不可触发（每会话独立连接），且迟到帧计数策略有害（R-02）；9 未发现持锁网络 IO；详见 3.2。 |
| 第 9 章边界用例 | 见 3.2 | 部分 | 2/8/12 有测试；3/4/5/11 有测试；1/6/7/9/10 覆盖不足或失效（R-01/R-02/R-13/R-16）。 |
| 第 10 章停机排空 | `tunnel.shutdown` | **不符合** | R-01：listener 先关，排空失效。 |
| 第 11 章埋点 | tunnel/metrics | **部分** | 7 个指标中 6 个有；`tunnel_window_stalls_total` 从不 Inc；`session_state` 日志字段齐全但 session_id 不唯一（R-22）。 |
| 第 12 章测试矩阵 | 各包测试 | 部分 | 「同一组用例跑 QUIC/WS 两遍」已实现（transport conformance suite）；背压/错误映射/状态机覆盖较好；缺口见第 5 节 J 项。 |
| 第 13 章禁止事项 | 全局 | 基本符合 | 未发现同 goroutine 先写后读、多 goroutine 并发写同一传输连接（WS 单写者、QUIC per-stream writeMu+control 串行）、流 ID 复用、RST 代替正常关闭、热路径 `time.After`（M2 范围）；`client_id` 未当身份（但 wildcard token 弱化了 token 本身，R-06）。 |

### 3.2 主规格关键条目

| 规格条目 | 实现 | 结论 | 说明 |
|---|---|---|---|
| A.1 传输抽象 + 双实现 | `transport/transport.go` | 符合 | Transport/Dialer/Listener/Stream/ControlStream 接口 + QUIC/WS。 |
| A.2 同端口 443 UDP/TCP | app/server.go | 符合 | QUIC 同 `listen_addr` UDP + TCP TLS listener。 |
| A.5 2s 回退/退避/10min 重探/滞回 | nodeagent/selector.go | 符合 | 见 2.4/2.5 行；集成测试覆盖。 |
| A.6 多平面 1–8、哈希分发 | agent planes + `tunnel.pickSession` | 符合 | `planes` 越界校验；流按 trace hash/round-robin 分发；单平面故障隔离有测试。 |
| A.7/8 WS 帧层 + 窗口（256KiB/8MiB/阈值） | `transport/ws_conn.go`、`protocol` | 符合 | 帧边界 0/64KiB/65KiB 有测试；窗口回补阈值 32KiB；连接上限 8MiB；发送方不越窗（强制校验）。 |
| A.9 两条路径通用语义（半关闭/保活/异常回收/版本化） | transport + tunnel + nodeagent | 符合 | 半关闭/RST/关闭回收/版本校验均有实现与测试；回收依赖上层关闭（见 R-20 边界）。 |
| A.10 STATS 每 10s | nodeagent/session.go | 符合 | 周期 10s + STATS_REQ/出口变化即时上报。 |
| A.11 QUIC 0-RTT/datagram/CC/MTU/qlog | transport/quic.go | **部分** | datagram 开启、DPLPMTUD 默认、qlog 可配（无新增依赖）；**0-RTT 未在装配层启用**（R-16）；CC 不可配（quic-go v0.48 已移除公开 API，代码注释说明，可接受）。 |
| C.4 fail-closed（组内无节点→503，绝不回退全节点） | `groups.Candidates` + `proxy.resolveCandidates` | **符合** | 空 groups=全节点；非空组无命中→空集→`errNoCandidates` 503/0x04；proxy 测试覆盖。 |
| D.5 透明重试与响应提交点 | proxy（M3） | 符合 | 未提交前换节点重试一次（排除已试节点），提交后不重试；`retryable` 标记驱动。 |
| D.6 全部不可用→502/503 | proxy 映射 | **部分** | 组为空/节点过载→503 ✓；**节点离线/禁用被映射 403**（R-03）。 |
| G.3 节点鉴权（每节点令牌/mTLS、常量时间、即时吊销踢下线） | nodesauth | **部分** | 常量时间比较 ✓；吊销/踢下线 `KickNode` 语义 ✓；**但吊销 `Authenticate.Revoke` 在生产代码无调用入口**（面板/API 未接线，M6 在途），默认 wildcard 令牌弱化身份（R-06），mTLS 未绑定身份（R-05）。 |
| G.5 ws:// 仅回环 + 告警 | config/client.go | 符合 | 客户端 `ParseServerURL` 对 http/ws 强制回环；`allow_plain_ws` 服务器侧为死配置（R-21）。 |
| I.1 三层覆盖 env>yaml>default | config/config.go | 符合 | 反射遍历 yaml 路径映射 `NP_*`；客户端显式环境变量；示例配置实测通过。 |
| I.4 节点 ID 缺省自动生成并持久化 | identity + app/client.go | 符合 | 128-bit 随机 + 原子写 0600；损坏自动重建。 |
| I.5 客户端行为参数固定、写了要告警忽略 | config/client.go:98-147 | 符合 | 顶格固定键检测并警告忽略；`TestClientFixedKeys` 类测试；注意只覆盖顶层键（嵌套同名键不在检测范围，影响低）。 |
| I.6 运行态对象原子持久化 + .bak 回退 | store + registry/rules/groups/auth | 符合 | temp+fsync+rename，损坏回退 `.bak`；文件 0600。 |
| K.1 三种证书模式 | certs | 符合 | pin/ca/insecure；ca 强制显式证书、insecure 仅回环监听且需显式承认风险。 |
| K.2 自签 ECDSA P-256/1y/SAN/私钥 0600/过宽拒绝启动 | certs/identity.go | **部分** | 生成与权限写入 0600 ✓；POSIX 权限过宽拒绝 ✓；**Windows 只告警**（R-09）。 |
| K.3 SPKI pin 计算/格式/hex 归一化 | certs/pin.go | **符合** | `RawSubjectPublicKeyInfo` §256 + standard base64，`sha256/` 前缀；hex/URL/base64/带/不带 padding 全部归一化；单测覆盖。 |
| K.4 多 pin + pin_next + 面板展示/安装命令不带 token | certs + tunnel + panel | **部分** | 多 pin 客户端校验 ✓、HELLO_ACK 下发 pin_next ✓、面板展示 ✓；**面板 rotate 不更新 pin_next**（R-15）；安装命令是否带 token 属 M6，需在合并后核对。 |
| K.5 TOFU 显式开启/告警/持久化 | certs/client.go | 符合 | 默认关闭；启用即告警；首连写盘（0600）后强校验；损坏文件失败关闭。 |
| K.6 pin 不匹配硬失败且错误含期望+实际+建议 | certs/pin.go、client.go、app/client.go:156-164 | 符合 | `PinMismatchError` 含期望/实际/中文建议；app 通过 `certs.IsPinMismatch` 注入致命分类；集成测试 `TestPinMismatchIsFatal`。 |
| K.7 ca 模式 RootCAs/ServerName/热重载/到期告警 | certs | **部分** | RootCAs/自定义 CA/ServerName ✓、热重载原子指针换证书 ✓（已有连接不受影响）；**到期告警无周期检查**（R-08）。 |
| K.9 除 insecure 外禁止 InsecureSkipVerify | certs/client.go | 符合（有说明） | pin 模式因 Go 要求必须 `InsecureSkipVerify=true` 并自实现 `VerifyPeerCertificate`（注释说明、测试断言）；ca 模式显式置 false；insecure 显式告警。`SessionTicketsDisabled=true` 的理由成立（恢复的会话不回调 `VerifyPeerCertificate`，必须禁用会话恢复保证每次都 pin 校验）。 |
| 验收 #23 私钥 0644 拒绝启动 | certs/identity.go | **部分** | POSIX 满足；Windows 仅告警（R-09）。 |
| 验收 #16 回退后 10min 不再试 QUIC | nodeagent/selector.go | 符合 | `onWSEstablished` 把 `quicNextTry` 推到 10min 后；集成测试覆盖回退。 |
| 验收 #19–21 pin/轮换 | certs 单测 | 符合 | 多 pin 轮换窗口 `TestPinClientMultiplePinsRotationWindow`、同密钥重签 pin 不变 `TestSameKeyReissueKeepsPin`；仅面板动态 pin_next 有缺口（R-15）。 |

---

## 4. 建议优先修复的 Top 5

1. **R-01 优雅停机失效（P1）**：SIGTERM 时先关 listener 导致在途流全部中断，附件第 10 章/验收 #14 不成立 —— 调整 shutdown 顺序，真实传输下补停机测试。
2. **R-02 WS 迟到帧计数误杀长连接（P1）**：正常 RST 引发的「未发完 DATA 在 RST 之后到达」被当协议违规，累计 100 次即断整条连接 —— 加已关闭流墓碑，静默丢弃。
3. **R-05 mTLS 身份未绑定 client_id（P1 安全）**：任一受信证书可冒充任意节点 —— 校验证书与 node_id 映射，`mtls` 参数来自连接事实。
4. **R-06 默认 wildcard 共享令牌（P1 安全）**：默认部署节点身份退化为共享秘密，且可放大 R-14 的无界注册 —— 默认绑定 per-node 令牌，wildcard 显式 opt-in。
5. **R-03 节点不可用返回 403（P1）**：与附件第 7 章冲突，客户端/运维被误导 —— tunnel 侧改 503/timeout 语义，CodePolicy 仅用于策略拒绝。

> 紧随其后：R-04 接管冷却被客户端致命化（双 agent 场景无法按 10min 冷却自愈），建议与 R-03 一起在本迭代修。

---

## 5. 未发现问题 / 已核实通过的方面（便于 lead 决策）

### 5.1 逐条清单结论（A–J）

| 清单项 | 结论 | 关键证据 |
|---|---|---|
| A1 每条流恰好一次资源释放 | **基本 pass**（1 处边界 P2 R-20） | `tunnel.Stream.closeOnce/detachStream`；`wsStream.releaseOnce`；`wsConn.closeOnce`；`session.teardownOnce/shutOnce/drainOnce`；nodeagent `streamEntry.abortOnce`/`session.shutdownOnce`；测试 `TestBidirectionalFin`、`TestConnectionClose`、`TestWSCleanup`、`TestNoGoroutineLeakAfterClose` 覆盖。 |
| A2 写必须串行 / 控制帧优先 | **pass**（附 R-02 的队列有序性注意） | WS 单 writer goroutine（`writeLoop`：先清空 ctrlCh 再混合 select）；QUIC per-stream `writeMu` + control `wmu`；session `sendMu`；控制帧星形不饿死（每轮最多插 1 个数据帧）。 |
| A3 读写 goroutine 分离 | **pass** | WS `readLoop`/`writeLoop`；QUIC 由 quic-go 提供收发；relay 双向各一 goroutine（nodeagent/stream.go:196-204、proxy/relay.go）。 |
| A4 背压不死锁 | **pass**（设计成立；极端 TCP 背压下表现为整体阻塞而非死锁） | `enqueue` 有界队列 + deadline + `done` 唤醒；`acquireSendCredit` 等待 channel 广播/截止；`consumeReceive` 在锁外入队；大文件 2MiB 慢消费者 conformance 测试通过（`testLargeTransfer`）。 |
| A5 流 ID epoch、迟到帧丢弃 | **partial**（R-02） | 实现存在（`protocol.MakeStreamID/SplitStreamID`、`wsConn.SetEpoch/dispatch` 过滤），但每会话独立连接使「旧 epoch 迟到帧」几乎不可自然出现；真正会发生的「已关闭流迟到帧」却按连接致命计数（R-02）。 |
| A6 FIN 之后仍可收数据 | **pass** | 半关闭后仍可读/写；`TestHalfClose`、`TestHalfCloseRemoteFINKeepsWrites`；隧道 `Stream.Read` EOF 只结束读方向。 |
| A7 RST ≠ EOF | **pass** | `ErrStreamReset/StreamResetError`；`mapStreamErr` 保留 remote/code；`tunnel.Stream.Read` 会话失败返回 error 而非 EOF；`TestReset`。 |
| A8 活跃流计数守恒 | **pass** | 隧道 `reserveStream(+1)/detachStream(-1)/releaseStreamReservation(-1)` 成对；nodeagent `addStream/removeStream`；`TestConcurrentDialStreams`、`TestGracefulCloseDrains` 断言归零。 |
| A9 不持锁做网络 IO | **pass（M2 范围）** | 逐点核对：`session.register` 在 `rejectHello` 前解锁；registry/groups/rules 锁内无网络；transport 队列锁内无 IO；`fsm` hook 锁内仅日志/计数；`windowMu` 内不写网络。未发现 M2 层持锁网络调用。 |
| A10 热路径不 time.After / 新建 bufio | **pass（M2 范围）** | M2 生产路径无 `time.After`（仅 shutdown、测试辅助）；relay 32KiB `sync.Pool` 复用；WS 帧编码每次 append 分配（可接受，非 bufio）；quic `withCtxDeadline` 每次短生命周期 goroutine（P3 级优化点，未列入主表）。 |
| B 会话/流 FSM 与附件 2.2/3.2 | **partial** | 见 3.1；主要缺口：服务端注册前数据拒绝（R-11）、draining 清理 30s 兜底缺失、审计（R-18）、接管维度（R-10）、冷却客户端语义（R-04）。 |
| B 超时表（10s/5s/15s×3/10s/10s/30m/30s/30s/30s/10s/5s） | **partial** | 10/5/15×3/10/10/30m/30s/30s/10s 通过；**窗口停滞 30s 与流表清理 5s 缺实现**（R-13），节点 drain 不同步（R-27）。 |
| C 错误码映射一致性 | **partial** | OPEN_ERR 8 码、HTTP/SOCKS5 映射与附件第 7 章一致（protocol/errors.go 与 proxy/errors.go 双份但值一致）；**唯一不一致：节点不可用→4/403**（R-03）；组为空 503 语义在 proxy 正确 fail-closed，未回退全节点；SOCKS5 组为空用 0x04 host unreachable（符合）。 |
| D certs（SPKI/多 pin/pin_next/TOFU/权限/ca/热重载/会话恢复） | **pass（细节问题见 R-08/R-09/R-15/R-28）** | SPKI 用 RawSubjectPublicKeyInfo ✓；多 pin 常量时间比较 ✓；pin 不匹配含期望+实际+建议 ✓；TOFU 持久化 0600 + 失败关闭 ✓；`SessionTicketsDisabled` 理由成立 ✓；ca 模式 RootCAs/ServerName ✓；热重载原子替换且老连接不受影响 ✓；`InsecureSkipVerify` 仅 pin（必需+说明）/insecure（显式）使用 ✓。 |
| E transport（帧边界/窗口/半关闭/RST/控制优先级/epoch/协议错误/泄漏/0-RTT/qlog） | **partial** | 0/64KiB/65KiB 帧、窗口耗尽/回补/写 deadline、半关闭/双 FIN/RST、控制优先、协议错误关连接、goroutine 泄漏测试均通过；**0-RTT 未启用**（R-16）；**迟到帧策略缺陷**（R-02）；qlog 无新增依赖、tracer 关闭 writer 无 fd 泄漏。 |
| F nodeagent（2s 回退/退避/10min 重探/KICK/半关闭/linger/错误码/致命分类/STATS/PROBE/流表/ctx 退出） | **pass（R-04/R-07/R-12 为偏差）** | 回退/退避/滞回/重探/回退翻转有实现+单测+集成测试；KICK shutdown 优雅退出、KICK replaced 冷却；半关闭+写超时+RST；错误码 1/2/3/7 映射；`ctx` 取消优雅退出；STATS 10s/PROBE/DNS 4KiB 上限；流表上限 1000→OPEN_ERR 5；fatal（pin/auth/version）不无限重连。 |
| G tunnel（注册前拒绝/接管/epoch/心跳/DialStream 预留/OPEN 超时/排空/Kick/Close 幂等/metrics nil/Auth nil） | **partial** | 预留、OPEN 10s 超时→504、每节点 1000 流→overload、KICK/Close 幂等、metrics nil 安全（测试 `TestNoAuthAndNilMetrics`）、Auth nil 语义（告警+放行，仅测试用）均通过；**注册前拒绝缺失（服务端，R-11）**、**排空被 R-01 破坏**、接管维度（R-10）。 |
| H 安全与日志 | **partial** | 未见 token/password/hash 进入日志/指标标签/错误响应（`logx.Redacted`、`audit.redact`、metrics 凭据 allowlist、错误消息不含凭据）；audit 事件无明文密码（测试）；**缺口：隧道接入失败未写审计（R-18）、默认 wildcard token（R-06）、mTLS 未绑定（R-05）**；请求路径 panic：proxy 有 recover、nodeagent 有 recover；**tunnel 会话无 recover（R-23）**；外部输入限长：HELLO 帧/域名/client_id/面板字段基本有，HELLO Weight/STATS 未限幅（R-26）。 |
| I 配置（三层覆盖/弱密钥/私钥权限/tls 组合/客户端固定键/示例配置） | **pass（R-09/R-21 边角）** | env>yaml>default 实测与代码核对通过；弱密钥/示例令牌拒绝（`CheckWeakSecrets`，`allow_insecure_defaults` 显式豁免）；`tls.mode` 组合校验完整（insecure 限回环、ca 要证书、client_auth=require 需 ca 模式+ca_file、nodes.mtls 联动）；客户端固定行为键检测+告警忽略；**两个示例配置实测 `-check-config` 通过**；`allow_plain_ws` 为死配置（R-21）。 |
| J 测试可信度 | **partial** | 覆盖强的部分：transport 共享 conformance 套件同时跑 QUIC/WS、帧边界、窗口回补/写 deadline、半关闭/双 FIN/RST、goroutine 清理；tunnel 注册/拒绝/接管/冷却/心跳/协议违规/并发 Dial/优雅关闭；certs pin/多 pin/轮换/TOFU/权限/热重载；nodeagent 回退/退避/致命/半关闭/流表/探测；无 flaky 复现（-count=2 通过）。**缺口**：(a) 优雅停机用 fakeListener，掩盖 R-01；(b) 心跳零余量未被覆盖（8ms PING vs 20ms 超时，余量过大）；(c) 迟到帧只测「注入未知流」，未测「RST 与队列中 DATA 竞争」；(d) 窗口停滞指标/0-RTT 无测试；(e) 集成测试 `freePort` 先探测 TCP 后用同端口 UDP（freePort 注释自认可能碰撞），CI 并发下有 flaky 风险；(f) certs 测试用 50–100ms `time.After` 等待（server_test.go:441-489），负载高时可能 flaky；`-race -count=2` 本轮未复现。 |

### 5.2 明确未发现问题的方面

- **SPKI pin 计算**：使用 `x509.Certificate.RawSubjectPublicKeyInfo` 的 SHA-256，不是整张证书；多 pin 常量时间比较；hex/URL-safe/无 padding 归一化；pin 不匹配错误同时含期望与实际（含中文排查建议）。
- **TOFU**：默认关闭、显式开启有醒目告警、首连写 0600 且失败即中止连接、损坏文件 fail-closed、与显式 pin 同时配置时 pin 优先。
- **私钥生成**：ECDSA P-256 / 365 天 / SAN 分类（IP 自动归类，非法 IP 报错）/ 私钥 0600 原子写 / 半套文件拒绝自动重建（避免 pin 意外变化）。
- **ca 模式**：RootCAs 加载（PEM/DER）、ServerName 覆盖、证书/私钥成对校验、ca 模式不自动生成自签证书。
- **热重载原子性**：`atomic.Pointer[loadedIdentity]` 替换，新握手用新证书、已建立连接不受影响；重载失败保留旧证书并记录 `LastError`。
- **WS 帧层边界**：0 字节 DATA、64KiB、>64KiB 帧（协议错误关连接）、多余 trailing bytes、未知帧类型、控制帧在数据流上出现 → 均按协议错误处理；读消息大小限制由 gorilla 层先行拦截。
- **WS 窗口流控**：初始 256KiB/连接 8MiB、消费 32KiB 阈值回补、发送方越窗 → 协议错误；大传输/慢消费者测试通过。
- **单写者/读写分离/队列背压**：见 A2/A3/A4。
- **RST/FIN 语义**：RST 不等于 EOF；FIN 后仍可收数据；双向 FIN 只释放一次；不把会话断开当流 EOF 上报入口。
- **节点侧注册前数据拒绝**：nodeagent 在 HELLO 前启动 accept 循环，非 ready/draining 状态数据流会被 `ReadOpen` 后 Reset 并记安全日志（与附件 2.3.1 的客户端半边一致）。
- **接管流程**：同 (node,plane) 新连接到达 → 旧会话 KICK(replaced) → draining，注册表 epoch+1，新会话 ready；旧会话 teardown 不会 Detach 新平面。
- **多平面**：流按 trace hash/round-robin 分发，单平面故障隔离，接管/心跳每平面独立。
- **心跳/失联**：服务端正确（15s 缺失→degraded、45s→摘除并 fail 该会话全部流）；客户端有 R-07 的零余量问题（不是失联判定错误）。
- **错误码（OPEN_ERR 与 HTTP/SOCKS5）**：1/2/3/5/6/7 全链路与附件第 7 章一致；组为空 fail-closed 为 503/0x04；节点过载 503/0x01；协议不支持 405/0x07。
- **常量时间令牌比较 + SHA-256 摘要持久化 + 吊销优先**：nodesauth 实现正确（未在实现文件/日志中出现明文令牌；比较循环不做提前退出）。
- **JSON 原子持久化**：temp+fsync+rename、`.bak` 回退、权限 0600；认证状态/节点覆盖/规则/组/设置均使用。
- **配置**：三层覆盖、弱密钥拒绝、tls 模式组合校验、客户端固定键忽略+告警、示例配置可校验通过、节点 ID 自动生成并持久化。
- **日志安全**：`logx.Redacted` 黑名单与 `audit.redact` 双保险；session/pin 日志中未出现令牌/密码/哈希；指标凭据标签有 allowlist。
- **qlog 依赖**：使用 quic-go 自带 `qlog` 子包（无新增 module），tracer 会在连接关闭时关闭文件（无 fd 泄漏）。
- **热路径分配**：M2 生产路径未发现 `time.After`；relay 有 `sync.Pool` 复用 32KiB 缓冲；WS 帧编码按帧分配（后续可加 Pool，属 P3 优化）。
- **集成测试**：QUIC 主用注册、仅 WS 启用、UDP 被丢弃 2s 回退、pin 不匹配致命失败四个 M2 关键场景均有进程内端到端测试并通过。

---

## 6. 附：审查文件清单（只读）

`internal/{protocol,fsm,certs,transport,tunnel,registry,nodesauth,nodeagent,app,config,stats,groups,rules,audit,settings,identity,health,store,logx,metrics,model,proxy(错误映射部分),integration,version}`、`cmd/proxygw-server`、`cmd/proxygw-client`、`go-multi-node-proxy-prompt.md`、`tunnel-state-machine.md`、`config.{server,client}.example.yaml`。

*（本报告为唯一写入文件；未改动任何实现代码。）*
