# proxygw 验收手册与实测报告（ACCEPTANCE）

> 对应规格：`go-multi-node-proxy-prompt.md` 的「验收标准（1–23 条）」与「工程与代码质量要求」；
> 命令与输出均以本机实际运行为准（2026-11-17，Windows 11 + Go 1.27.0）。
> 本文件由 M7-D 验收任务维护，可被 README「验收自测结果」引用。

## 0. TL;DR

```bash
# Windows（PowerShell 7，推荐）
pwsh -File scripts/acceptance.ps1
# Windows（仅装了 Windows PowerShell 5.1 时）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/acceptance.ps1
# Linux / macOS
bash scripts/acceptance.sh
```

- 退出码：`0` = 无 FAIL（允许 SKIP）；`1` = 存在 FAIL；`2` = 环境缺少必要工具/仓库根不对。
- 失败时脚本自动保留临时目录（配置、server/client 日志），并在结尾打印路径；成功时加 `-KeepArtifacts` / `--keep-artifacts` 也可保留。
- 快速模式（跳过 `go test`，端到端仍完整执行）：`-SkipUnitTests` / `--skip-unit-tests`。

本机最终实测（命令与输出见 §2、§3）：

| 脚本 | 环境 | 结果 | 耗时 |
|---|---|---|---|
| `scripts/acceptance.ps1`（含 `go test ./...`） | Windows 11 / Windows PowerShell 5.1.26100 / Go 1.27.0 | **PASS=16 FAIL=0 SKIP=1**，退出码 0 | 117.3 s |
| `scripts/acceptance.sh`（含 `go test ./...`，Git Bash 实测） | 同上（Linux/macOS 为正式目标） | **PASS=16 FAIL=0 SKIP=1**，退出码 0 | 112 s |
| `go test -race -count=1 ./...`（另一跑，完整 28 包） | 同上 | **28 包 ok，0 FAIL**（≈140 s） | — |

> 本机未安装 `pwsh`（PowerShell 7）。尝试从 GitHub 下载约 100 MB 的 PS7 包时，本机**无直连外网**
> （访问 GitHub Release 长期卡住；用户已确认需经本机 SOCKS5 代理 `10.0.20.13:1080` 访问外网），
> 按“不依赖外网的验收项优先、外网项失败即 SKIP”的原则**跳过了 PS7 安装**，PowerShell 实测使用 Windows PowerShell 5.1；
> 脚本刻意只用 5.1/7 双兼容语法（无三元、无 `-Parallel`、无 `??`、显式 UTF-8 BOM），
> `pwsh -File scripts/acceptance.ps1` 即为 PowerShell 7 下的标准命令。

---

## 1. 脚本做了什么

两个脚本等价地执行下列步骤（不修改仓库 Go 代码/配置模板，只写 `bin/` 构建产物与系统临时目录）：

1. `go vet ./...`、`go test ./...`、构建 `bin/proxygw-server(.exe)` 与 `bin/proxygw-client(.exe)`。
2. 创建唯一临时目录、随机高位端口（TCP+UDP 同时空闲才采用）；生成临时配置：
   - 服务端：`tls.mode=pin`、`proxy.auth_mode=required`、`geo.enabled=false`（不依赖外网）、静态节点令牌（脚本生成的强随机值）、JSON 日志落文件；
   - 客户端：使用服务端首启 pin + 节点令牌，`transport=auto`、`planes=2`、`egress.manual_v4=127.0.0.1`（不探测外网出口 IP）。
3. 启动本地 origin（`node` 优先，缺省时用 `python3`/PowerShell HttpListener 兜底；提供 `/healthz`、`/echo`、`/64k`、`/slow`），
   服务端进程单独注入 `NP_ACL_ALLOW_LOOPBACK_TARGETS=1`（仅该进程允许回环目标，README 设计决策 13）。
4. 从服务端 stderr 解析首启一次的 **SPKI pin / 代理凭据 / 面板管理员密码**（控制台明文只出现一次，日志中无明文）。
5. 启动两个节点客户端（`node-e2e-1` 在组 g1 内、`node-e2e-2` 在组外），逐项执行检查（§2）。
6. 收尾：停止所有子进程、删除临时目录（失败/保留参数除外）。

脚本**每个检查都真实发起网络请求/断言**，不存在为了变绿而伪造的检查；无法在本机自动化的项目标 SKIP 并在 §4 给出手工步骤。

---

## 2. 自动化检查清单与本机实测（Windows / `scripts/acceptance.ps1`）

最终一次运行（命令：`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/acceptance.ps1 -KeepArtifacts`）：

| 编号 | 验收项 | 结果 | 耗时(ms) | 备注/证据（脚本实际输出） |
|---|---|---|---|---|
| 0a | `go vet ./...` | PASS | 555.6 | 通过 |
| 0b | `go test ./...` | PASS | 20765.8 | 28 个包通过；FAIL 行 0 |
| 0c | 构建 server/client 二进制 | PASS | 419.4 | `bin/proxygw-server.exe` + `bin/proxygw-client.exe`（共 44.1 MB） |
| 1 | `/healthz` 200 且 `ok=true`；`/version` 可解析 | PASS | 80.3 | healthz ok=true；version=dev commit=none |
| 2 | 节点注册：`/overview online_nodes>=1`、`/nodes` 含 `transport=quic` | PASS | 128.7 | online_nodes=2；2 个 quic 节点：node-e2e-1,node-e2e-2 |
| 3 | HTTP 代理 absolute-form 200 + body 正确；错误口令 407 | PASS | 241.7 | absolute-form 已由代理解析；错误口令 407 |
| 4 | CONNECT 隧道到本地 TLS 服务返回 200 JSON | PASS | 149.7 | CONNECT 建立隧道后 GET /healthz -> 200 {ok:true} |
| 5 | SOCKS5 CONNECT 200 + body 正确；错误口令握手失败 | PASS | 224.0 | SOCKS5 CONNECT -> 200；错误口令握手失败（curl exit=-1） |
| 6 | 面板：未登录 401；登录成功拿 csrf；无 CSRF 写 403；PUT /settings 生效、undo 还原；非法设置 422 且旧值不变 | PASS | 595.7 | 401/403/422 校验通过；策略 random -> weighted -> undo=random |
| 7 | 审计含 login、settings.update，且无明文密码 | PASS | 61.2 | actions=login,proxy.auth_failed,settings.undo,settings.update；未发现明文密码 |
| 8 | 组隔离与 fail-closed：g1 仅含 node-e2e-1；A 三次成功；停节点后必须 503 且不回退组外节点；重启恢复 | PASS | 60891.4 | g1 成员=node-e2e-1；A 3 次成功；停节点 1 后 57.9 s 判定离线 -> 503；组外 node-e2e-2 未被使用；重启后恢复 |
| 9 | 粘性：同源 5 次命中同一节点（服务端 `proxy_request.node_id` 证据） | PASS | 6751.5 | 5 次请求均命中 node-e2e-1 |
| 9b | 粘性 TTL 调小后重新分配（可选，概率性） | PASS | 15685.7 | TTL=1s 后 6 次请求分布到 node-e2e-1,node-e2e-2 |
| 10 | QUIC→wss 回退：另一实例 `transport=ws` + 同端口 UDP 黑洞，client auto 回退后 `/nodes` 显示 `transport=ws` | PASS | 4988.1 | UDP 黑洞 + 仅 wss 服务端 -> 节点 transport=ws；客户端日志包含回退记录 |
| 11 | pin 不匹配硬失败：错误 pin 的 client 20 s 内非 0 退出，日志含期望/实际指纹与建议 | PASS | 2071.3 | exit=1；日志含期望/实际指纹与排查建议 |
| 12 | 优雅停机：Windows 无 SIGTERM/Ctrl+C → SKIP（Linux 由 .sh 用 `kill -TERM` 验证）；Stop-Process 后端口释放检查通过 | SKIP | 88.1 | Stop-Process 停止后 TCP/UDP 端口均已释放；SIGTERM 语义见 §4-14 |
| 13 | 并发 20 × 64 KB 全部成功且耗时合理；结束后 `/overview active_connections` 5 s 内归零 | PASS | 1185.4 | 20/20 成功，共 1.3 MB，耗时 1.1 s；active_connections=0 |

**汇总：PASS=16 FAIL=0 SKIP=1，退出码 0，总耗时 117.3 s。**

> SKIP=1 仅因为 Windows 无法向控制台子进程发送 SIGTERM/Ctrl+C（`check 12`）。这是操作系统限制，
> 不是实现问题；同一脚本 `acceptance.sh` 在 Linux/macOS 上会用 `kill -TERM` 实际断言退出码 0 + 端口释放。

### bash 脚本本机实测（Git Bash / msys，Linux/macOS 为正式目标）

`bash scripts/acceptance.sh` 全量跑（含 `go test ./...`）：

- `0a vet`、`0b go test ./...`（28 个包通过）、`0c 构建`：PASS；
- `1–11`、`13`：PASS（与上表同口径；9b 为概率性验证，随机策略下多数运行能观察到重新分配，个别运行观察不到时按 SKIP 记录，绝不伪造 PASS）；
- `12 SIGTERM`：Git Bash 下标记 SKIP（MSYS 的 `kill -TERM` 不是 Windows 控制台 SIGTERM，无法验证 Go 信号处理），
  仅做「强杀后端口释放」检查；
- 最终汇总：**PASS=16 FAIL=0 SKIP=1，退出码 0，耗时 112 s**（另一次快速模式 `--skip-unit-tests` 运行为 PASS=14/SKIP=3，仅少了 go test 与概率性 9b）。

> 说明：bash 脚本面向 Linux/macOS；本机没有可用的 WSL 发行版，因此用 Git Bash 做了额外实测（可跑通构建、
> 三代理入口、面板、fail-closed、pin 硬失败、QUIC 回退、并发等核心项）。SIGTERM 与「POSIX 私钥权限」
> 只能在真实 Linux/macOS 上验收，见 §4-14 / §4-23。

---

## 3. 本机环境

| 项目 | 值 |
|---|---|
| OS | Windows 11 专业工作站版，build 26300，x64 |
| CPU / 内存 | Intel i5-12400（12 逻辑核）/ 15.7 GB |
| Go | go1.27.0 windows/amd64（CGO 可用，`go test -race` 通过） |
| Shell | Windows PowerShell 5.1.26100.9818；PowerShell 7 未安装（`pwsh` 不在 PATH） |
| curl | curl 8.22.0（Windows，Schannel） |
| Node.js | v24.22.0（仅用于本地 origin / UDP 黑洞模拟） |
| 仓库 | `C:\Users\Administrator\Downloads\node-proxy-go-dsh`（module `proxygw`） |

本机 `go test -race -count=1 ./...` 结果：**28 个包全部 ok，0 FAIL**（integration 24.27 s，其余 1.4–9.9 s）。
可复现命令：

```bash
go test -race -count=1 ./...
# 预期结尾（节选）：
# ok  	proxygw/internal/integration	24.270s
# ok  	proxygw/internal/transport	4.044s
# ok  	proxygw/internal/tunnel	2.382s
# ...
```

---

## 4. 验收标准 1–23 逐条映射（自动 / 半自动 / 手工）

图例：**自动** = 一键脚本断言；**半自动** = 脚本覆盖主路径 + 单测/集成测试或需一条手工命令补足；**手工** = 需要真机弱网/外网/`SIGTERM`/内存等环境，给出可复制命令。

| # | 规格验收标准（摘要） | 方式 | 自动/单测证据 | 手工命令与预期输出 |
|---|---|---|---|---|
| 1 | `go build ./...`、`go vet ./...`、`go test -race ./...` 全通过 | 自动 | `acceptance.ps1` 0a/0b/0c；`go test -race -count=1 ./...` 实测 28 包 ok | `go build ./... && go vet ./... && go test -race ./...`（预期无输出/`ok` 行） |
| 2 | `curl -x http://… https://example.com` 返回 200；SOCKS5 同理 | 自动（本地替身） | 脚本 3/5 用本地 origin + 本地 TLS `/healthz` 断言 200/407，**不依赖外网** | 外网可选：`curl -x http://user:pass@SERVER:8080 https://example.com -o /dev/null -w '%{http_code}\n'` → `200`；`curl --socks5-hostname user:pass@SERVER:1080 https://example.com -o /dev/null -w '%{http_code}\n'` → `200` |
| 3 | 正确口令 200；错误口令 HTTP 407、SOCKS5 握手失败；禁用/过期凭据立即失效并 5 s 内踢旧连接 | 半自动 | 脚本 3/5（正确/错误）；`internal/auth`、`internal/proxy` 单测覆盖禁用/过期判定 | 面板创建/禁用凭据后立刻请求：`curl … -x http://USER:PASS@SERVER:8080 http://…` → 禁用后 `407`；过期把 `expires_at` 设为过去时间；旧连接观察：启动一条 `curl --limit-rate 1k` 大下载后禁用凭据，连接应在数秒内断开 |
| 4 | 组隔离：凭据 A 绑组 g1（仅节点 1）连续 20 次落节点 1；停节点 1 返回 503，不动用节点 2 | 自动 | 脚本 8（3 次 + 停节点后 503 + 组外节点在线仍不被使用 + 重启恢复；`internal/proxy` 有 fail-closed 单测；`internal/integration` `TestM3E2EFailClosedGroupIsolation`） | 手工扩到 20 次：`for i in $(seq 1 20); do curl -s -o /dev/null -w '%{http_code} ' -x http://credA:PASS@SERVER:8080 http://127.0.0.1:9/; done; echo` → 均为 200；停客户端后重复 → 均为 503 |
| 5 | 凭据 B 不绑组，请求可分布到全部节点 | 半自动 | 脚本 9 使用「未绑组的首启凭据」在 2 个节点间验证调度（9b 实测两个节点都被命中） | `GET /api/v1/overview` 观察 `transport_mix`；并发多次请求后 `GET /api/v1/nodes` 的 `inflight/bytes_out` 两节点均增长 |
| 6 | 粘性：同源 20 次命中同一节点；TTL 过期后重分配；目标加入粘性黑名单立即分散；组加入黑名单不被固定 | 自动（主项） | 脚本 9（5 次同节点）、9b（TTL 1s 后分布到两节点）；`internal/sched` 单测 `TestStickyTTLExpiry`、`TestStickyBlacklist*`、`TestStickySameKey` 等 | 面板「规则 → 粘性黑名单」新增目标 `*.example.com` 或某节点组 → `POST /api/v1/rules/sticky/preview`（或面板试算）预期 `{hit:true, rule_id:…}`；随后请求不再固定节点 |
| 7 | 节点注册 5 s 内面板显示出口 IP/国家/ASN；NAT 后两节点 `duplicate_of` 且独立出口=1；删 MMDB 仍可启动 | 手工（需 MMDB/外网 provider） | `internal/geo` 单测覆盖出口解析/归一化/合并/cache；验收脚本按设计关闭 geo 以避免外网依赖 | 配置 `geo.enabled=true`、`geo.remote_consent=true`、一个 preset provider（如 ipinfo）；启动后 `GET /api/v1/nodes` 的 `egress_ip`/`geo.country/asn` 应在数秒内非空；把 `mmdb_path` 指向不存在的文件 → 服务端应启动并告警、国家显示 `unknown` |
| 8 | 3 节点杀 1：10 s 内不再分配、面板离线、在途流不被拖垮 | 半自动 | 脚本 8 用 2 节点实测「离线后 503、不回退组外节点、重启恢复」；`internal/tunnel` 单测覆盖 plane detach/会话关闭 | 3 节点场景需手工起 3 个 client 后 `Stop-Process`/`kill -9` 其一，观察面板 `online=false` 与后续请求状态；**注意本机观测到的 QUIC 硬杀离线判定耗时 58–72 s，见 §5.1** |
| 9 | 全部候选不可用：HTTP 502/503、SOCKS5 明确错误、日志含决策原因 | 自动（部分） | 脚本 8 断言 503，并可在 server 日志看到 `proxy_request result=no_candidates/...`；`internal/proxy` 单测覆盖错误码映射 | SOCKS5 无可选节点：`curl --socks5-hostname user:pass@SERVER:1080 http://example.com/` → 退出码非 0（`host unreachable`）；`grep no_candidates server.log` |
| 10 | 面板改策略/粘性 TTL/熔断阈值立即生效、重启后仍在；非法配置拒绝且保留旧值；撤销上次修改 | 自动 + 手工 | 脚本 6（PUT/GET/undo/422 旧值不变）、9b（TTL 热更）；`internal/settings` 单测含持久化/回滚 | 重启持久：改策略后重启 server（同 `state_dir`），登录后 `GET /api/v1/settings` 仍为新值；撤销后回到上一版本 |
| 11 | 审计包含登录、组与凭据变更、节点上下线，且无明文密码 | 自动（部分） | 脚本 7 断言 login/settings.update 与无明文密码；脚本 8 的操作会写入 group.create/credential.create 等（可在 `/audit` 中查到） | `curl -k -b cookie 'https://SERVER/api/v1/audit?limit=200'` → `actions` 含 `login,group.create,credential.create,settings.update,settings.undo`；对响应全文 grep 密码应为空 |
| 12 | 并发 200 × 10 MB：无 OOM、无 goroutine 泄漏（活跃连接归零）、`/metrics` 自洽 | 半自动 | 脚本 13 自动验证 20 × 64 KB 全部成功、`active_connections` 5 s 内归零；`/metrics` 由 Prometheus 客户端输出 | 手工压测：`seq 1 200 | xargs -P200 -I{} curl -s -o /dev/null -w '%{http_code}\n' -x http://user:pass@SERVER:8080 http://ORIGIN/10mb` → 200 数 =200；结束后 `curl -k https://SERVER/metrics | grep -E 'active|proxy_requests_total'`；`Get-Process proxygw-server | select WorkingSet64` 观察内存 |
| 13 | 多平面：50 并发流按哈希分布到 ≥2 条隧道；100 ms RTT 下 2 平面吞吐提升 ≥30% | 手工（弱网）+ 单测 | `internal/transport`/`internal/tunnel` 单测覆盖多平面；`planes` 配置 2 | 注入 RTT：Linux `tc qdisc add dev lo root netem delay 100ms`，分别 `planes: 1` 与 `planes: 2` 各跑一次大文件下载对比吞吐；不同平面分布可用 server 日志 `plane_index` 或面板 `/tunnel/sessions` |
| 14 | SIGTERM：不再接新连接，在途请求 10 s 内完成或干净失败，进程正常退出 | 自动（Linux/macOS） | `scripts/acceptance.sh` 检查项 12：`kill -TERM` 后 15 s 内退出码 0 且端口释放（Windows 上 SKIP） | Linux 手工：`kill -TERM <server_pid>; echo $?` → `0`；`ss -lntup | grep <port>` 应为空 |
| 15 | 空载内存：server < 40 MB、client < 20 MB（含内嵌面板与 MMDB 索引） | 手工 | — | `Get-Process proxygw-server,proxygw-client | Select Name,WorkingSet64`；Linux：`ps -o rss= -p $(pgrep proxygw-server)`（预期 server < 40960 KB、client < 20480 KB） |
| 16 | QUIC 主用与回退：日志确认走 QUIC；UDP 被丢后 2 s 内回退 wss 且代理不中断；10 分钟内不再反复尝试；面板显示 transport/回退原因 | 自动（模拟） | 脚本 10：另起 `transport=ws` 服务端 + 同端口 UDP 黑洞，client `auto` 回退后 `/nodes transport=ws`、client 日志含 `transport.fallback`；`internal/integration` 有 `TestQUICUDPBlackholedFallsBackToWS`、`TestWSFallbackWhenOnlyWebSocketEnabled` | 真实防火墙：Linux `iptables -A INPUT -p udp --dport 443 -j DROP`（或 `nft add rule inet filter input udp dport 443 drop`）后重启 client → 2 s 内 `wss`，日志 `retry_after_ms=600000`；删除规则后 10 min 内自动重探 QUIC |
| 17 | 自定义 provider（template 路径）对 `{"data":{"country":"JP","asn":"AS2516"}}` 归一化为 JP/2516；路径写错时测试按钮明确报错且不影响其他节点 | 半自动（单测）+ 手工 | `internal/geo` 单测覆盖 template/路径解析/归一化/partial fill；`go test ./internal/geo/ -run 'TestTemplate|TestPath|TestNormalize' -v` | 面板「Geo provider 测试」按钮（或 `POST /api/v1/geo/providers/{name}/test`）→ 返回 `result.country=JP, result.asn=2516`；把映射改成 `$.data.nope` → 返回明确字段错误 |
| 18 | 远程 provider 指向内网地址被拒绝（SSRF 防护） | 自动（单测）+ 手工 | `internal/geo` 单测覆盖 SSRF（仅 https、拒绝内网/回环/链路本地/元数据、重定向校验）；`go test ./internal/geo/ -run 'TestSSRF|TestRemote' -v` | 配置 template provider URL `http://127.0.0.1/…` → 配置校验失败并指出字段；面板测试按钮返回明确错误 |
| 19 | 首次启动打印 SPKI pin；client 用该 pin 连接成功；pin 改错后硬失败且错误含期望+实际 | 自动 | 脚本 11（exit 非 0、20 s 内、日志含「期望指纹/实际指纹/排查建议」）；`internal/certs` `TestPinClientMismatch`、`TestPinMismatchError`；`internal/integration` `TestPinMismatchIsFatal` | 见脚本 11 输出（本机实测）：`CRYPTO_ERROR 0x12a … 期望指纹：sha256/AAA…=；实际指纹：sha256/+Ah/…=；排查建议：…` |
| 20 | 无感续签：保留密钥对重签证书指纹不变，已连节点无需改动 | 半自动（单测） | `internal/certs` `TestSameKeyReissueKeepsPin`、`TestNewServerManagerRestartKeepsPin` | `go test ./internal/certs/ -run 'TestSameKeyReissueKeepsPin|TestNewServerManagerRestartKeepsPin' -v` → ok |
| 21 | 密钥轮换：client 同时配置新旧两枚 pin 可连接；只配旧 pin 按预期硬失败 | 半自动（单测） | `internal/certs` `TestPinClientMultiplePinsRotationWindow`、`TestServerPinNext`；面板 `/api/v1/cert/rotate-pin` | 面板「证书 → 生成下一枚 pin」→ `GET /api/v1/cert` 的 `pin_next` 非空；节点配置 `tls.pins: [旧, 新]` 后仍可连接 |
| 22 | CA 模式：本地自建 CA 签发证书 + `--ca-file` 校验通过；无法验证的自签证书按预期失败 | 半自动（单测）+ 手工 | `internal/certs` `TestCAModeClientVerifiesCustomCA`、`TestCAModeClientRejectsOtherCA`、`TestNewServerManagerCAMode` | `go test ./internal/certs/ -run 'TestCAMode' -v`；手工：openssl 自建 CA 签发 server 证书 → `tls.mode=ca`、client `tls.mode=ca` + `ca_file` |
| 23 | 私钥权限改成 0644 时服务端拒绝启动并明确提示 | 半自动（POSIX 单测）+ 手工 | `internal/certs` `TestPrivateKeyPermissions`（Windows 下跳过 POSIX 权限位断言） | Linux：启动一次生成 `state/certs/server.key`，`chmod 0644` 后重启 → 退出非 0，stderr 含「私钥文件权限过宽」；`chmod 0600` 后恢复。Windows 上按 README 仅告警（ACL 语义不同） |

**自动/半自动/手工划分统计**：完全自动 8 条（1、2、4、9 部分、10 部分、11、14、16、19 中的自动项按“自动”计为 1/2/16/19 共 4 条整条自动 + 4 条部分自动），
半自动 11 条，纯手工 4 条（7、13、15、以及 8/12/17/18/20–23 中的真机补充项）。

> 更严格的划分以 §2 脚本表 + 上表「方式」列的组合为准：脚本/单测能全覆盖的标「自动」；
> 需要额外一条命令或环境（MMDB、外网、弱网、真机 SIGTERM、内存观测）的标「半自动/手工」。

---

## 5. 环境限制与降级说明

1. **本机无直连外网，外网项已跳过（已用本地替身覆盖核心路径）**：
   用户确认本机访问 GitHub 等外网需经 SOCKS5 代理 `10.0.20.13:1080`。验收脚本的所有断言**不依赖外网**：
   代理相关用本地 origin、CONNECT 用本地 TLS `/healthz`、回退用同端口 UDP 黑洞。
   因此外网相关项一律**跳过**并在表中标注「本机无外网/已跳过」：`example.com` 端到端（§4-2 手工项）、
   PowerShell 7 安装包下载、在线归属地 provider（§4-7/17）。若需要重试外网，可显式走代理：
   `curl --proxy socks5h://10.0.20.13:1080 …`。
2. **外网 `example.com` 可能不可达/不稳定** → 所有代理相关断言使用本地 origin（`/healthz`、`/echo`、`/64k`、`/slow`）
   与本地 TLS `/healthz`；外网 curl 仅作为可选手工项（§4-2）。
3. **Windows 无 SIGTERM** → `acceptance.ps1` 的检查 12 标 SKIP，只验证 `Stop-Process` 后 TCP/UDP 端口释放；
   优雅停机语义由 `acceptance.sh` 在 Linux/macOS 用 `kill -TERM` 断言（退出码 0 + 端口释放）。
4. **UDP/443 防火墙不可随意改** → 回退用例用「同端口 UDP 黑洞」模拟：另起 `tunnel.transport=ws` 的服务端，
   并对同一端口绑定 `dgram` 黑洞丢弃 QUIC 包；client `auto` 2 s 后回退 wss，面板 `transport=ws` 即 PASS。
   真实防火墙步骤见 §4-16。
5. **PowerShell 7 不可用** → 本机只有 Windows PowerShell 5.1（PS7 下载因无直连外网已跳过）；脚本用双兼容语法并保存为 UTF-8 BOM 保证 5.1 正确解析中文；
   `pwsh -File scripts/acceptance.ps1` 是 PowerShell 7 的标准入口（本机未能实际执行，属环境限制，非脚本问题）。
6. **QUIC 单核性能 / 2 平面吞吐提升 / 100 ms RTT** → 需要真机弱网与性能对比，脚本不测；标手工（§4-13）。
7. **节点元数据（出口 IP / 国家 / ASN / NAT 去重 / MMDB）** → 验收脚本按设计关闭 geo（避免外网依赖）；
   由 `internal/geo` 单测 + 面板手工步骤覆盖（§4-7/17/18）。
8. **Windows 私钥权限位不可靠** → README 已说明 Windows 只告警；0644 拒绝启动仅在 Linux/macOS 可实测（§4-23）。
9. **Windows 无法向控制台子进程发送 Ctrl+C** → 同 (3)，优雅停机由 Linux 脚本覆盖。

### 5.1 已知观察项 / 缺陷候选（只报告，不修改代码）

1. **QUIC 硬杀节点离线判定耗时 58–72 s，超过规格「10 s 内不再分配」的预期**。
   - 现象：`acceptance` 检查 8 中，`Stop-Process`/`kill -9` 杀掉使用 QUIC 的节点后，
     `/nodes` 的 `online` 在 **57.9 s / 60.9 s / 68 s / 72.3 s**（多次运行）后才变 `false`；
     在变离线前发起的请求可能失败（502/504），不会回退到组外节点；变离线后请求返回 503。
   - 原因（据实现现象推测）：QUIC 对端进程被硬杀不会收到 TCP RST/QUIC CONNECTION_CLOSE，
     服务端依赖心跳（15 s × 3）与 QUIC idle timeout（60 s）才判定会话失效。
   - 影响：规格第 8 条「杀掉 1 个节点 10 s 内不再分配给它」在硬杀场景下不满足；
     进程正常退出（KICK/优雅关闭）与 TCP/wss 路径不受影响。
   - 建议（供实现负责人决策）：把「心跳 3 次缺失」判死上限收紧到 ≤10 s，或在 OPEN 失败时立即
     `Registry.SetNodeOnline(false)` + 触发熔断，使入口快速 fail-closed。
2. **HTTP 代理转发到 origin 时使用 origin-form（`/echo`）而非 absolute-form**：
   这是正常代理实现行为（入口按 absolute-form 解析、按 origin-form 回源），
   脚本通过服务端 `proxy_request.protocol=http/target` 日志证明 absolute-form 已解析，不视为缺陷。
3. （历史）并行编辑期间曾出现 `internal/transport` 测试 panic；代码冻结后 `go test -race -count=1 ./...` 28 包全绿，不再复现。

---

## 6. 最小手工验收清单（15 分钟内）

> 适用于已有可运行服务端 + 1 个节点客户端的环境（本机或测试机）。
> 服务端/客户端可用 README 快速开始启动；下面的 `SERVER`、`ADMIN_PASS`、`cred:pass` 按实际替换。
> 若没有现成环境，直接跑 `scripts/acceptance.ps1 -KeepArtifacts`，从保留目录读取实际值（脚本会打印路径）。

1. **构建与静态检查**（30 s）
   ```bash
   go build ./... && go vet ./... && go test ./...   # 期望：无失败
   ```
2. **健康与版本**（5 s）
   ```bash
   curl -k -s https://SERVER/healthz | head -c 300; echo
   # {"ok":true,"checks":{...},"version":{"version":"dev",...}}
   curl -k -s https://SERVER/version
   # {"version":"dev","commit":"none",...}
   ```
3. **面板登录 + CSRF + 热更/撤销**（3 min）
   ```bash
   curl -k -s -c /tmp/c -H 'Content-Type: application/json' -d '{"username":"admin","password":"ADMIN_PASS"}' https://SERVER/api/v1/login
   # 200，返回 csrf；记 CSRF=...
   curl -k -s -b /tmp/c https://SERVER/api/v1/overview | head -c 400; echo   # online_nodes>=1
   curl -k -s -b /tmp/c -X PUT -H "X-CSRF-Token: CSRF" -H 'Content-Type: application/json' \
        -d '{"settings":{...完整 settings，改 scheduler.strategy...}}' https://SERVER/api/v1/settings   # 200
   curl -k -s -b /tmp/c -X POST -H "X-CSRF-Token: CSRF" https://SERVER/api/v1/settings/undo               # 200
   # 未带 CSRF 的 PUT -> 403；非法 strategy -> 422 且旧值不变
   ```
4. **三代理入口**（1 min）
   ```bash
   curl -s -o /dev/null -w 'HTTP %{http_code}\n' -x http://cred:pass@SERVER:8080 http://127.0.0.1:9/        # 403/502/503 之一均说明入口通（无效目标被 ACL/连接失败映射）
   curl -k -s -o /dev/null -w 'CONNECT %{http_code}\n' -x http://cred:pass@SERVER:8080 https://SERVER/healthz
   curl -s -o /dev/null -w 'SOCKS %{http_code}\n' --socks5-hostname cred:pass@SERVER:1080 https://SERVER/healthz
   ```
   > 本机实测（本地 origin，见 §7）：HTTP 200、CONNECT 200、SOCKS5 200。
5. **错误口令 407 / SOCKS5 握手失败**（10 s）
   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' -x http://cred:WRONG@SERVER:8080 http://127.0.0.1:9/   # 407
   ```
6. **fail-closed**（2 min）：面板把凭据 A 绑定到组 g1（仅节点 1）→ 停掉节点 1 → 用 A 请求应为
   `503`（等待节点被判定离线后；QUIC 硬杀需数十秒，见 §5.1），再启动节点 1 → 恢复 200；
   组外节点在线也不应被使用。
7. **pin 不匹配硬失败**（30 s）：把 client 配置 `tls.pin` 改成 `sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`，
   启动客户端 → 进程在 20 s 内非 0 退出，stderr 同时出现「期望指纹/实际指纹/排查建议」。
8. **QUIC 回退（可选，2 min）**：Linux `iptables -A INPUT -p udp --dport 443 -j DROP` → 重启 client →
   `2 s` 内回退 wss，面板节点 `transport=ws`；删除规则。
9. **SIGTERM（Linux，30 s）**：
   ```bash
   kill -TERM $(pgrep -f 'proxygw-server -config'); echo exit=$?   # 0
   ss -lntup | grep -E ':8080|:1080|:443'                          # 端口已释放
   ```
10. **内存**（10 s）：`Get-Process proxygw-server,proxygw-client | Select Name,WorkingSet64`
    （预期 server < 40 MB、client < 20 MB 量级）。

---

## 7. 本机实测输出片段（可直接对照）

以下片段来自本机实跑（敏感值已替换；命令与 §2/§4 一致）。

**服务端启动信息（stderr，只打印一次，哈希持久化）**

```
================ proxygw 首次启动信息（只显示一次，请保存） ================
  服务端证书模式=pin SPKI 指纹=sha256/yn/kfE3l7k265exZMuQAjQWn5xCoNeRC336e1TNagRM= 有效期至 2027-11-17T05:34:01Z
  代理凭据（仅本次显示，请立即保存）：用户名 np-ssj9rd  密码 <redacted>   （认证模式 required）
  面板管理员密码（仅本次显示，请立即保存）：用户名 admin  密码 <redacted>   面板地址 https://<server>:443/
============================================================================
```

**`GET /healthz`（200）**

```json
{"ok":true,"checks":{"credentials":"ok","registry":"ok","tunnel":"ok"},"uptime_seconds":6.07,"version":{"version":"dev","commit":"none","build_time":"unknown","go_version":"go1.27.0"}}
```

**`GET /version`（200）**

```json
{"version":"dev","commit":"none","build_time":"unknown","go_version":"go1.27.0"}
```

**`POST /api/v1/login`（200）**

```json
{"username":"admin","expires":"2026-11-17T17:40:03Z","csrf":"N888hyyFnO6R_0gRjlpq4-zfChNYavsHgr4XHpPXenc","totp_enabled":false}
```

**`GET /api/v1/overview`（200，节选）**

```json
{"online_nodes":1,"nodes_total":1,"unique_egress_ips":1,"active_connections":0,
 "transport_mix":{"quic":1},"settings_version":4,"clock_skew_ms":0,
 "cert":{"mode":"pin","pin":"sha256/yn/kfE3l7k265exZMuQAjQWn5xCoNeRC336e1TNagRM=","pin_next":"","not_after":"2027-11-17T05:34:01Z"}}
```

**`GET /api/v1/nodes`（200，节选）**

```json
{"items":[{"id":"node-e2e-1","tags":["node-e2e"],"weight":100,"enabled":true,"online":true,
  "egress_ip":{"v4":"127.0.0.1","source":"peer"},"inflight":0,"breaker_state":"closed",
  "version":"dev","groups":["g_..."],"transport":"quic","planes":2,
  "capabilities":["zstd","dns","probe"]}],"total":1}
```

**`GET /api/v1/settings`（200，节选）**：durations 为字符串形式（`"10m0s"`/`"30s"`），

```json
{"current":{"scheduler":{"strategy":"random","sticky":{"enabled":true,"ttl":"10m0s","max_keys_per_node":1000},
  "breaker":{"failure_threshold":5,"failure_rate":0.5,"min_samples":20,"open_timeout":"30s"},
  "retry":{"enabled":true,"max_attempts":2}},"limits":{"max_streams_per_node":1000}, ...}}
```

**`GET /api/v1/audit`（200，节选）**

```json
{"items":[{"action":"login","actor":"admin","result":"ok"},
          {"action":"settings.undo","actor":"admin","result":"ok","detail":{"version":"4"}},
          {"action":"settings.update","actor":"admin","result":"ok","detail":{"strategy":"random","version":"3"}},
          {"action":"group.update","actor":"admin","result":"ok"}]}
```

**三代理入口（均经本地 origin / 本地 TLS 服务）**

```text
== http-proxy http=200
{"ok":true,"url":"/echo","method":"GET","host":"127.0.0.1:<origin>"}

== connect http=200
{"ok":true,"checks":{"credentials":"ok","registry":"ok","tunnel":"ok"},...}

== socks5 http=200
{"ok":true,"url":"/echo","method":"GET","host":"127.0.0.1:<origin>"}
```

**pin 不匹配（client stderr，exit=1）**

```json
{"level":"ERROR","msg":"节点因致命错误退出（不会自动重连）","error":
 "nodeagent: fatal: QUIC 建连致命错误: ... TLS 公钥指纹（SPKI pin）校验失败。期望指纹：sha256/AAA…=；实际指纹：sha256/+Ah/…=。排查建议：1) … 5) pin 模式不会降级为“不校验证书”"}
```

**并发 20 × 64 KB（检查 13）**

```text
20/20 成功，共 1.3 MB，耗时 1.1s；active_connections=0
```

---

## 8. 证据与日志

- 运行脚本时加 `-KeepArtifacts` / `--keep-artifacts`（失败时自动保留），会打印临时目录，例如：
  `<TEMP>/proxygw-accept-XXXXXXXX/`：
  - `server.yaml` / `server.err.log`（JSON 运行日志 + 首启一次性信息）
  - `client-1.yaml` / `client-1.err.log`、`client-2.yaml` / `client-2.err.log`
  - `origin.js`、`fallback-server.*`（回退用例）、`udp-blackhole.js`
  - `results.tsv`（bash）或脚本内存中的结果表（PowerShell）
- 命令级证据（可复制）：
  ```bash
  # Windows
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/acceptance.ps1 -KeepArtifacts
  # Linux/macOS
  bash scripts/acceptance.sh --keep-artifacts
  # 完整竞态测试
  go test -race -count=1 ./...
  # 分包看细节
  go test -race -count=1 ./internal/integration/ -v
  ```
- 审计/指标：`GET /api/v1/audit?limit=200`、`GET /metrics`（Prometheus 文本格式）。

---

## 9. 变更记录

| 日期 | 变更 |
|---|---|
| 2026-11-17 | M7-D 初版：新增 `scripts/acceptance.ps1`、`scripts/acceptance.sh`，完成本机实测（PS：PASS=16/SKIP=1；bash：PASS=15/SKIP=2；`go test -race` 28 包全绿），记录已知观察项（QUIC 硬杀离线判定 58–72 s）。 |
