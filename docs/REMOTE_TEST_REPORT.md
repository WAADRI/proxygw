# 远程真实服务器全功能测试报告

- 测试时间：2026-11-21 22:27 – 23:05（Asia/Shanghai）
- 测试目标：`node.proxy.waadri.top`（Ubuntu 26.04.1 LTS / x86_64 / 2 vCPU / 3.6 GiB RAM / 50 GiB 磁盘，root）
- 被测版本：`proxygw 1.0.4-test`（Linux amd64 交叉编译；包含本报告第 4 节列出的四处修复）
- 证书：复用服务器现有 Let's Encrypt 通配证书
  `/www/server/panel/vhost/cert/node.proxy.waadri.top/{fullchain,privkey}.pem`（CN=`*.node.proxy.waadri.top`，有效期至 2027-01-31），服务端 `tls.mode=ca`，浏览器/客户端无需 `-k`。
- 部署目录：`/opt/proxygw-test`（二进制、配置、状态、日志、自测脚本）；systemd 单元 `proxygw-test-server`、`proxygw-test-client-a`、`proxygw-test-client-b`（另有两个 test-only 单元：本地 origin、webhook 接收器）。
- 对外端口：`443/tcp`（面板 HTTPS + wss 隧道）、`443/udp`（QUIC）、`8080/tcp`（HTTP 代理）、`1080/tcp`（SOCKS5）；`ufw` 已放行上述端口。
- 拓扑：本机两个节点 `node-a`（group-a）/`node-b`（group-b），均 QUIC 双平面、zstd 压缩；另有一次性 Windows 外部客户端 `node-ext` 从公网接入（wss 回退路径验证）。

> 本文件记录的是**真实公网服务器**上的实测结果；仓库自带的 `scripts/acceptance.ps1|sh` 仍是本地一键验收脚本，二者互补。
> 管理员口令与代理凭据不写入仓库，由交付对话单独提供。

## 1. 总体结果

| 测试组 | 结果 |
|---|---|
| 部署与启动（systemd、端口、健康检查、首启密钥、真实证书） | **全部 PASS** |
| 三代理入口（HTTP/CONNECT/SOCKS5、认证、错误码、大文件、并发、限流、压缩、IPv6 目标） | **全部 PASS** |
| 节点认证与管理（双节点 QUIC、错误令牌/错误证书、kick、禁用、拨测、安装命令、证书轮换） | **全部 PASS** |
| 调度（粘性、组隔离 fail-closed、故障转移、节点恢复、webhook 告警） | **全部 PASS** |
| 控制面（面板登录/CSRF/静态资源/SSE、总览/节点/会话/证书/设置热更/undo/reset、组/凭据/规则 CRUD、审计、指标、TopN、Geo provider、TOTP、PROXY protocol v2、mTLS） | **全部 PASS** |
| 容灾与运维（QUIC→wss 回退、UDP 恢复后回 QUIC、SIGTERM 优雅停机排空、重启恢复） | **全部 PASS** |

合计约 **99 项自动化断言**（多个测试组对同一能力有交叉验证），最终 **0 FAIL**。测试过程中发现并修复了 **4 个真实缺陷**（3 个功能缺陷 + 1 个指标口径缺陷，第 4 节），另有 3 项配置/文档级改进建议（第 5 节）。

## 2. 部署与启动实测

| 检查 | 结果 |
|---|---|
| 交叉编译 | `GOOS=linux GOARCH=amd64 CGO_ENABLED=0`，server 17.3 MB、client 14.5 MB，静态 ELF |
| systemd | server 与两个 client 均 `active (running)`，`systemctl enable` 后随系统启动；`ufw` 规则持久 |
| 监听 | `443/tcp`、`443/udp`（QUIC）、`8080/tcp`、`1080/tcp` 全部由 proxygw-server 监听 |
| 首启信息 | 控制台一次性输出 SPKI pin、代理凭据、面板管理员密码；重启后不再输出（哈希持久化） |
| 健康检查 | `GET https://node.proxy.waadri.top/healthz` → `{"ok":true,"checks":{"credentials":"ok","geo":"ok","registry":"ok","tunnel":"ok"}}` |
| 版本 | `/version` → `1.0.4-test`（server/client 一致，`-version` 亦验证） |
| 面板 | `/` 与 `/static/app.js` 均 200；公网证书校验通过（`ssl_verify=0`，无需 `-k`）；CSP/X-Frame-Options 等安全头存在 |
| 指标 | `/metrics` 输出 `proxy_requests_total`、`tunnel_bytes_total`、`nodes_online`、`tunnel_planes`、`tunnel_session_state` 等 |

## 3. 功能测试明细

### 3.1 三代理入口与数据面

| 用例 | 结果 |
|---|---|
| HTTP CONNECT → `https://www.baidu.com/` | 200 |
| HTTP absolute-form → `http://www.baidu.com/`（跟随跳转） | 200 |
| SOCKS5 → `https://www.baidu.com/` | 200 |
| 错误代理口令 | HTTP 407（`Proxy-Authenticate` 返回）；SOCKS5 握手失败 |
| 本地 origin（经节点回环拨号）`/healthz` | `origin-ok` |
| 下载 64 KiB / chunked 响应 / 1 MiB | 字节数精确 65536 / 32 / 1048576，耗时 0.26–0.31s |
| 慢速 2 MiB（origin 限速 ~1.6 Mbps） | 2097152 字节，5.37s，完整无截断 |
| POST 100000 字节回显 | `echo:100000:...` 长度一致 |
| 20 并发 × 64 KiB | 20/20 成功，3.21s |
| 压缩（`compression_enabled=true`，1 MiB 可压缩对象） | `tunnel_bytes_total` 仅增加 **659 B**（约为明文 0.001），节点 `compression=true` |
| 凭据下行限速（`per_credential_down_kbps=2000`） | 1 MiB 耗时 3.31s（不限速约 0.3s），undo 后恢复 |
| IPv6 目标 `http://[::1]:19001/healthz` | 200 `ipv6-origin-ok`（节点成功拨 IPv6 回环目标） |
| 外部 Windows 客户端（公网，wss 回退） | 注册为 `node-ext`；经其转发 1 MiB 下载 + 100 KB POST 回显，TopN 计数 3 次/1.1 MB 全部正确 |

### 3.6 公网 QUIC 实测（云安全组放行 UDP 443 之后）

首次公网测试时云安全组未放行 UDP 443，外部客户端 2s 超时后回退 wss（该路径已验证）。放行 UDP 443 后追加以下公网 QUIC 测试（外部客户端位于公网 Windows 机器，经真实互联网连到测试服务器）：

| 用例 | 结果 |
|---|---|
| 外部节点 QUIC 注册 | `node-ext` 2 条 QUIC 平面均在 64–65ms 内建连并 ready；`/nodes` 显示 `transport=quic, planes=2, compression=true` |
| 数据面经外部 QUIC 节点（公网 origin） | `/healthz` 454ms；64 KiB 355ms；1 MiB 0.41s（**~20.7 Mbit/s**）；10 MiB 0.70s（**~119 Mbit/s**）；POST 1 MiB 0.51s（**~15.6 Mbit/s**） |
| 多流并发 | 20/20 路 64 KiB 全部成功，2.60s；节点客户端日志显示 **53 条数据流分布到两个 QUIC 平面（plane0=30，plane1=23）** |
| CONNECT + TLS | 经外部 QUIC 节点 CONNECT `https://www.baidu.com` → 200 |
| 路由证据 | TopN 节点计数 `node-ext=78`，其余节点 0（证明流量确实经外部节点） |
| 公网 IPv6 QUIC | 外部客户端用 IPv6 字面量 `[2402:…:0]:443` + `server_name` 连接，1 条 QUIC 平面 58ms 建连、ready，面板 ping 拨测 21.8ms 成功 |
| 与 wss 对照（同一外部节点、同一公网 origin） | 1 MiB：wss 0.54s（15.4 Mbit/s）vs QUIC 0.41s（20.7）；10 MiB：wss 0.77s（109 Mbit/s）vs QUIC 0.70s（119）；POST 1 MiB：wss 0.66s（12.2）vs QUIC 0.51s（15.6）；20 并发 64 KiB：wss 3.16s vs QUIC 2.60s——**QUIC 在本环境全面优于 wss**（主要是多流无队头阻塞与更低的连接/流开销） |
| 长连接/稳定性 | 外部 QUIC 节点空闲 45s：心跳保持 session ready、无重连，下一个请求 422ms 正常；随后连续 30 × 1 MiB：**30/30 成功、30 MiB / 13.7s、平均 457ms/请求、全程无重连**；TopN 计数 31 与流量吻合 |

> 测试结束后已清理：公网测试 origin 与临时 ufw 规则已停用/删除，外部测试节点进程已停止，其测试用组/凭据已从面板删除；最终集群只保留 `node-a`/`node-b` 两个 QUIC 节点。

### 3.7 节点侧 Docker 部署验证

在测试服务器的 Docker 环境（Docker 29.9.2 / Compose v5.6.1）中验证节点侧容器化部署：

| 用例 | 结果 |
|---|---|
| 从仓库源码构建镜像 | `docker build -f deploy/Dockerfile.client --build-arg VERSION=1.0.4 --build-arg GOPROXY=https://goproxy.cn,direct -t proxygw-client:1.0.4 .` 成功，镜像 8.59MB（content） |
| 仅环境变量启动（不挂载配置文件） | 镜像内置 `deploy/config.client.docker.yaml`，只传 `SERVER_URL/AUTH_TOKEN/CLIENT_ID/TLS_MODE=ca` 等环境变量即可运行 |
| 单机启动 2 个节点容器 | `proxygw-node-1`（node-docker-1）、`proxygw-node-2`（node-docker-2）均 `Up`，各自独立 state 卷 |
| 注册结果 | 两个节点均以 **QUIC / 2 平面** 在线（建连 ready 24–61ms），面板 ping 拨测 0.74ms |
| 数据面 | 面板创建匹配 `tags=docker` 的组与凭据后，经两个 Docker 节点转发 **6/6 请求 200**，TopN 计数 6 |
| Compose 配置校验 | `docker compose -f deploy/docker-compose.client.yml --env-file deploy/.env.client config` 校验通过 |
| 清理 | 测试容器与卷已删除，服务端重启后仅保留 `node-a`/`node-b`；测试服务器保留已构建镜像供后续使用 |

配套文档：**[docs/DOCKER_NODE.md](DOCKER_NODE.md)**（镜像构建、env 参数表、单机多节点、compose、排障与安全建议）。

### 3.2 认证、节点与管理面

| 用例 | 结果 |
|---|---|
| 双节点 QUIC 注册 | `node-a`/`node-b` 各 2 平面，`transport_mix.quic=2`，`tunnel_planes=2`，能力 `zstd/dns/probe`，compression=true |
| 网关节点令牌（静态 per-node） | 两个 node 各自令牌注册成功；控制台不打印明文（仅首启随机凭据） |
| 错误节点令牌 | 客户端 **1s 内 exit=1**，日志 `服务端拒绝注册：authentication failed`（修复后，见 4.2）；服务端审计 `node.auth_failed` |
| 错误 SPKI pin（pin 模式客户端连 CA 服务端） | 硬失败 exit=1，日志含 pin mismatch 诊断，不重试 |
| 面板强制下线（kick） | KICK 送达后 1.8s 完成 epoch 递增重连（修复后，见 4.1）；审计 `node.kick`；流量恢复 |
| 节点禁用/启用 | 禁用后组内凭据 `503`；启用后 `200`（不走组外节点） |
| 节点拨测 | `ping` 成功（0.45–18ms）；`http https://www.baidu.com` 成功 |
| 安装命令 / 模板 | 返回 `install-node.sh --server ... --pin ... --token '<节点接入令牌>'`，令牌始终为占位符，不回显真实令牌 |
| 证书轮换 | `POST /cert/rotate-pin` 返回新 pin，`GET /cert.pin_next` 立即更新；`POST /cert/reload` 成功 |
| 错误/过期凭据 | 禁用凭据立即 407（旧连接被踢），重新启用后 200；生成密码凭据可用；`kick-sessions` 实测踢掉 1 条在途下载 |

### 3.3 调度、组隔离与故障转移

| 用例 | 结果 |
|---|---|
| 粘性 | 同源（公网客户端 IP）连续 5–6 次请求全部命中同一节点（另一节点计数 +0） |
| 组隔离 fail-closed | 凭据绑定 `g1`（仅 node-a）：10 次全走 node-a；停 node-a 后请求 **恰好 503**，node-b 计数为 0；重启 node-a 后恢复 200 |
| 故障转移 | 无组凭据在 node-a 离线后自动迁移到 node-b，请求 200；`sticky.migrated` 审计可见 |
| Webhook 告警 | 停 node-a 后 15–30s 内收到 `node_offline` JSON（含 node_id/alias/egress/transport） |
| 节点禁用 | 面板禁用后组内流量 503；启用后恢复 |
| 节点恢复 | 进程重启后自动注册、组流量恢复 |

### 3.4 控制面（面板 API 与页面）

| 用例 | 结果 |
|---|---|
| 登录/会话 | 未登录 401；错误密码 401；正确登录 200 + CSRF；`/session` 正常 |
| CSRF | 写请求无 CSRF → 403 |
| 静态资源与安全头 | `/`、`/static/app.js` 200；CSP、`X-Frame-Options: DENY`、`nosniff` 存在 |
| SSE | `/api/v1/events` 持续收到 `data:` tick |
| 总览/节点/会话/证书 | 在线节点 2、transport_mix、证书 `mode=ca`、pin/not_after 正确 |
| 运行设置 | GET/PUT 热更（strategy/compression）立即生效且版本递增；非法设置 422 保旧值；undo 还原；reset 恢复默认 |
| 节点组 | g1/g2 创建、成员解析（各 1 个节点）正确；被引用组删除受保护（单测覆盖 409） |
| 凭据 | 创建/绑定组/可见节点数/usage/禁用启用/生成密码/踢会话/删除 全部通过；响应无 password_hash |
| ACL | 新增 `blocked.example` 拒绝规则后请求 → 403；删除规则后恢复 |
| 粘性黑名单 | 创建规则后 preview 命中 `hit=true`；删除成功 |
| 审计 | 含 login/settings.update/group.create/credential.*/node.kick/node.auth_failed/proxy.acl_denied 等；**无管理员/代理/凭据明文口令** |
| TopN | `/stats/topn` targets/nodes/credentials 计数与字节随真实流量变化 |
| Geo | provider `ipwho.is` 实测 8.8.8.8 → US / AS15169 / 973ms；节点 egress v4/v6 与 geo（CN/Jiangsu/Nanjing/Tencent Cloud AS45090）正常展示 |
| TOTP | 独立实例开启 `admin.totp_secret`：无码 401 `totp_required`；正确 TOTP 200 + CSRF；错误码 401 |
| PROXY protocol v2 | 共享 TLS 监听带 PROXY v2 头 → 面板登录成功且审计 `source_ip=203.0.113.9`；HTTP 代理入口带 PROXY v2 头 → 407 且审计 `source_ip=203.0.113.77`；无头直连仍 200/407（可选头透传） |
| mTLS | 独立实例 `tls.mode=ca + client_auth=require + nodes.mtls=true`：无客户端证书 TLS 握手被拒；带客户端证书、无令牌的节点 QUIC 上线；面板需客户端证书可登录 |

### 3.5 容灾与运维

| 用例 | 结果 |
|---|---|
| QUIC→wss 回退 | 临时 `iptables` 丢弃 UDP/443 后重启客户端：2s 内回退 wss，面板 `transport=ws`；恢复 UDP 后重新注册为 `quic` |
| 外部公网回退（云安全组未放行 UDP 443 时） | Windows 客户端 QUIC 2s 超时后回退 wss，后续大文件/上传全部正常；放行 UDP 443 后重测，外部客户端直接以 2 条 QUIC 平面注册并用 QUIC 承载全部数据面（见 3.6） |
| SIGTERM 优雅停机 | 进行中的 2 MiB 慢速下载在停机排空期间**完整完成**（2097152 字节）；服务端退出码 0；drain 日志存在；端口释放 |
| 重启恢复 | 停机后重启 server + clients，节点重新上线、组流量恢复 |

## 4. 本次测试发现并修复的真实缺陷

以下四处均先在远程环境复现，再修改代码、补充回归测试、重新交叉编译部署并复测通过；修改后本地 `gofmt/go build/go vet/go test -race ./...`（28 包）全部通过。

### 4.1 KICK 控制帧可能丢失（手动下线后 60s 才重连）

- 现象：面板强制下线 / `KickNode` 时若会话无在途流，服务端发送 KICK 后立即关闭传输；客户端可能只观察到“session drained/连接错误”，进入通用 1 分钟重连退避，而不是 KICK 的 1s 重连路径。实测偶发 60s 才恢复。
- 修复：`internal/tunnel/session.go` 在 `beginDrain` 成功发送 KICK 且无在途流时增加 **300ms KICK 送达宽限**（`kickDeliveryGrace`）再关闭传输。
- 回归：新增 `internal/tunnel/grace_test.go:TestKickDeliversControlFrameBeforeClose`；远程复测 kick 后 **1.8s** 完成重连，审计与流量均正常。

### 4.2 HELLO_ACK 拒绝原因可能丢失（错误令牌无限重试且无审计）

- 现象：错误节点令牌/版本不兼容时，服务端发送 `HELLO_ACK(ok=false)` 后立刻关闭会话，客户端常收不到拒绝原因，按传输错误 60s 退避重试（实测 >30s 不退出）；且服务端未写 `node.auth_failed` 审计。
- 修复：`internal/tunnel/session.go` `rejectHello` 发送 ACK 后增加 **250ms 送达宽限**（`helloRejectGrace`）；认证失败路径补充 `auditEvent("node.auth_failed", ...)`。
- 回归：新增 `internal/tunnel/grace_test.go:TestHelloRejectionDeliversAckBeforeClose`；远程复测错误令牌客户端 **1s 内 exit=1** 并打印明确原因，审计出现 `node.auth_failed`。

### 4.3 PROXY protocol v2 配置未接线（配置被静默忽略）

- 现象：`server.proxy_protocol: true` 只存在于配置结构，监听器未包装；发送 PROXY v2 头后 HTTP 代理返回 400（头被当作请求行），与 README/配置文档不符。
- 修复：
  - `internal/app/server.go`：共享 TCP 监听（面板/wss）在 TLS 前用 `proxyproto.NewListener(ln, 5s)` 包装；
  - `internal/app/gateway.go`：HTTP/SOCKS5 代理监听同样包装；
  - 采用 proxyproto 的“可选头”语义：无 PROXY 头的直连连接原样透传，避免破坏直连访问。
- 回归：新增 `internal/integration/proxyproto_test.go:TestProxyProtocolV2Listeners`（PROXY 头 + TLS 面板 200、代理 407、审计 source_ip 为伪造地址、无头直连仍正常）；远程复测三类入口全部通过。

### 4.4 面板 overview 的 retries 指标把失败请求当作重试

- 现象：`GET /overview` 的 `requests.retries` 与 `errors` 完全相等（远程实测 `errors=14, retries=14`）。原实现是在 `OnRequestEnd` 中只要请求失败就 `AddRetry()`，把 ACL 拒绝/认证失败等非重试失败计入重试；真实重试次数由 proxy 管线掌握。
- 修复：proxy `Options` 新增 `OnRetry` 回调，在管线每次透明重试处调用（与 `proxy_retries_total` 指标同点）；`app.panelDeps` 改为只在该回调中累加 overview retry 计数，`OnRequestEnd` 不再把失败当重试。
- 回归：新增 `internal/proxy/retry_callback_test.go:TestOnRetryCallback`；远程 1.0.4-test 复测：1 次 ACL 拒绝 + 1 次成功请求后 `overview.requests = {total:2, errors:1, retries:0}`，口径正确。

## 5. 配置/文档级改进建议（未改代码）

1. **egress 探测建议使用 family 专用端点**：默认 `api.ipify.org` 在测试环境不可达时，`icanhazip.com` 双栈可能返回 IPv6 导致 v4 探测失败。部署配置改为 `https://ipv4.icanhazip.com` / `https://ipv6.icanhazip.com` 后 v4/v6 均识别成功。建议在示例配置中把 family 专用端点放在首位。
2. **CA 模式下安装命令仍展示 pin**：`/nodes/{id}/install-command` 在 `tls.mode=ca` 时仍输出 `--pin '<sha256/…>'`（该 pin 是服务端证书 SPKI）。CA 模式下节点应使用系统根证书，建议按 tls 模式输出不同命令或标注“本参数仅 pin 模式需要”。
3. **滚动重启运维说明**：服务端优雅停机/重启会向节点发送 KICK(shutdown)，节点按设计干净退出（exit 0）；若 client systemd 单元使用 `Restart=on-failure` 则不会自动拉起。生产滚动重启后需重启 client 单元，或使用 `Restart=always` 并配合 `RestartSec`。

## 6. 最终部署状态

| 项目 | 值 |
|---|---|
| 面板地址 | `https://node.proxy.waadri.top/`（公共 CA 证书，浏览器不再告警） |
| HTTP 代理 | `node.proxy.waadri.top:8080`（auth required） |
| SOCKS5 | `node.proxy.waadri.top:1080`（auth required） |
| 隧道 | `443/tcp`（wss）+ `443/udp`（QUIC），节点 `node-a`/`node-b` 双平面 QUIC 在线；公网外部客户端 QUIC 与 IPv6 QUIC 均已实测通过 |
| 运维命令 | `systemctl {status,restart,stop} proxygw-test-server`；客户端 `proxygw-test-client-a|b` |
| 日志 | `journalctl -u proxygw-test-server -f`；`/opt/proxygw-test/`（配置/状态/二进制） |
| 测试辅助 | `/opt/proxygw-test/{origin.py,webhook.py}` 与对应 systemd 单元（仅回环，用于本地 origin 与告警接收） |

## 7. 复现命令（节选）

```bash
# 状态与健康
systemctl status proxygw-test-server
curl -s https://node.proxy.waadri.top/healthz
curl -s https://node.proxy.waadri.top/version

# 三入口（替换为实际代理凭据）
curl -s -x http://USER:PASS@node.proxy.waadri.top:8080 https://www.baidu.com/ -o /dev/null -w '%{http_code}\n'
curl -s --socks5-hostname USER:PASS@node.proxy.waadri.top:1080 https://www.baidu.com/ -o /dev/null -w '%{http_code}\n'

# ACL 安全默认（应 403）
curl -s -x http://USER:PASS@node.proxy.waadri.top:8080 http://127.0.0.1/ -o /dev/null -w '%{http_code}\n'
curl -s -x http://USER:PASS@node.proxy.waadri.top:8080 http://169.254.169.254/ -o /dev/null -w '%{http_code}\n'
```

> 备注：本轮测试使用了服务端进程环境变量 `NP_ACL_ALLOW_LOOPBACK_TARGETS=1` 以构造本地 origin 目标；**最终状态已移除该测试豁免并重启**，因此最终部署维持 ACL 强制默认拒绝（回环/私网/云元数据均 403）。
