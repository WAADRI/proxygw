# internal/acl：访问控制与强制默认拒绝

本包实现 `go-multi-node-proxy-prompt.md` G.1/G.2 的 ACL 引擎，被代理入口（HTTP/CONNECT/SOCKS5）
与面板共用。只依赖标准库与 `internal/model`。

## 评估顺序（固定，不可配置）

1. **强制默认拒绝清单**先于一切用户规则执行，任何 allow 规则都不能放行；
2. **用户规则**按 `Order` 升序匹配（相同 `Order` 保持配置顺序）。一条规则的各个非空维度
   必须同时命中（来源 CIDR、目标 host、端口、协议），维度内部任一项命中即可。第一条命中的
   规则立即决定结果（allow 放行 / deny 拒绝）并停止扫描；
3. 无规则命中时读取动态默认动作（`Options.DefaultAction`，通常接
   `Settings().DefaultACLAction`）。非法值按 allow 处理，`Explain` 的 `Reason` 会记录原始值。

## 强制默认拒绝清单（不可关闭，只可追加 ACL deny）

| Name | 内容 | 测试开关豁免 | 说明 |
|---|---|---|---|
| `cloud_metadata` | `169.254.169.254/32`、`fe80::a9fe:a9fe/128` | 否 | 云元数据端点，防凭据窃取 |
| `loopback` | `127.0.0.0/8`、`::1/128` | 是 | 回环 |
| `private_network` | `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` | 是 | 私有网段 |
| `unique_local_ipv6` | `fc00::/7` | 是 | IPv6 唯一本地地址 |
| `link_local` | `169.254.0.0/16`、`fe80::/10` | 是 | 链路本地 |
| `unspecified` | `0.0.0.0/8`、`::/128` | 否 | 未指定地址 |
| `cgnat` | `100.64.0.0/10` | 否 | 运营商级 NAT 网段 |
| `loopback_hostname` | `localhost`、`*.localhost`、`localhost.localdomain`、`ip6-localhost`、`ip6-loopback` | 是 | 按字面量匹配的回环主机名 |
| `high_risk_ports` | `25`、`135`、`139`、`445`、`6379` | 是 | 任何目标、任何协议均拒绝 |

`ForcedDenies()` 返回上述清单的副本，供面板展示「不可关闭」的安全基线。

## 域名匹配语义（`ACLRule.Domains`）

- `example.com`：仅精确匹配裸域名，不匹配子域；
- `.example.com`：匹配裸域名与所有子域（`a.example.com`、`a.b.example.com`）；
- `*.example.com`：仅匹配子域，**不匹配裸域名**；
- `10.0.0.0/8`、`8.8.8.8`、`::1`：按 IP/CIDR 匹配 IP 字面量目标；
- 大小写不敏感，忽略一个尾部根点（`example.com.` 等价 `example.com`）。

`ACLRule.SrcCIDRs`、`ACLRule.Domains` 中的 IP 条目支持 CIDR 与裸 IP（按 /32、/128 处理）。
`ACLRule.Ports` 每项为单端口（`443`）或闭区间（`8000-9000`），不支持逗号；空表示任意端口。
协议仅接受 `http`、`connect`、`socks5`、`tcp`，空表示任意；`http` 与 `connect` 是两个不同协议。

## 不做 DNS 解析

引擎**不解析域名**：目标是域名时只按字面量与域名规则匹配，强制 IP 清单无法事先知道解析结果，
因此节点侧解析出 IP 后必须再做一次内网/回环/链路本地/云元数据校验。`localhost` 等字面回环主机名
由强制清单按名字拦截。

## 测试专用开关（生产严禁开启）

```text
NP_ACL_ALLOW_LOOPBACK_TARGETS=1
```

或 `acl.Options{AllowLoopbackTargets: true}`。开启后**仅**豁免回环、私有网段、链路本地、
IPv6 唯一本地地址、回环主机名与高风险端口清单——这些是进程内测试访问本机 echo/HTTP 服务所需要的。
云元数据端点、`0.0.0.0/8`/`::/128`、`100.64.0.0/10` **仍然拒绝**，用户 ACL 规则与默认动作也照常生效。
该开关只用于自动化集成测试；生产默认关闭，也不应出现在任何部署配置中。

## 并发与原子性

`SetRules` 先完整编译校验，成功后一次性替换已编译规则快照；失败时旧规则原样保留。
`Check`/`Explain` 只对当前快照取一次读锁，规则编译不在请求热路径。`Rules()`/`ForcedDenies()`
返回深拷贝。`Engine` 零值即可用（无规则、默认 allow、强制清单生效）。
