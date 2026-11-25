# 管理面板 API 契约（v1）

所有接口前缀 `/api/v1`，返回 `application/json`。除 `POST /login` 与静态资源外都需要登录 Cookie。

## 认证

- Cookie：`np_admin=<JWT>`，`HttpOnly; Secure; SameSite=Strict; Path=/`。
- 登录成功后返回 CSRF token；所有写操作（POST/PATCH/PUT/DELETE）必须带请求头 `X-CSRF-Token`，与 JWT claims 中的 `csrf` 一致，否则 `403 csrf_invalid`。
- 未登录返回 `401 {"error":"unauthorized"}`。
- 登录失败按 IP 限速/锁定，返回 `429 {"error":"locked_out","retry_after_seconds":N}` 或 `401 {"error":"invalid_credentials"}`。
- TOTP 启用时登录需 `totp` 字段；缺失返回 `401 {"error":"totp_required"}`。

| 方法 | 路径 | 请求 | 响应 |
|---|---|---|---|
| POST | `/login` | `{username,password,totp?}` | `{username,expires,csrf,totp_enabled}` |
| POST | `/logout` | — | `{ok:true}` |
| GET | `/session` | — | `{username,expires,csrf,totp_enabled}` |
| GET | `/events` | SSE | `text/event-stream`，`data: {"type":"snapshot"|"tick",...}` |

## 总览

`GET /overview`
```json
{
  "version": {"version":"dev","commit":"none","build_time":"unknown","go_version":"go1.22"},
  "online_nodes": 3,
  "nodes_total": 4,
  "unique_egress_ips": 2,
  "active_connections": 17,
  "transport_mix": {"quic": 4, "ws": 2},
  "requests": {"total": 12345, "errors": 12, "retries": 3, "rate_limited": 0, "breaker_trips": 0},
  "trend": [{"ts": 1730000000, "requests": 120, "errors": 1, "active": 17}],
  "settings_version": 3,
  "cert": {"mode":"pin","pin":"sha256/...","pin_next":"","not_after":"2027-01-01T00:00:00Z"}
}
```

## 节点

- `GET /nodes?q=&country=&asn=&isp=&group=&online=&unique=1&page=1&size=50`
  → `{items:[Node], total, summary:{nodes,online,unique_egress_ips}}`
  - `Node`：`id, alias, region, isp_label, tags, weight, enabled, online, egress_ip{v4,v6,source}, geo{country,region,city,asn,asn_org,isp,sources}, inflight, bytes_in, bytes_out, latency_ewma_ms, breaker_state, last_heartbeat, version, groups, transport, planes, duplicate_of, created_at, updated_at`
- `PATCH /nodes/{id}`：`{alias?,tags?,weight?,region?,isp_label?,enabled?}` → `Node`（写审计）
- `POST /nodes/{id}/kick`：`{reason?}` → `{ok:true}`（强制下线，写审计）
- `POST /nodes/{id}/probe`：`{kind:"ping"|"tcping"|"http"|"dns", target?, payload_b64?}`
  → `{ok, latency_ms, detail, result_b64, error}`（写审计）
- `GET /nodes/{id}/install-command` → `{command, pin, server_url}`（不含接入令牌）
- `GET /nodes/install-template` → `{linux:"...", windows:"..."}`（令牌占位符）
- `GET /nodes/tokens` → `{items:[{node_id,note,revoked,created_at}]}`（不返回 token/hash）
- `POST /nodes/tokens`：`{node_id,note?}` → `201 {token, node:{node_id,note,revoked,created_at}}`
  - 令牌只在响应中返回一次，服务端仅保存哈希；写审计 `token.create`
- `DELETE /nodes/tokens/{id}` → `{ok:true}`（吊销该节点全部令牌并踢下线；写审计 `token.revoke`）
- 注：`config.server.yaml` 中 `node_id: "*"` 的静态共享令牌只由配置文件管理，不出现在列表接口中，也不能通过面板吊销。

## 节点组

- `GET /groups` → `{items:[{id,name,description,match,nodes_add,nodes_remove,created_at,updated_at,member_count}]}`
- `POST /groups`：`{name,description?,match?,nodes_add?,nodes_remove?}` → `Group`
- `PATCH /groups/{id}`：同上字段 → `Group`
- `DELETE /groups/{id}` → `{ok:true}`（被凭据引用时 409 `group_in_use`）
- `GET /groups/{id}/members` → `{nodes:[Node], count}`
- `GET /credentials/{id}/visible-nodes` → `{count, nodes:[Node]}`（某凭据当前可见节点数，实时）

## 凭据

- `GET /credentials` → `{items:[Credential]}`（绝不返回 password_hash）
- `POST /credentials`：`{username,password?,groups?,enabled,expires_at?,max_concurrent?,bandwidth_kbps?,allowed_protocols?,source_cidrs?,note?,generate_password?}`
  → `{credential:Credential, password?: "仅 generate_password 时返回一次"}`
- `PATCH /credentials/{id}`：字段子集（含 `password` 或 `generate_password:true`）
- `DELETE /credentials/{id}` → `{ok:true}`（同时踢掉该凭据已有会话）
- `POST /credentials/{id}/kick-sessions` → `{kicked:n}`（立即失效，写审计）
- `GET /credentials/{id}/usage` → `{last_used_at, bytes_in, bytes_out, active_connections}`

## 规则（ACL / 粘性黑名单）

- `GET /rules/acl` → `{items:[ACLRule], default_action}`
- `PUT /rules/acl`：`{items:[ACLRule]}` → 全量替换（校验失败 422 + 字段错误）
- `POST /rules/acl`：ACLRule → ACLRule
- `PATCH /rules/acl/{id}`：部分字段
- `DELETE /rules/acl/{id}` → `{ok:true}`
- `GET /rules/acl/forced` → `{items:[{name,cidrs,ports,reason}]}`（不可关闭清单）
- ACLRule 的 `action` 为 `allow` / `deny` / `route`；`route` 必须同时提供非空 `node_groups`，命中的目标会强制使用这些节点组并覆盖凭据绑定的组（组内无可用节点时 fail-closed 503）。
- `GET /rules/sticky` → `{items:[StickyRule]}`
- `POST /rules/sticky` / `PATCH /rules/sticky/{id}` / `DELETE /rules/sticky/{id}`
- `POST /rules/sticky/preview`：`{host?,ip?,port?,node_id?,groups?}` → `{hit:true, rule_id, reason, forced_node_id}`（试算命中）

## 运行设置

- `GET /settings` → `{current:Settings, defaults:Settings, version, updated_by, history:[{version,updated_at,updated_by}]}`
- `PUT /settings`：`{settings:Settings}` → 校验通过 `{current,version}`；失败 `422 {error, field_errors:[]}` 且旧值不变
- `POST /settings/undo` → `{current,version}`
- `POST /settings/reset` → `{current,version}`（恢复配置文件默认）

## 审计

`GET /audit?since=RFC3339&until=RFC3339&action=&actor=&limit=200` → `{items:[{id,time,actor,source_ip,action,object,result,detail}]}`（敏感字段已脱敏）

## 隧道状态

`GET /tunnel/sessions` → `{items:[{node_id,node_alias,transport,state,planes,epoch,last_error,connected_since,last_heartbeat}], transport_mix:{quic:n,ws:n}}`

## 证书与轮换

- `GET /cert` → `{mode,pin,pin_next,cert_path,key_path,not_after,last_reload,last_error}`
- `POST /cert/rotate-pin` → `{pin, message}`：生成新密钥对到 `state/certs/next/` 并返回新 SPKI pin（不切换，供面板展示 pin_next / 下发节点）
- `POST /cert/reload` → `{ok:true}`（触发 ca 模式证书热重载）

## 归属地 provider

- `GET /geo/providers` → `{items:[{name,type,preset,enabled,healthy,failures,last_error,priority}]}`
- `PATCH /geo/providers/{name}`：`{enabled:bool}` → 状态
- `POST /geo/providers/{name}/test`：`{ip?}` → `{provider,ip,raw_snippet,result{...},duration_ms,hit_paths,error}`

## 统计

- `GET /stats/topn?window=15m&n=10` → `{windows:"15m", targets:[{target,count,bytes,errors}], nodes:[...], credentials:[...]}`

## 错误格式

```json
{"error":"机器可读错误码","message":"中文说明","field_errors":[{"field":"admin.username","message":"..."}]}
```

常见错误码：`unauthorized`、`csrf_invalid`、`invalid_credentials`、`totp_required`、`locked_out`、`not_found`、`validation_failed`、`conflict`、`internal_error`。

## 面板安全响应头

`Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'`
`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`、`Cache-Control: no-store`（API）。
