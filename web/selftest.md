# M6-A 内嵌管理面板前端 — 自测记录

> 交付范围：`web/index.html`、`web/app.js`、`web/style.css`（原生 HTML/CSS/JS，无框架、无 CDN、无外部字体/图标，离线可用）。
> `web/embed.go`（`//go:embed index.html app.js style.css`）由面板后端模块提供，本前端未修改，embed 列表与三个交付文件一致。
> API 契约唯一依据：`docs/PANEL_API.md`；本文件不修改契约。

## 1. 文件清单

| 文件 | 行数 | 说明 |
|---|---|---|
| `web/index.html` | 670 | SPA 骨架：登录视图、顶栏/导航、10 个页面静态结构、模态框/Toast 容器；无内联脚本、无内联事件、CSS 外链 |
| `web/app.js` | 4374 | 全部交互逻辑（IIFE 普通脚本，`defer` 加载）：API 客户端/CSRF/401、登录、hash 路由、SSE+轮询、各页面渲染与表单、模态框/Toast |
| `web/style.css` | 2359 | 深色运维主题（CSS 变量）、响应式断点（1400/1100/860/560px）、表格/卡片/表单/模态框/徽标/Toast 样式 |
| `web/selftest.md` | 本文件 | 页面与 API 映射、实现决策、自测方法与结果、已知限制 |

路径约定：`GET /` 由后端返回 `index.html`；`index.html` 以绝对路径 `/static/app.js`、`/static/style.css` 引用资源；其余资源 0 个（无字体/图片/图标文件，favicon 使用 `data:,` 占位避免额外 404）。

## 2. 页面清单

| 页面 | 路由 hash | 主要内容 |
|---|---|---|
| 登录 | 未登录时 | 用户名/密码/可选 TOTP、回车提交、loading、invalid_credentials / locked_out（含 retry_after_seconds）/ totp_required 中文提示 |
| 总览 | `#/overview` | 在线节点数/独立出口 IP 数/活跃连接数三张指标卡；请求/错误/重试/限流/熔断 5 张数字卡；15 分钟 SVG sparkline（requests/errors/active 三条线）；传输方式占比条；证书到期告警（<30 天黄、≤7 天红）；隧道会话、TopN、设置版本卡片 |
| 节点 | `#/nodes` | 16 列节点表（别名/ID、组、出口 IP、国家、城市、ASN、ISP、权重、在途、延迟、累计流量、熔断、版本、传输、在线、操作）；搜索/国家/ASN/组/仅在线/仅独立出口筛选 + 分页；行操作：编辑、拨测（ping/tcping/http/dns）、安装命令（Linux/Windows 代码块+复制）、强制下线（二次确认）；可见时 3s 自动刷新 / SSE 推送 |
| 节点组 | `#/groups` | 卡片列表（名称、选择器、显式加入/排除、成员数、更新时间）；新建/编辑模态框（name/description/tags_any/regions_any/nodes_add/nodes_remove）；成员预览（实时 `/members`）；删除二次确认（409 group_in_use 提示） |
| 凭据 | `#/credentials` | 表格（用户名、组、启用、过期、最近使用、用量、并发上限、操作）；新建/编辑（密码或服务端生成随机密码、组多选、启用、过期、并发、带宽、协议、来源 CIDR、备注）；生成密码仅展示一次并复制；踢会话、用量、可见节点（count+nodes）、删除确认 |
| 连接与规则 | `#/rules` | 路由与运行时设置快速编辑（策略/粘性/熔断/重试/限流/超时/压缩/默认 ACL 动作，保存/撤销/恢复默认，422 field_errors 内联标红）；粘性黑名单 CRUD + 试算（host/ip/port/node_id/groups → hit/rule_id/reason/forced_node_id）；ACL CRUD（order 排序、动作徽标 allow 绿/deny 红、删除确认）；强制默认拒绝清单只读折叠面板 |
| 运行设置 | `#/settings` | 全部 current 字段可编辑（24 项）；保存 PUT + 成功版本号提示；修改历史；撤销上次修改；恢复默认（二次确认） |
| 审计 | `#/audit` | 时间范围/action/actor/limit 筛选；表格（时间、操作者、来源、动作、对象、结果）；detail 展开 JSON 美化；加载更多（until 游标） |
| 证书 | `#/cert` | mode/pin/pin_next/not_after/last_reload/last_error；pin 复制；生成安装命令（Linux/Windows）；生成下一枚 pin（含轮换流程说明）；重载证书；到期告警 |
| 归属地 | `#/geo` | provider 表格（名称/类型/preset/启用/健康/连续失败/最后错误/优先级）；启用开关 PATCH；测试模态框（可选 IP、raw_snippet、提取结果、耗时、命中路径、错误） |
| 接入 | `#/access` | Linux/Windows 一键接入命令（自动填入当前 SPKI pin、token 占位）与复制；服务端 pin 展示/复制；节点接入令牌说明（首启打印/静态配置/mTLS；契约无签发吊销 API 时明确提示） |

## 3. 页面 → API 映射

所有请求前缀 `/api/v1`；非 GET 请求带 `X-CSRF-Token`（登录后从 `/login` 或 `/session` 响应取得并仅存内存），`fetch` 使用 `credentials: "same-origin"`。

| 页面 / 功能 | API |
|---|---|
| 登录 / 退出 / 登录态 | `POST /login`、`POST /logout`、`GET /session` |
| 实时推送 | `GET /events`（EventSource；`{"type":"snapshot"|"tick","overview":{...},"nodes":[...]}`） |
| 总览 | `GET /overview`、`GET /tunnel/sessions`、`GET /stats/topn?window=15m&n=10`（后两者失败时降级占位） |
| 节点列表/筛选/分页 | `GET /nodes?q=&country=&asn=&group=&online=1&unique=1&page=&size=` |
| 节点编辑/下线/拨测/安装命令 | `PATCH /nodes/{id}`、`POST /nodes/{id}/kick`、`POST /nodes/{id}/probe`、`GET /nodes/{id}/install-command`、`GET /nodes/install-template` |
| 节点组 | `GET/POST /groups`、`PATCH/DELETE /groups/{id}`、`GET /groups/{id}/members` |
| 凭据 | `GET/POST /credentials`、`PATCH/DELETE /credentials/{id}`、`POST /credentials/{id}/kick-sessions`、`GET /credentials/{id}/usage`、`GET /credentials/{id}/visible-nodes` |
| 运行设置 | `GET/PUT /settings`、`POST /settings/undo`、`POST /settings/reset` |
| 粘性黑名单 | `GET/POST /rules/sticky`、`PATCH/DELETE /rules/sticky/{id}`、`POST /rules/sticky/preview` |
| ACL | `GET/POST /rules/acl`、`PATCH/DELETE /rules/acl/{id}`、`GET /rules/acl/forced` |
| 审计 | `GET /audit?since=&until=&action=&actor=&limit=`（加载更多用 `until` 游标） |
| 证书 / 轮换 / 重载 | `GET /cert`、`POST /cert/rotate-pin`、`POST /cert/reload` |
| 归属地 provider | `GET /geo/providers`、`PATCH /geo/providers/{name}`、`POST /geo/providers/{name}/test` |

未在 UI 暴露的契约接口：`PUT /rules/acl`（全量替换；单条 CRUD 已覆盖运营场景）、节点令牌签发/吊销（契约本身未提供）。

## 4. 已实现交互与工程约束

- **CSP 兼容**：无内联 `<script>`、无 `onclick` 等内联事件属性、无 `javascript:` URL；所有事件通过 `addEventListener` + `data-action`/`data-id` 委托绑定；样式仅外链 CSS 与 JS CSSOM。无 CDN/外部字体/图标/图片，离线可用。
- **XSS 防护**：所有来自 API 的字符串一律通过 `textContent` / `createTextNode` / DOM 属性写入；全文件无 `innerHTML`、无 `insertAdjacentHTML`（静态自检强制校验）。另提供 `escapeHtml` 工具备用。
- **登录态与 CSRF**：启动 `GET /session` 判定；401 → 登录页；所有写请求带 `X-CSRF-Token`；`401 unauthorized` 或 `403 csrf_invalid` 统一清理状态回登录页并提示重新登录。
- **错误可见性**：网络错误/5xx 顶部持久横幅 + 重试按钮；4xx/校验错误 Toast；422 `field_errors` 在表单内标红对应字段并显示表单级错误条；SSE 断开显示降级横幅。
- **SSE + 轮询兜底**：`GET /events` 推送更新总览与节点轻量数据；断开后自动关闭并以 3s 轮询降级、指数退避（4s→30s）重连，连通后恢复推送；`document.hidden` 时暂停轮询并显示“已暂停”，恢复可见时立即刷新并重连。
- **模态框**：Esc 关闭、点击遮罩关闭、初始焦点进入首个输入、提交中按钮禁用防重复提交；删除/踢会话/恢复默认均有中文二次确认。
- **时间与单位**：本地化时间（`YYYY-MM-DD HH:mm:ss`）+ 相对时间（秒/分钟/小时/天前）；流量 B/KiB/MiB/GiB；延迟 ms；国家 ISO alpha-2 → 中文名+旗帜 emoji；ASN 显示 `AS15169` + 组织。
- **响应式/主题**：深色 CSS 变量主题；≥1400px 三列卡片网格，1100px 以下折叠导航，860px 以下单列、表格横向滚动（关键列 nowrap）。
- **中文界面**：全部 label/按钮/空状态/确认框/错误提示为中文。

## 5. 自测方法与结果

环境：Windows + Node v24.22.0（无浏览器交互环境，使用 jsdom 与 headless Edge 辅助）。

### 5.1 语法检查

```powershell
node --check web/app.js      # 通过（普通脚本，非 ES module）
go build ./web/              # 通过（embed 包可编译，index.html/app.js/style.css 均存在）
```

### 5.2 静态一致性检查（Node 脚本）

检查项与结果：

- CSP：外部脚本 `/static/app.js`、外部样式 `/static/style.css`；无内联 `<script>`、无内联事件属性、无 `javascript:`；
- 所有 `/static/*` 引用文件存在；
- `index.html` id 唯一；`app.js` 中 `$('id')` 引用均存在（或为动态生成）；
- `data-action`：html 21 个、JS 动态 18 个，共 39 个处理器全部注册；
- API 路径：`api()`/EventSource 使用 26 个字面量路径 + `/events`，全部可在 `docs/PANEL_API.md` 找到对应接口；
- 无 `innerHTML`/`insertAdjacentHTML`；`textContent=` 39 次、`createTextNode` 12 次；
- CSS class 引用无缺失定义。

结果：**通过，0 问题**。

### 5.3 本地静态服务器加载

将 `index.html` 放根、`app.js`/`style.css` 放 `static/`，用 `python -m http.server` 验证：

```
/                      HTTP 200  29828 bytes  text/html
/static/app.js         HTTP 200 169673 bytes  text/javascript
/static/style.css      HTTP 200  38981 bytes  text/css
STATIC SERVER TEST: PASS
```

无 404（favicon 通过 `data:,` 占位避免浏览器默认请求）。

### 5.4 jsdom DOM 级冒烟测试（登录/全部页面/弹窗/表单/SSE/CSRF）

用 jsdom 加载真实 `index.html` + `app.js`，stub 全部面板 API 与 EventSource，驱动完整用户流程。断言覆盖：

- 启动 401 → 登录页；登录失败显示中文错误；再次登录成功进入主界面并显示管理员名；
- 总览指标/sparkline 3 条折线/时钟偏移 chip 渲染；SSE tick 更新总览指标与时钟偏移；SSE nodes 轻量数据合并进节点表；
- 10 个页面逐一切换渲染（节点表 2 行、节点组卡片、凭据表、ACL/黑名单/强制拒绝清单、设置表单 4 组字段、审计 2 行+详情展开、证书 pin/到期告警、provider 表、接入命令）；
- 节点编辑、拨测、安装命令、节点组成员、可见节点、新建凭据（服务端生成密码一次性弹窗）、粘性规则/ACL 新建、pin 轮换、provider 测试等模态框开合；
- 点击遮罩关闭模态框、Esc 关闭；
- 保存运行设置成功；后端 422 `field_errors` → 表单错误条 + 字段标红；
- 48 次 API 请求、15 次写请求：除 `/login` 外全部携带 `X-CSRF-Token`；
- SSE 断开 → 降级横幅 + 3s 轮询；页面隐藏 → 暂停轮询；`403 csrf_invalid` → 回登录页；重新登录后退出登录正常。

结果：**全部断言通过，未捕获 JS 异常**（脚本位于临时目录，仅用于自测，不随仓库交付）。

### 5.5 headless 浏览器视觉抽查（临时 demo 数据，非仓库文件）

用 headless Edge 对 overview/nodes/narrow-nodes/groups/credentials/rules/settings/audit/cert/geo/access/login 截图抽查，确认：深色主题、卡片/表格/徽标/表单布局、窄屏（640px）单列+表格横向滚动、登录页居中布局均正常；据此修正了证书页 2×2 栅格、窄屏表格关键列 nowrap、凭据到期徽标措辞、接入页 pin 提示文案。截图保存在临时目录，不随仓库提交。

## 6. 与真实面板后端的对齐核对（只读检查 `internal/panel`）

- 静态服务：后端 `/static/*` 从 embed FS 根读取 `app.js`/`style.css`，`GET /` 及非 API 路径返回 `index.html`；与前端绝对路径约定一致。
- 安全头 CSP 为 `script-src 'self'`，前端无内联脚本，匹配。
- 登录/会话响应 `{username,expires,csrf,totp_enabled}`，锁定 429 带 `retry_after_seconds`，与前端处理一致。
- SSE 载荷确认为 `{type:"snapshot"|"tick", ts, overview:{...|clock_skew_ms...}, nodes:[{id,online,inflight,latency_ewma_ms,...}]}`，前端解析逻辑已覆盖（overview 全量刷新 + nodes 按 id 合并轻量字段）。
- 节点列表 `summary{nodes,online,unique_egress_ips}`、节点组 `member_count`、凭据写响应 `{credential,password?}`、设置 `{current,defaults,version,updated_by,history}`、证书字符串时间、provider `preset/priority`、安装模板已由服务端填入真实 pin（token 占位）等均与前端字段读取一致。
- 创建凭据未提供密码时后端自动生成并仅在响应返回一次明文，前端会弹出“凭据密码（仅显示一次）”模态框并提示复制。

## 7. 已知限制 / 需后端注意点

1. **契约中的 `clock_skew_ms` 未写入 `docs/PANEL_API.md`**：前端按“若 overview 返回则显示”实现（后端 `internal/panel` 已返回该字段），不影响契约约定字段。
2. **SSE tick 只携带轻量节点字段**：若后端某次 tick 的 `nodes` 为空或缺少字段，前端会以最多 3s 一次的静默 `GET /nodes` 兜底，保证节点页仍是 3s 刷新语义；SSE 不可用时自动降级为 3s 轮询（页面隐藏暂停）。
3. **审计“加载更多”使用 `until` 时间游标**（契约未提供 offset）：若后端返回顺序非按时间倒序，可能出现少量重复/遗漏；建议后端保证 `items` 按时间倒序。
4. **节点接入令牌**：契约未提供签发/吊销 API，前端在「接入」页明确提示“通过服务端首次启动打印或静态 token 配置”，不做伪造接口；后端若后续补充接口，前端可按同样模式加页。
5. **ACL 全量替换 `PUT /rules/acl` 未在 UI 暴露**，前端使用单条 CRUD；如需要批量导入可后续补充。
6. **证件表单字段**：编辑凭据清空过期时间时会发送 `"expires_at": null`（后端 `optionalTime` 支持 null 清除）；如后端实现变化需注意。
7. **浏览器视觉验收**：本环境无真实浏览器交互，仅使用 jsdom 功能级验证 + headless Edge 静态截图抽查；真实浏览器中的剪贴板 API（HTTPS 才可用，HTTP 下回退 `execCommand`）与系统字体渲染差异需在面板 HTTPS 环境做最终确认。
8. **面板默认 HTTPS + Secure Cookie**：若以 HTTP 方式直接访问，浏览器不会回传 Secure Cookie，登录态会立即 401；这属于部署形态（应使用 HTTPS 或 TLS 终止后的可信环境），前端无法绕开。
