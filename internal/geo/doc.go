// Package geo resolves node egress IP addresses and enriches them with
// geolocation and ASN metadata for the proxy gateway.
//
// Two independent pieces live here, matching chapter E of the project
// specification:
//
//   - Egress IP detection (EgressResolver): egress IPs are resolved with the
//     priority manual configuration > peer address observed on the tunnel >
//     configurable HTTPS IP echo endpoints (IPv4 and IPv6 probed separately,
//     2s timeout each, failure degrades gracefully). The result is a
//     presentation/dedup aid only: it is never used on the proxy request hot
//     path and this package never touches proxy traffic. The echo and the
//     geolocation lookups are separate configuration items.
//
//   - Geolocation providers (Resolver): a local MaxMind DB (MMDB) is the
//     primary layer; online providers only fill the fields the MMDB could not
//     provide. Online providers are opt-in (geo.remote_consent=true) because
//     they send node IP addresses to third parties. Three provider kinds are
//     supported and the response format is never sniffed: preset adapters with
//     fixed parsers, user templates with declarative field mappings (JSON path
//     or regex) and a strictly defined project JSON schema. Every resolved
//     field records which provider produced it (model.FieldSource) together
//     with the fetch time, results are cached per IP for 24 hours by default,
//     concurrent lookups of the same IP are coalesced, provider calls are rate
//     limited, capped in concurrency, timeout bounded and the remote URL is
//     protected against SSRF.
//
// 精度预期（必须向用户说明，不要承诺精准定位）：
//   - 国家级（ISO 3166-1 alpha-2）准确率较高，可用于展示与粗粒度筛选；
//   - 城市与 ISP 字段存在明显偏差，尤其在移动网络、NAT、企业出口与使用
//     VPN/代理的节点上；不要把城市字段用于风控级别的精确判定；
//   - ASN 相对可靠，但仍以运营商的注册数据为准。
//
// 隐私：默认只使用本地 MMDB。只有显式配置 geo.remote_consent=true 后，在线
// provider 才会被调用（节点 IP 会发送给第三方）；remote_consent=false 时不会
// 发出任何在线查询请求。Token 只出现在请求 URL 的 query 中，日志与错误信息
// 会抹掉 query，绝不记录 token。
//
// Lookups are only performed once per node registration or egress IP change by
// the caller and are cached here, so remote provider traffic stays negligible
// and never appears on the connection hot path.
package geo
