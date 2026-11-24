// Package panel implements the administrative HTTP API and the embedded web UI
// service required by docs/PANEL_API.md.
//
// # Dependencies
//
// The panel only imports the finished domain packages (auth, groups, rules,
// registry, settings, audit, acl, metrics, certs, model, protocol, version).
// The packages that are still being written in parallel (tunnel, geo, sched,
// stats) are injected through the small interfaces declared in api.go, so the
// panel never imports them and can be tested with fakes.
//
// # Authentication model
//
// POST /api/v1/login verifies the configured administrator through
// auth.AdminManager.Authenticate (which also enforces the per-IP login rate
// limit and lockout). On success the panel issues:
//
//   - np_admin: the HS256 JWT, HttpOnly; Secure (when served over TLS);
//     SameSite=Strict; Path=/;
//   - np_csrf: a random URL-safe token, same attributes except HttpOnly is off
//     so the frontend JavaScript can read it.
//
// Every other /api/v1 request requires a valid np_admin cookie (401
// {"error":"unauthorized"} otherwise). Every write request (POST/PATCH/PUT/
// DELETE) additionally requires the X-CSRF-Token header to equal the np_csrf
// cookie (constant-time compare, 403 {"error":"csrf_invalid"}).
//
// Note: docs/PANEL_API.md describes the CSRF token as a JWT claim. The auth
// manager's IssueToken does not put a csrf claim into the JWT, so the panel
// implements the double-submit-cookie variant instead; the validation surface
// (header vs cookie) is identical for the frontend.
//
// # SSE payload (GET /api/v1/events)
//
// Every `data:` line is one JSON object:
//
//	{
//	  "type": "snapshot" | "tick",
//	  "ts": 1730000000000,
//	  "overview": { ...same shape as GET /api/v1/overview... },
//	  "nodes": [
//	    {"id","alias","online","enabled","weight","transport","planes",
//	     "inflight","latency_ewma_ms","bytes_in","bytes_out","breaker_state",
//	     "egress_ip","geo","version","runtime","update_capable","update",
//	     "groups","last_heartbeat"}
//	  ]
//	}
//
// A snapshot is sent immediately on connect, a tick every 3 seconds and after
// every successful mutation. Comment heartbeat lines `: ping` are sent every
// 15 seconds. The response is text/event-stream with Cache-Control: no-cache
// and X-Accel-Buffering: no.
//
// # Static assets
//
// Options.WebFS must contain index.html, app.js and style.css at its root.
// /static/<name> serves those files with a content type derived from the file
// extension; unknown /static paths return 404. Every other non-API path returns
// index.html so the frontend can own client side routing.
package panel
