// Package auth implements the two authentication domains of the gateway:
//
//   - proxied client credentials (CredentialStore): multiple proxy accounts with
//     argon2id password hashes, group bindings, expiry, enable/disable, protocol
//     and source network restrictions, last-used tracking and traffic counters;
//   - the operations panel administrator (AdminManager): password hash
//     verification (argon2id or bcrypt), per-source-IP login rate limiting and
//     lockout, RFC 6238 TOTP second factor and HS256 JWT session tokens.
//
// Runtime objects are persisted as JSON with the crash safe
// temp-file+fsync+atomic-rename scheme from internal/store; a corrupted primary
// file falls back to its ".bak" copy. An empty store path keeps the store purely
// in memory (used by tests and by ephemeral deployments).
//
// Secrets are never logged: only usernames, source addresses and decisions are
// emitted. Failed verifications return typed errors (VerifyError and the
// sentinel errors below) so callers can write audit records without leaking
// which part of the credential was wrong.
package auth
