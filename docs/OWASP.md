# OWASP Security Considerations

This document maps BareMetalWeb's security controls to the OWASP Top 10 (2021).

## A01:2021 — Broken Access Control

- **Route-level permissions**: Every route declares `PermissionsNeeded` — `Public`, `AnonymousOnly`, `Authenticated`, or comma-separated permission strings. Enforced in `RequestHandler` before dispatching.
- **Entity-level permissions**: `[DataEntity(Permissions = "...")]` gates CRUD API access per entity type.
- **MCP/Cluster auth**: MCP endpoints require authentication; cluster endpoints require admin/monitoring permissions.
- **CSRF protection**: Form POSTs validated via `CsrfProtection.ValidateFormToken()`. API writes use Content-Type validation (non-simple types trigger CORS preflight).

## A02:2021 — Cryptographic Failures

- **Password hashing**: PBKDF2 with per-user salt (configurable iteration count).
- **Session cookies**: AES-256-GCM encrypted + HMAC via `CookieProtection`. Keys stored in `{dataRoot}/.keys/`.
- **API keys**: Stored as PBKDF2 hashes; raw key shown only once at creation.

## A03:2021 — Injection

- **XSS**: Page renderer validates link URLs via `IsSafeUrl()` (http/https/mailto/relative only). Raw HTML sanitized via `SanitizeHtml()` stripping dangerous attributes (`on*`, `style`, `javascript:`).
- **Path traversal**: Proxy strips `..` segments from request paths. Static file handler rejects paths with `..`.

## A04:2021 — Insecure Design

- **Query caps**: Tree/orgchart queries capped at `Top(10000)`. Batch operations capped at 500 items. FK traversals capped at 20 per entity.
- **Body size limits**: 10 MB limit on all write endpoints.

## A05:2021 — Security Misconfiguration

- **Security headers**: CSP with nonce, HSTS (HTTPS only), `X-Content-Type-Options: nosniff`.
- **Error sanitization**: Exception messages and entity type names stripped from API error responses.

## A07:2021 — Identification and Authentication Failures

- **Rate limiting**: Login, registration, device code, and MFA endpoints rate-limited (5-10 attempts per 60s window per IP/user).
- **MFA support**: TOTP-based MFA for enrolled users.
- **Session management**: Sliding expiry (8h standard, 30d remember-me). Sessions revoked on logout.

## A08:2021 — Software and Data Integrity Failures

- **WAL integrity**: Append-only write-ahead log with checksums. Atomic commit operations.
- **CSRF tokens**: HMAC-based, tied to session ID, 1-hour expiry.

## A09:2021 — Security Logging and Monitoring Failures

- **Session logging**: `SessionLog` entity tracks user activity.
- **Request tracking**: `ClientRequestTracker` monitors per-IP request rates with lock-free `ConcurrentDictionary` implementation.
- **Cluster status**: Health endpoint exposes cluster state and leader election status.

## A10:2021 — Server-Side Request Forgery (SSRF)

- **Proxy SSRF protection**: `IsPrivateOrMetadataHost()` blocks RFC 1918, link-local (169.254.x.x), and loopback addresses. Returns 502 instead of forwarding.
- **Path traversal**: Proxy strips `..` from forwarded paths.