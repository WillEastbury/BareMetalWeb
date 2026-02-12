# Code Review Findings

## Security

1. **Template token replacement emits raw values without HTML encoding**
   - **Location**: `BareMetalWeb.Rendering/HtmlRenderer.cs` (RenderSection, around lines 109-207)
   - **Details**: `RenderSection` writes template token values (`values`, `appvalues`, scoped values) directly to the response without HTML encoding. If any of these values can contain user input, a template token could inject raw HTML/JS.
   - **Recommendation**: Apply HTML encoding by default for string tokens, or clearly document that callers must pre-encode user-supplied values.

2. **CSP allows inline script/style**
   - **Location**: `BareMetalWeb.Host/BareMetalWebServer.cs` (ContentSecurityPolicy constant, line 13)
   - **Details**: `script-src` and `style-src` include `'unsafe-inline'`, which weakens CSP protections against XSS.
   - **Recommendation**: Replace inline allowances with nonces/hashes or remove `'unsafe-inline'` if feasible.

3. **Unencoded CSS class in action links**
   - **Location**: `BareMetalWeb.Rendering/TableActionRenderer.cs` (lines 20-24, 46-50)
   - **Details**: In the non-CSRF branches, `action.ButtonClass` is injected into HTML without encoding. If action data can be user-supplied, this could enable attribute injection.
   - **Recommendation**: HTML encode or validate `ButtonClass` for all branches.

## Correctness / Behavior

1. **Blank permissions deny access by default**
   - **Location**: `BareMetalWeb.Host/BareMetalWebServer.cs` (IsAuthorized, lines 464-472)
   - **Details**: `IsAuthorized` returns `false` when `PermissionsNeeded` is empty, which means routes without explicit permissions return 403 even if they should be public.
   - **Recommendation**: Confirm this is intentional; if not, default to `Public` or enforce metadata validation at route registration.

2. **Session expiration is fixed (no sliding window)**
   - **Location**: `BareMetalWeb.Host/UserAuth.cs` (GetSession / GetSessionAsync, lines 43-87)
   - **Details**: Sessions are revoked once `ExpiresUtc` is reached, but `LastSeenUtc` or `ExpiresUtc` are not updated on access. Active users will be logged out at TTL even with continuous use.
   - **Recommendation**: If a sliding expiration model is desired, update `LastSeenUtc` and extend `ExpiresUtc` on access.

## Performance / Resilience

1. **Sync wrappers block on async operations**
   - **Location**: `BareMetalWeb.Data/DataObjectStore.cs` (Save/Load/Query/Delete, lines 37-80)
   - **Details**: Synchronous methods call async methods via `GetAwaiter().GetResult()`, which can block threads and risk deadlocks in sync contexts.
   - **Recommendation**: Either provide true sync provider implementations or document the blocking behavior and encourage async use.

2. **Thread.Sleep during log IO retries**
   - **Location**: `BareMetalWeb.Host/DiskBufferedLogger.cs` (AppendTextShared, lines 159-173)
   - **Details**: Logger uses `Thread.Sleep` for retry backoff, which blocks the thread during error handling.
   - **Recommendation**: Consider async backoff or bounded retries if logging becomes a hot path.
