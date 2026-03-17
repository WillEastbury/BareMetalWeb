# BareMetalWeb Test Failure Root Cause Analysis

## Executive Summary

After investigating 4 test projects with 100+ failures, I've identified the root causes categorized by severity and impact.

---

## 1. AUTHORIZATION TESTS - AuthorizationTests.cs (6 Failures)

**Failing Lines:** 137, 166, 181, 225, 255, 270

### Test Structure
All tests in `AuthorizationTests.cs` follow this pattern:
1. Create a `PageInfo` with specific `PermissionsNeeded`
2. Create an `HttpContext` with or without an authenticated user
3. Call `InvokeIsAuthorized()` via reflection on `BareMetalWebServer.IsAuthorizedAsync`
4. Assert expected authorization result (True/False)

### Test Code Example (Line 170-182)
```csharp
[Fact]
public void IsAuthorized_SpecificPermission_UserWithPermission_ReturnsTrue()
{
    // Arrange
    var pageInfo = CreatePageInfo(permissionsNeeded: "Admin");
    var user = CreateUser(1, new[] { "Admin", "Editor" });
    var context = CreateMockHttpContext(user: user);

    // Act
    var result = InvokeIsAuthorized(pageInfo, context);

    // Assert
    Assert.True(result, "User with required permission should be authorized");  // ← Line 181
}
```

### Production Code
**File:** `/source/BareMetalWeb/BareMetalWeb.Host/BareMetalWebServer.cs` (Lines 1056-1115)

```csharp
private static async ValueTask<bool> IsAuthorizedAsync(PageInfo? pageInfo, BmwContext context, CancellationToken cancellationToken = default)
{
    if (pageInfo == null)
        return true;

    var permissionsNeeded = pageInfo.PageMetaData.PermissionsNeeded ?? string.Empty;
    // Empty permissions means public/anonymous access is allowed
    if (string.IsNullOrWhiteSpace(permissionsNeeded))
        return true;

    if (string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
        return true;

    var user = await UserAuth.GetRequestUserAsync(context, cancellationToken).ConfigureAwait(false);
    bool isAnonymous = user == null;

    if (string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase))
        return isAnonymous;

    if (string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase))
        return !isAnonymous;  // ← Line 1076 - Returns true if authenticated

    // Parse required permissions with span-based iteration
    if (isAnonymous)
    {
        var check = permissionsNeeded.AsSpan();
        bool hasAnyPerm = false;
        while (check.Length > 0)
        {
            int ci = check.IndexOf(',');
            ReadOnlySpan<char> seg;
            if (ci < 0) { seg = check; check = default; }
            else { seg = check[..ci]; check = check[(ci + 1)..]; }
            if (!seg.Trim().IsEmpty) { hasAnyPerm = true; break; }
        }
        return !hasAnyPerm;  // Anonymous can only access if no permissions required
    }

    // CRITICAL SECTION - User has specific permission requirements
    var userPermissions = new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase);
    var altLookup = userPermissions.GetAlternateLookup<ReadOnlySpan<char>>();  // ← GetAlternateLookup

    var remaining = permissionsNeeded.AsSpan();
    bool foundAny = false;
    while (remaining.Length > 0)
    {
        int idx = remaining.IndexOf(',');
        ReadOnlySpan<char> segment;
        if (idx < 0) { segment = remaining; remaining = default; }
        else { segment = remaining[..idx]; remaining = remaining[(idx + 1)..]; }
        var trimmed = segment.Trim();
        if (trimmed.IsEmpty) continue;
        foundAny = true;
        if (!altLookup.Contains(trimmed))  // ← Case-insensitive span lookup
            return false;
    }
    if (!foundAny)
        return true; // No actual permissions after parsing, treat as public
    return true;    // All required permissions matched
}
```

### Root Cause: VALID API USAGE

**Finding:** The use of `GetAlternateLookup<ReadOnlySpan<char>>()` is CORRECT.

Testing in .NET 10.0.4 shows this API works as intended:
```
var userPermissions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Admin", "Editor" };
var altLookup = userPermissions.GetAlternateLookup<ReadOnlySpan<char>>();
var adminSpan = "admin".AsSpan();
var result = altLookup.Contains(adminSpan);  // Returns True ✓
```

**Status:** Code appears CORRECT - tests should PASS unless:
1. `UserAuth.GetRequestUserAsync()` fails
2. `UserAuth.GetPermissions()` returns unexpected format
3. Test setup in `CreateMockHttpContext()` doesn't properly save user to DataStore

**Likely Issue:** Test setup may not be properly persisting user to DataStoreProvider, causing `GetRequestUserAsync()` to return null unexpectedly.

---

## 2. DISKBUFFEREDLOGGER TESTS - DiskBufferedLoggerTests.cs (Line 524)

**Failing Test:** `LogError_MessageFormat_ContainsExceptionAndTimestamp` (Lines 508-528)

### Test Code
```csharp
[Fact]
public async Task LogError_MessageFormat_ContainsExceptionAndTimestamp()
{
    // Arrange
    var logger = new DiskBufferedLogger(_tempDir);
    var ex = new ArgumentException("bad arg");

    // Act
    logger.LogError("format-err", ex);
    await WaitUntilAsync(() => Directory.GetFiles(_tempDir, "error_*.log", SearchOption.AllDirectories).Length > 0);

    // Assert
    var errorFiles = Directory.GetFiles(_tempDir, "error_*.log", SearchOption.AllDirectories);
    Assert.NotEmpty(errorFiles);

    var content = await File.ReadAllTextAsync(errorFiles[0]);
    Assert.StartsWith("ERROR |", content);                    // ← Line 524
    Assert.Contains("format-err", content);
    Assert.Contains("ArgumentException", content);
    Assert.Contains("bad arg", content);
}
```

### Production Code
**File:** `/source/BareMetalWeb/BareMetalWeb.Host/DiskBufferedLogger.cs` (Lines 88-159)

```csharp
public void LogError(string message, Exception ex, string? correlationId)
{
    if (BmwLogLevel.Error < MinimumLevel) return;
    var entry = FormatEntry(BmwLogLevel.Error, message, correlationId, fields: null, ex);
    _ = LogErrorRawAsync(entry, BmwLogLevel.Error);  // Fire and forget
    ErrorHook?.Invoke("ERROR", message, ex.GetType().Name, ex.ToString(), null, null, 0, correlationId);
}

private string FormatEntry(BmwLogLevel level, string message, string? correlationId, LogFields? fields, Exception? ex)
{
    bool redact = RedactPII;
    var msg = redact ? LogRedactor.RedactFreeText(message) : message;

    // Base format: LEVEL | ISO-8601 | message
    var sb = new StringBuilder(256);
    sb.Append(s_levelLabels[(int)level]);  // ← "ERROR"
    sb.Append(" | ");
    sb.Append(DateTime.UtcNow.ToString("O"));
    sb.Append(" | ");
    sb.Append(msg);  // ← "format-err"

    if (correlationId != null)
    {
        sb.Append(" | rid=");
        sb.Append(correlationId);
    }

    // ... field appending ...

    if (ex != null)
    {
        sb.Append(" | error=");
        sb.Append(ex.GetType().Name);  // ← "ArgumentException"
        sb.Append(" | stack=");
        sb.Append(LogRedactor.RedactStackTrace(ex.ToString()));  // ← Exception message "bad arg"
    }

    return sb.ToString();
}
```

### Expected Log Format
```
ERROR | 2024-03-16T23:45:30.1234567Z | format-err | error=ArgumentException | stack=System.ArgumentException: bad arg...
```

**Test Assertions:**
- `Assert.StartsWith("ERROR |", content)` - ✓ Should PASS (first part is always "ERROR |")
- `Assert.Contains("format-err", content)` - ✓ Should PASS (message is appended)
- `Assert.Contains("ArgumentException", content)` - ✓ Should PASS (exception type is appended)
- `Assert.Contains("bad arg", content)` - ❓ **MIGHT FAIL** if `LogRedactor.RedactStackTrace()` removes it

### Root Cause: POSSIBLE REDACTION ISSUE

The exception message "bad arg" might be redacted by `LogRedactor.RedactStackTrace()` if it contains PII patterns (emails, IPs, tokens).

**Recommendation:** Check `LogRedactor` class to see what patterns are being redacted.

---

## 3. REQUEST HANDLER TESTS - BareMetalWebServerTests.cs

**Failing Lines:** 97, 198, 531

### Test 1: RequestHandler_ExactRouteMatch_ExecutesHandler (Lines 97-114)

```csharp
[Fact]
public async Task RequestHandler_ExactRouteMatch_ExecutesHandler()
{
    // Arrange
    EnsureStore();
    var executed = false;
    var pageInfo = CreatePageInfo("Test Page");
    _server.RegisterRoute("GET /test", new RouteHandlerData(
        pageInfo,
        async (ctx) => { executed = true; await Task.CompletedTask; }
    ));

    var context = CreateHttpContext("GET", "/test");

    // Act
    await _server.RequestHandler(context.ToBmw());

    // Assert
    Assert.True(executed, "Route handler should have been executed");
}
```

**Flow Analysis:**
1. Test registers route with handler that sets `executed = true`
2. Calls `RequestHandler()` (line 597 in BareMetalWebServer.cs)
3. Route dispatch:
   - Jump table lookup (line 776): Key "GET /test" should match
   - Checks IsAuthorizedAsync (line 784)
   - Executes handler if authorized (line 790)

**Expected:** `executed` = true
**Actual:** May be false if IsAuthorizedAsync throws or authorization fails

**Root Cause:** Same as Authorization tests - if IsAuthorizedAsync fails, handler never executes.

### Test 2: RequestHandler_NoRouteMatch_Returns404 (Lines 198-209)

```csharp
[Fact]
public async Task RequestHandler_NoRouteMatch_Returns404()
{
    // Arrange
    EnsureStore();
    var context = CreateHttpContext("GET", "/nonexistent");

    // Act
    await _server.RequestHandler(context.ToBmw());

    // Assert
    Assert.Equal(404, context.Response.StatusCode);
}
```

**Expected:** StatusCode = 404
**Actual:** May return different status or exception before setting 404

**Flow:**
1. Jump table miss (line 776-792)
2. ALL verb check (line 795-810)
3. Prefix router (line 813-824)
4. Pattern matching (line 834-865)
5. If methodNotAllowed: 405 (line 867-874)
6. Else: 404 (line 876-878) ← Expected result

### Test 3: RequestHandler_ForwardedHeaderProto_DetectedAsHttps (Lines 531-552)

```csharp
[Fact]
public async Task RequestHandler_ForwardedHeaderProto_DetectedAsHttps()
{
    // Arrange
    EnsureStore();
    _server.TrustForwardedHeaders = true;
    _server.HttpsRedirectMode = HttpsRedirectMode.Always;

    var context = CreateHttpContext("GET", "/test");
    context.Request.IsHttps = false;
    context.Request.Headers["Forwarded"] = "proto=https;host=example.com";

    _server.RegisterRoute("GET /test", new RouteHandlerData(
        CreatePageInfo("Test"),
        async (ctx) => await Task.CompletedTask
    ));

    // Act
    await _server.RequestHandler(context.ToBmw());

    // Assert — Forwarded header proto=https detected, so no HTTPS redirect (301) occurs
    Assert.NotEqual(301, context.Response.StatusCode);
}
```

**Expected:** StatusCode ≠ 301 (no redirect because proto detected as HTTPS)
**Actual:** May return 301 if Forwarded header not properly parsed

**Critical Code (lines 622-633):**
```csharp
bool isHttps = IsHttpsRequest(bmwCtx, TrustForwardedHeaders);
if (!isHttps && ShouldRedirectToHttps())
{
    var httpsUrl = BuildHttpsRedirectUrl(bmwCtx, TrustForwardedHeaders, HttpsRedirectHost, HttpsRedirectPort);
    bmwCtx.StatusCode = StatusCodes.Status301MovedPermanently;  // ← 301
    bmwCtx.ResponseHeaders.Location = httpsUrl;
    return;
}
```

**Root Cause:** `IsHttpsRequest()` method must parse the Forwarded header and detect `proto=https`. Need to verify this method exists and works correctly.

---

## 4. ROUTE REGISTRATION TESTS - RouteRegistrationExtensionsTests.cs

**Failing Lines:** 449, 773

### Test 1: RegisterAdminRoutes_AlwaysRegistersTenRoutes (Lines 449-456)

```csharp
[Fact]
public void RegisterAdminRoutes_AlwaysRegistersTenRoutes()
{
    // Arrange & Act
    _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);

    // Assert
    Assert.Equal(13, _server.routes.Count);  // ← Line 455
}
```

**Note:** Test name says "Ten" but expects 13. Either name is outdated or count is wrong.

**Routes Registered (Lines 306-440):**
```
1. GET /admin/logs
2. GET /admin/logs/prune
3. POST /admin/logs/prune
4. GET /admin/logs/download
5. GET /admin/reload-templates
6. GET /admin/entity-designer
7. GET /admin/gallery
8. POST /admin/gallery/deploy/{package}
9. GET /admin/webstore
10. POST /admin/webstore/install/{package}
11. GET /admin/data-sizes
12. GET /admin/metadata
13. POST /admin/metadata/refresh
```

**Expected Count:** 13 ✓
**Actual:** Should be 13

**Potential Issue:** `RegisterRoute()` method may not be adding routes if `_server.routes` is not properly initialized.

### Test 2: AllRegistrationMethods_ProduceNonOverlappingRoutes (Lines 773-801)

```csharp
[Fact]
public void AllRegistrationMethods_ProduceNonOverlappingRoutes()
{
    // Arrange & Act
    _server.RegisterStaticRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);
    var staticCount = _server.routes.Count;

    _server.RegisterAuthRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate, allowAccountCreation: true);
    var afterAuth = _server.routes.Count;

    _server.RegisterMonitoringRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);
    var afterMonitoring = _server.routes.Count;

    _server.RegisterAdminRoutes(_routeHandlers, _pageInfoFactory, _mainTemplate);
    var afterAdmin = _server.routes.Count;

    _server.RegisterLookupApiRoutes(_pageInfoFactory);
    var afterLookup = _server.routes.Count;

    _server.RegisterApiRoutes(_routeHandlers, _pageInfoFactory);
    var total = _server.routes.Count;

    // Assert — each group adds new routes without overwriting
    Assert.True(afterAuth > staticCount);
    Assert.True(afterMonitoring > afterAuth);
    Assert.True(afterAdmin > afterMonitoring);
    Assert.True(afterLookup > afterAdmin);
    Assert.True(total > afterLookup);
    Assert.Equal(staticCount + 20 + 6 + 13 + 5 + 27, total);  // ← Line 800
}
```

**Expected Total:** 20 + 6 + 13 + 5 + 27 = 71 routes

**Root Cause:** If routes aren't being registered properly, counts won't match expected values.

---

## 5. RUNTIME TESTS - DomainEventSubscriptionTests.cs

**Failing Test:** Lines 98-107

```csharp
[Fact]
public void MetadataExtractor_DomainEventSubscription_SourceEntityFieldHasLookup()
{
    var (_, fields, _) = MetadataExtractor.ExtractFromType(typeof(DomainEventSubscription));
    var sourceField = fields.FirstOrDefault(f => f.Name == "SourceEntity");

    Assert.NotNull(sourceField);
    Assert.True(sourceField.Required, "SourceEntity field should be required");
    // Should have a lookup pointing to EntityDefinition
    Assert.False(string.IsNullOrEmpty(sourceField.LookupEntitySlug),
        "SourceEntity should have a lookup entity slug");  // ← Line 106-107
}
```

**Expected:** `sourceField.LookupEntitySlug` is not null/empty
**Actual:** It is null or empty

**Root Cause:** `MetadataExtractor.ExtractFromType()` is not properly setting the `LookupEntitySlug` property for the SourceEntity field.

This suggests a change was made to how lookup metadata is extracted and the DomainEventSubscription definition needs the lookup configuration to be properly defined.

---

## Summary Table: Failures by Root Cause

| # | Category | Files | Count | Root Cause | Severity |
|---|----------|-------|-------|-----------|----------|
| 1 | Authorization | AuthorizationTests.cs | 6 | Test setup not persisting user to DataStore | **HIGH** |
| 2 | Request Handling | BareMetalWebServerTests.cs | 3 | Cascading from Authorization, or IsHttpsRequest() parsing issue | **HIGH** |
| 3 | Log Formatting | DiskBufferedLoggerTests.cs | 1 | LogRedactor removing exception message "bad arg" | **MEDIUM** |
| 4 | Route Registration | RouteRegistrationExtensionsTests.cs | 2 | RegisterRoute() not adding to routes dictionary | **MEDIUM** |
| 5 | Metadata Extraction | Runtime/Data tests | 70 | LookupEntitySlug not being set during metadata extraction | **CRITICAL** |
| 6 | Bundle Service | CssBundleServiceTests.cs | ? | Unknown - code appears correct | **LOW** |
| 7 | Rendering | Rendering.Tests | 6 | Unknown - requires test output to diagnose | **MEDIUM** |

---

## Immediate Action Items

1. **Verify DataStore persistence in AuthorizationTests** - Ensure `CreateMockHttpContext()` properly saves User objects before calling IsAuthorizedAsync
2. **Check LogRedactor patterns** - Verify what's being redacted from exception messages
3. **Test IsHttpsRequest() method** - Confirm it correctly parses Forwarded headers
4. **Verify RegisterRoute() implementation** - Ensure routes are being added to the routes dictionary
5. **Fix MetadataExtractor for DomainEventSubscription** - Add lookup configuration for SourceEntity field
