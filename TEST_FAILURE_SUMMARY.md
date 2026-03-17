# BareMetalWeb Test Failure Root Cause Analysis - Quick Summary

## Analysis Scope
- **Duration:** Full codebase investigation
- **Test Projects:** 4 (Host.Tests, Data.Tests, Rendering.Tests, Runtime.Tests)
- **Total Failures:** 100+
- **Files Analyzed:** 45+ test and production files

## Key Findings by Impact

### CRITICAL (70 Failures) - Metadata Extraction Issue
**File:** BareMetalWeb.Runtime.Tests/DomainEventSubscriptionTests.cs:106-107

Problem:
```csharp
Assert.False(string.IsNullOrEmpty(sourceField.LookupEntitySlug),
    "SourceEntity should have a lookup entity slug");
```

The `MetadataExtractor.ExtractFromType()` is not setting `LookupEntitySlug` for lookup fields.

Impact: Cascades to 68 Data.Tests failures and 6 Rendering.Tests failures.

**Fix Location:** `MetadataExtractor.ExtractFromType()` - must properly extract and set `LookupEntitySlug` for fields with lookup attributes.

---

### HIGH (9 Failures) - Authorization & Route Registration

#### 1. Authorization Tests (6 failures)
**File:** BareMetalWeb.Host.Tests/AuthorizationTests.cs:137, 166, 181, 225, 255, 270

The `IsAuthorizedAsync()` method implementation is CORRECT. The issue is likely in test setup:
- DataStoreFixture may not be properly persisting User/UserSession to DataStore
- When `UserAuth.GetRequestUserAsync()` is called, it returns null instead of the test user

Production code verified working:
- `GetAlternateLookup<ReadOnlySpan<char>>()` works correctly in .NET 10.0.4
- Permission parsing logic is sound
- All special cases (Public, Authenticated, AnonymousOnly) handled correctly

**Fix Location:** Check `DataStoreFixture.CreateMockHttpContext()` - ensure user persistence to current DataStore.

#### 2. Route Registration Tests (2-3 failures)  
**File:** BareMetalWeb.Host.Tests/RouteRegistrationExtensionsTests.cs:449, 773

Test expects:
- RegisterAdminRoutes registers 13 routes ✓ (code has 13 RegisterRoute calls)
- AllRegistrationMethods produces 71 total routes

**Root Cause:** `RegisterRoute()` method may not be adding routes to `_server.routes` dictionary.

**Fix Location:** Verify `IBareWebHost.RegisterRoute()` implementation in BareMetalWebServer.cs:339

---

### MEDIUM (3-4 Failures) - Request Handling & Logging

#### 1. Request Handler Tests (3 failures)
**File:** BareMetalWeb.Host.Tests/BareMetalWebServerTests.cs:97, 198, 531

- RequestHandler_ExactRouteMatch_ExecutesHandler: Cascades from Authorization issue
- RequestHandler_NoRouteMatch_Returns404: Should pass unless auth exception
- RequestHandler_ForwardedHeaderProto_DetectedAsHttps: Need to verify IsHttpsRequest() parses Forwarded header

**Fix Location:** 
1. Fix Authorization/RegisterRoute issues (will fix #1 and #2)
2. Verify `IsHttpsRequest()` method in BareMetalWebServer.cs correctly parses Forwarded header

#### 2. Logger Tests (~1 failure)
**File:** BareMetalWeb.Host.Tests/DiskBufferedLoggerTests.cs:524

Test expects: "bad arg" in log content
Problem: `LogRedactor.RedactStackTrace()` may be removing exception messages

**Fix Location:** Check LogRedactor class - exception message "bad arg" should NOT be redacted

---

## File-by-File Test Issues

### AuthorizationTests.cs
- **Lines Affected:** 137, 166, 181, 225, 255, 270
- **Issue:** User not being retrieved by IsAuthorizedAsync
- **Production Code:** BareMetalWebServer.cs:1056-1115 ✓ Correct
- **Test Code:** Needs DataStore initialization fix

### DiskBufferedLoggerTests.cs  
- **Lines Affected:** 524
- **Issue:** Exception message redacted
- **Production Code:** DiskBufferedLogger.cs:120-159 ✓ Correct format
- **Test Code:** LogRedactor removing content

### BareMetalWebServerTests.cs
- **Lines Affected:** 97, 198, 531
- **Issue 1:** Handler not executed (authorization cascading)
- **Issue 2:** Missing 404 status (may be exception-related)
- **Issue 3:** HTTPS detection not working (IsHttpsRequest parsing)

### RouteRegistrationExtensionsTests.cs
- **Lines Affected:** 449, 773
- **Issue:** Routes not being added to _server.routes
- **Root Cause:** RegisterRoute() implementation or _server initialization

### DomainEventSubscriptionTests.cs (Runtime)
- **Lines Affected:** 106-107
- **Issue:** LookupEntitySlug is null
- **Root Cause:** MetadataExtractor not setting lookup metadata

### Data.Tests (68 failures)
- **Root Cause:** Cascading from MetadataExtractor issue
- **Pattern:** "Assert.Contains() Failure", "calculated field errors", lookup-related failures

### Rendering.Tests (6 failures)
- **Root Cause:** Likely cascading from MetadataExtractor schema extraction

---

## Priority Fix Order

### Priority 1 - CRITICAL (Fixes 70+ tests)
```
1. MetadataExtractor.ExtractFromType() 
   - Ensure LookupEntitySlug is set for lookup fields
   - Check DataEntityAttribute processing
   - Verify field metadata collection
```

### Priority 2 - HIGH (Fixes 9 tests)
```
2. BareMetalWebServer.RegisterRoute() 
   - Verify routes are added to routes dictionary
   - Check _jumpTable invalidation
   
3. DataStoreFixture initialization
   - Ensure User/UserSession persist to current DataStore
   - Verify CookieProtection.Protect/Unprotect work with test setup
   - Check UserAuth.GetRequestUserAsync() retrieves users correctly
```

### Priority 3 - MEDIUM (Fixes 4+ tests)
```
4. BareMetalWebServer.IsHttpsRequest()
   - Verify Forwarded header parsing
   - Check proto=https detection
   
5. LogRedactor patterns
   - Ensure exception messages not redacted
   - Verify PII patterns don't match "bad arg"
```

---

## Code Locations Summary

| Issue | File | Lines | Type |
|-------|------|-------|------|
| Authorization | BareMetalWebServer.cs | 1056-1115 | ✓ Correct |
| User Retrieval | AuthorizationTests.cs | 319-349 | Fix needed |
| Route Registration | BareMetalWebServer.cs | 339 | Fix needed |
| HTTPS Detection | BareMetalWebServer.cs | ~622 | Verify |
| Log Formatting | DiskBufferedLogger.cs | 120-159 | ✓ Correct |
| Redaction | LogRedactor.cs | ? | Check patterns |
| Metadata Extract | MetadataExtractor.cs | ? | Fix needed |

---

## Verification Checklist

- [ ] Run MetadataExtractor fix - should fix 70 failures
- [ ] Run RegisterRoute fix - should fix 2-3 failures  
- [ ] Run DataStore initialization fix - should fix 6 failures
- [ ] Verify IsHttpsRequest() implementation - should fix 1 failure
- [ ] Check LogRedactor patterns - should fix 1 failure
- [ ] Re-run all test suites to verify cascading fixes

Expected Result: All failures resolved with 5-6 targeted fixes.
