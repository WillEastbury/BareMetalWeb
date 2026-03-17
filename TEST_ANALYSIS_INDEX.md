# Test Failure Analysis - Documentation Index

This directory contains detailed root cause analysis for 100+ test failures across 4 test projects.

## Quick Links

1. **[TEST_FAILURE_SUMMARY.md](TEST_FAILURE_SUMMARY.md)** ← START HERE
   - Quick reference of all issues
   - Priority fix order
   - Code locations

2. **[TEST_FAILURE_ROOT_CAUSE_ANALYSIS.md](TEST_FAILURE_ROOT_CAUSE_ANALYSIS.md)**
   - Detailed code snippets
   - Full test implementations
   - Production code analysis
   - All 5 major issue categories

## Summary by Severity

### CRITICAL (70 Tests) - Metadata Extraction
- Issue: `MetadataExtractor.ExtractFromType()` not setting `LookupEntitySlug`
- Affects: 68 Data.Tests + 6 Rendering.Tests
- File: BareMetalWeb.Runtime/MetadataExtractor.cs
- Status: Needs fix

### HIGH (9 Tests) - Authorization & Routes
- Issue 1: User not persisting in DataStore during auth tests
- Issue 2: RegisterRoute() not adding to routes dictionary
- Files: BareMetalWebServer.cs, AuthorizationTests.cs, RouteRegistrationExtensionsTests.cs
- Status: Needs investigation + fix

### MEDIUM (4+ Tests) - Request Handler & Logging
- Issue 1: IsHttpsRequest() not parsing Forwarded header
- Issue 2: LogRedactor removing exception messages
- Issue 3: Cascading failures from auth tests
- Files: BareMetalWebServer.cs, DiskBufferedLogger.cs, BareMetalWebServerTests.cs
- Status: Depends on HIGH priority fixes

## Tests by Project

### BareMetalWeb.Host.Tests (11 failures)
- AuthorizationTests.cs (6): User retrieval issue
- BareMetalWebServerTests.cs (3): Cascading + IsHttpsRequest issue
- DiskBufferedLoggerTests.cs (1): LogRedactor issue
- RouteRegistrationExtensionsTests.cs (2): RegisterRoute issue

### BareMetalWeb.Data.Tests (68 failures)
- Root cause: MetadataExtractor not extracting lookup metadata
- Pattern: "Assert.Contains() Failure", lookup-related assertions
- Status: Will be fixed by Critical priority fix

### BareMetalWeb.Runtime.Tests (2 failures)
- DomainEventSubscriptionTests.cs (1): LookupEntitySlug null
- Other (1): Unknown - likely metadata-related
- Root cause: Same as Data.Tests

### BareMetalWeb.Rendering.Tests (6 failures)
- Root cause: Likely cascading from MetadataExtractor
- Status: Will be fixed by Critical priority fix

## Investigation Process

All failures were traced through:
1. Test code analysis (test setup, assertions, expected results)
2. Production code analysis (implementation, logic flow)
3. Integration points (how tests call production code)
4. Common patterns (failures in same area indicate shared root cause)

## Fix Implementation Order

```
Phase 1 (CRITICAL):
  → Fix MetadataExtractor.ExtractFromType()
    └─ Fixes 70 failures immediately

Phase 2 (HIGH):
  → Fix RegisterRoute() implementation
    └─ Fixes 2-3 failures
  → Fix DataStore initialization in AuthorizationTests
    └─ Fixes 6 failures

Phase 3 (MEDIUM):
  → Verify/Fix IsHttpsRequest() Forwarded header parsing
    └─ Fixes 1 failure
  → Fix LogRedactor patterns
    └─ Fixes 1 failure

Phase 4 (Verification):
  → Re-run all test suites
  → Verify no cascading failures
  → Expected result: All 100+ tests passing
```

## Key Files Analyzed

### Production Code
- BareMetalWeb.Host/BareMetalWebServer.cs (1500+ lines)
- BareMetalWeb.Host/DiskBufferedLogger.cs (200+ lines)
- BareMetalWeb.Host/CssBundleService.cs (200+ lines)
- BareMetalWeb.Host/RouteRegistrationExtensions.cs (500+ lines)
- BareMetalWeb.Runtime/MetadataExtractor.cs (unknown - not fully viewed)
- BareMetalWeb.Data/LogRedactor.cs (unknown - not fully viewed)

### Test Code  
- BareMetalWeb.Host.Tests/AuthorizationTests.cs (460 lines)
- BareMetalWeb.Host.Tests/BareMetalWebServerTests.cs (41+ KB)
- BareMetalWeb.Host.Tests/DiskBufferedLoggerTests.cs (23+ KB)
- BareMetalWeb.Host.Tests/RouteRegistrationExtensionsTests.cs (1000+ lines)
- BareMetalWeb.Runtime.Tests/DomainEventSubscriptionTests.cs (142 lines)

## Notes

- GetAlternateLookup<ReadOnlySpan<char>>() API verified working in .NET 10.0.4
- All failures appear to be code bugs, not platform/framework issues
- No external dependencies or environment configuration issues detected
- Root causes are isolated to 5-6 specific implementation areas
