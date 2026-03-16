# Test Failure Report

**Date:** 2026-03-16
**Branch:** `main`
**Total tests:** 2842
**Passing:** 2699
**Failing:** 143
**Failure groups:** 22

## Summary

| # | Test Class | Project | Failures | Root Cause |
|---|-----------|---------|----------|------------|
| 1 | [AuthenticationIntegrationTests](#authenticationintegrationtests) | IntegrationTests | 6 | System.Net.Http.HttpRequestException  |
| 2 | [BareMetalWebServerTests](#baremetalwebservertests) | Tests | 5 | Assert.Contains() Failure, Assert.Equal() Failure, Keep-Alive header must not be |
| 3 | [CalculatedFieldServiceTests](#calculatedfieldservicetests) | Tests | 6 | System.InvalidOperationException  |
| 4 | [CssBundleServiceCompressionTests](#cssbundleservicecompressiontests) | Tests | 3 | System.NullReferenceException  |
| 5 | [CssBundleServiceTests](#cssbundleservicetests) | Tests | 6 | System.NullReferenceException  |
| 6 | [DiskBufferedLoggerTests](#diskbufferedloggertests) | Tests | 6 | Assert.Contains() Failure, Assert.Equal() Failure, Assert.StartsWith() Failure |
| 7 | [DomainEventSubscriptionTests](#domaineventsubscriptiontests) | Tests | 1 | SourceEntity should have a lookup entity slug |
| 8 | [ExportTests](#exporttests) | Tests | 1 | Assert.NotNull() Failure |
| 9 | [ExpressionRelationshipTests](#expressionrelationshiptests) | Tests | 2 | System.InvalidOperationException  |
| 10 | [HtmlRendererCompressionTests](#htmlrenderercompressiontests) | Tests | 4 | System.NullReferenceException  |
| 11 | [JsBundleServiceCompressionTests](#jsbundleservicecompressiontests) | Tests | 4 | System.NullReferenceException  |
| 12 | [JsBundleServiceTests](#jsbundleservicetests) | Tests | 10 | System.NullReferenceException  |
| 13 | [MfaSecretProtectorTests](#mfasecretprotectortests) | Tests | 1 | Assert.Equal() Failure |
| 14 | [PrincipalAuthorizationPolicyTests](#principalauthorizationpolicytests) | Tests | 22 | Assert.Equal() Failure, Assert.False() Failure, Assert.NotNull() Failure, Assert |
| 15 | [RouteRegistrationExtensionsTests](#routeregistrationextensionstests) | Tests | 2 | Assert.Equal() Failure |
| 16 | [SampleGalleryServiceTests](#samplegalleryservicetests) | Tests | 1 | Assert.Equal() Failure |
| 17 | [SearchIndexingTests](#searchindexingtests) | Tests | 47 | Assert.Contains() Failure, Assert.Equal() Failure, Assert.Single() Failure, Asse |
| 18 | [SettingsServiceTests](#settingsservicetests) | Tests | 1 | Assert.Equal() Failure |
| 19 | [SimdAccelerationTests](#simdaccelerationtests) | Tests | 2 | Assert.Contains() Failure |
| 20 | [StaticAssetCacheTests](#staticassetcachetests) | Tests | 9 | System.NullReferenceException  |
| 21 | [SystemEntitySchemaTests](#systementityschematests) | Tests | 1 | Assert.Equal() Failure |
| 22 | [UserAuthTests](#userauthtests) | Tests | 3 | Assert.NotNull() Failure, Assert.True() Failure |

---

### AuthenticationIntegrationTests

**Project:** `BareMetalWeb.IntegrationTests`  
**Failing tests:** 6  
**Error:** `System.Net.Http.HttpRequestException : Resource temporarily unavailable (baremetalweb-cimigrate.azurewebsites.net:443)`

**Failing tests:**

- [ ] `BareMetalWeb.IntegrationTests.AuthenticationIntegrationTests.ApiEndpoint_RespondsCorrectly`
  - Error: `System.Net.Http.HttpRequestException : Resource temporarily unavailable (baremetalweb-cimigrate.azurewebsites.net:443)`
- [ ] `BareMetalWeb.IntegrationTests.AuthenticationIntegrationTests.HomePage_Returns_Success`
  - Error: `System.Net.Http.HttpRequestException : Resource temporarily unavailable (baremetalweb-cimigrate.azurewebsites.net:443)`
- [ ] `BareMetalWeb.IntegrationTests.AuthenticationIntegrationTests.Login_WithInvalidCredentials_Fails`
  - Error: `System.Net.Http.HttpRequestException : Resource temporarily unavailable (baremetalweb-cimigrate.azurewebsites.net:443)`
- [ ] `BareMetalWeb.IntegrationTests.AuthenticationIntegrationTests.Login_WithValidCredentials_Succeeds`
  - Error: `System.Net.Http.HttpRequestException : Resource temporarily unavailable (baremetalweb-cimigrate.azurewebsites.net:443)`
- [ ] `BareMetalWeb.IntegrationTests.AuthenticationIntegrationTests.ProtectedPage_WithoutAuthentication_Redirects`
  - Error: `System.Net.Http.HttpRequestException : Resource temporarily unavailable (baremetalweb-cimigrate.azurewebsites.net:443)`
- [ ] `BareMetalWeb.IntegrationTests.AuthenticationIntegrationTests.StaticFiles_AreAccessible`
  - Error: `System.Net.Http.HttpRequestException : Resource temporarily unavailable (baremetalweb-cimigrate.azurewebsites.net:443)`

**Key stack trace locations:**

- `at System.Net.Http.HttpConnectionPool.ConnectToTcpHostAsync(String host, Int32 port, HttpRequestMessage initialRequest, Boolean async, CancellationToken cancellationToken)`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~AuthenticationIntegrationTests"
```

---

### BareMetalWebServerTests

**Project:** `BareMetalWeb.Host.Tests`  
**Failing tests:** 5  
**Error:** `Assert.Contains() Failure: Sub-string not found; Assert.Equal() Failure: Strings differ; Keep-Alive header must not be set for HTTP/2 connections`

**Failing tests:**

- [ ] `RequestHandler_AjaxHandlerThrowsException_Returns500WithJsonBody`
  - Error: `Assert.Contains() Failure: Sub-string not found`
- [ ] `RequestHandler_ForwardedHeaderProto_DetectedAsHttps`
  - Error: `Assert.Equal() Failure: Strings differ`
- [ ] `RequestHandler_ForwardedHeadersNotTrusted_IgnoresHeaders`
  - Error: `Assert.Equal() Failure: Strings differ`
- [ ] `RequestHandler_ForwardedProtoHttps_DetectedAsHttps`
  - Error: `Assert.Equal() Failure: Strings differ`
- [ ] `RequestHandler_Http2_DoesNotIncludeKeepAliveHeader`
  - Error: `Keep-Alive header must not be set for HTTP/2 connections`

**Key stack trace locations:**

- `at BareMetalWeb.Host.Tests.BareMetalWebServerTests.RequestHandler_AjaxHandlerThrowsException_Returns500WithJsonBody() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/BareMetalWe`
- `at BareMetalWeb.Host.Tests.BareMetalWebServerTests.RequestHandler_ForwardedHeaderProto_DetectedAsHttps() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/BareMetalWebServerTests.`
- `at BareMetalWeb.Host.Tests.BareMetalWebServerTests.RequestHandler_ForwardedHeadersNotTrusted_IgnoresHeaders() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/BareMetalWebServerT`
- `at BareMetalWeb.Host.Tests.BareMetalWebServerTests.RequestHandler_ForwardedProtoHttps_DetectedAsHttps() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/BareMetalWebServerTests.c`
- `at BareMetalWeb.Host.Tests.BareMetalWebServerTests.RequestHandler_Http2_DoesNotIncludeKeepAliveHeader() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/BareMetalWebServerTests.c`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~BareMetalWebServerTests"
```

---

### CalculatedFieldServiceTests

**Project:** `BareMetalWeb.Data.Tests`  
**Failing tests:** 6  
**Error:** `System.InvalidOperationException : Error evaluating calculated field 'PriceWithMarkup' with expression 'Price * 1.1': Fi; System.InvalidOperationException : Error evaluating calculated field 'Subtotal' with expression 'Quantity * UnitPrice': `

**Failing tests:**

- [ ] `EvaluateCalculatedFields_DependencyChain_EvaluatesInCorrectOrder`
  - Error: `System.InvalidOperationException : Error evaluating calculated field 'Subtotal' with expression 'Quantity * UnitPrice': Field 'Quantity' not found in `
- [ ] `EvaluateCalculatedFields_IndependentFields_ComputesBoth`
  - Error: `System.InvalidOperationException : Error evaluating calculated field 'PriceWithMarkup' with expression 'Price * 1.1': Field 'Price' not found in conte`
- [ ] `EvaluateCalculatedFields_SimpleCalculation_ComputesCorrectValue`
  - Error: `System.InvalidOperationException : Error evaluating calculated field 'Subtotal' with expression 'Quantity * UnitPrice': Field 'Quantity' not found in `
- [ ] `EvaluateCalculatedFields_WithDecimalPrecision_MaintainsPrecision`
  - Error: `System.InvalidOperationException : Error evaluating calculated field 'Subtotal' with expression 'Quantity * UnitPrice': Field 'Quantity' not found in `
- [ ] `EvaluateCalculatedFields_WithDiscount_AppliesCorrectly`
  - Error: `System.InvalidOperationException : Error evaluating calculated field 'Subtotal' with expression 'Quantity * UnitPrice': Field 'Quantity' not found in `
- [ ] `EvaluateCalculatedFields_WithZeroValues_HandlesCorrectly`
  - Error: `System.InvalidOperationException : Error evaluating calculated field 'Subtotal' with expression 'Quantity * UnitPrice': Field 'Quantity' not found in `

**Key stack trace locations:**

- `at BareMetalWeb.Data.ExpressionEngine.CalculatedFieldService.EvaluateCalculatedFields(BaseDataObject instance) in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data/ExpressionEngine/Calcula`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~CalculatedFieldServiceTests"
```

---

### CssBundleServiceCompressionTests

**Project:** `BareMetalWeb.Host.Tests`  
**Failing tests:** 3  
**Error:** `System.NullReferenceException : Object reference not set to an instance of an object.`

**Failing tests:**

- [ ] `TryServeAsync_WithBrotliAcceptEncoding_SetsBrContentEncoding`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_WithGzipAcceptEncoding_SetsGzipContentEncoding`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_WithNoAcceptEncoding_NoContentEncodingHeader`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`

**Key stack trace locations:**

- `at BareMetalWeb.Core.BmwContext.TryLogFirstWriteLatency() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Core/BmwContext.cs:line 324`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~CssBundleServiceCompressionTests"
```

---

### CssBundleServiceTests

**Project:** `BareMetalWeb.Host.Tests`  
**Failing tests:** 6  
**Error:** `System.NullReferenceException : Object reference not set to an instance of an object.`

**Failing tests:**

- [ ] `LoadAssets_LoadsThemesAndServesFromCache`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_KnownTheme_ReturnsTrue`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_Returns304_WhenETagMatches`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_SetsCacheControlHeader`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_SetsCorrectContentType`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_SetsETagHeader`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`

**Key stack trace locations:**

- `at BareMetalWeb.Core.BmwContext.TryLogFirstWriteLatency() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Core/BmwContext.cs:line 324`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~CssBundleServiceTests"
```

---

### DiskBufferedLoggerTests

**Project:** `BareMetalWeb.Host.Tests`  
**Failing tests:** 6  
**Error:** `Assert.Contains() Failure: Sub-string not found; Assert.Equal() Failure: Values differ; Assert.StartsWith() Failure: String start does not match`

**Failing tests:**

- [ ] `LogError_MessageFormat_ContainsExceptionAndTimestamp`
  - Error: `Assert.StartsWith() Failure: String start does not match`
- [ ] `LogError_WritesErrorFileToDisk`
  - Error: `Assert.Contains() Failure: Sub-string not found`
- [ ] `LogError_WritesToErrorFile_NotInfoFile`
  - Error: `Assert.Contains() Failure: Sub-string not found`
- [ ] `LogInfo_BuffersMessages_FlushWritesToDisk`
  - Error: `Assert.Contains() Failure: Sub-string not found`
- [ ] `LogInfo_MessageFormat_ContainsIso8601Timestamp`
  - Error: `Assert.Equal() Failure: Values differ`
- [ ] `LogInfo_WritesToInfoFile_NotErrorFile`
  - Error: `Assert.Contains() Failure: Sub-string not found`

**Key stack trace locations:**

- `at BareMetalWeb.Host.Tests.DiskBufferedLoggerTests.LogError_MessageFormat_ContainsExceptionAndTimestamp() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/DiskBufferedLoggerTests`
- `at BareMetalWeb.Host.Tests.DiskBufferedLoggerTests.LogError_WritesErrorFileToDisk() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/DiskBufferedLoggerTests.cs:line 105`
- `at BareMetalWeb.Host.Tests.DiskBufferedLoggerTests.LogError_WritesToErrorFile_NotInfoFile() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/DiskBufferedLoggerTests.cs:line 279`
- `at BareMetalWeb.Host.Tests.DiskBufferedLoggerTests.LogInfo_BuffersMessages_FlushWritesToDisk() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/DiskBufferedLoggerTests.cs:line 63`
- `at BareMetalWeb.Host.Tests.DiskBufferedLoggerTests.LogInfo_MessageFormat_ContainsIso8601Timestamp() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/DiskBufferedLoggerTests.cs:li`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~DiskBufferedLoggerTests"
```

---

### DomainEventSubscriptionTests

**Project:** `BareMetalWeb.Runtime.Tests`  
**Failing tests:** 1  
**Error:** `SourceEntity should have a lookup entity slug`

**Failing tests:**

- [ ] `MetadataExtractor_DomainEventSubscription_SourceEntityFieldHasLookup`
  - Error: `SourceEntity should have a lookup entity slug`

**Key stack trace locations:**

- `at BareMetalWeb.Runtime.Tests.DomainEventSubscriptionTests.MetadataExtractor_DomainEventSubscription_SourceEntityFieldHasLookup() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Runtime.Te`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~DomainEventSubscriptionTests"
```

---

### ExportTests

**Project:** `BareMetalWeb.Host.Tests`  
**Failing tests:** 1  
**Error:** `Assert.NotNull() Failure: Value is null`

**Failing tests:**

- [ ] `BuildSubFieldSchemas_ForVirtualEntityChildList_ReturnsSubFieldsFromChildMeta`
  - Error: `Assert.NotNull() Failure: Value is null`

**Key stack trace locations:**

- `at BareMetalWeb.Host.Tests.ExportTests.BuildSubFieldSchemas_ForVirtualEntityChildList_ReturnsSubFieldsFromChildMeta() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/ExportTests`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~ExportTests"
```

---

### ExpressionRelationshipTests

**Project:** `BareMetalWeb.Data.Tests`  
**Failing tests:** 2  
**Error:** `System.InvalidOperationException : Error evaluating calculated field 'DiscountedPrice' with expression 'UnitPrice * (1 -`

**Failing tests:**

- [ ] `EvaluateCalculatedFieldsAsync_WithParentContext_SetsParentFields`
  - Error: `System.InvalidOperationException : Error evaluating calculated field 'DiscountedPrice' with expression 'UnitPrice * (1 - Parent.DiscountPercent / 100)`
- [ ] `EvaluateCalculatedFieldsAsync_WithoutParentContext_ParentFieldsAreNull`
  - Error: `System.InvalidOperationException : Error evaluating calculated field 'DiscountedPrice' with expression 'UnitPrice * (1 - Parent.DiscountPercent / 100)`

**Key stack trace locations:**

- `at BareMetalWeb.Data.ExpressionEngine.CalculatedFieldService.EvaluateCalculatedFieldsAsync(BaseDataObject instance, String entitySlug, ILookupResolver resolver, IReadOnlyDictionary`2 parentContext, Ca`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~ExpressionRelationshipTests"
```

---

### HtmlRendererCompressionTests

**Project:** `BareMetalWeb.Rendering.Tests`  
**Failing tests:** 4  
**Error:** `System.NullReferenceException : Object reference not set to an instance of an object.`

**Failing tests:**

- [ ] `RenderPage_WithBrotliAcceptEncoding_BodyIsDecompressibleBrotli`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `RenderPage_WithBrotliAcceptEncoding_SetsBrContentEncoding`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `RenderPage_WithGzipAcceptEncoding_BodyIsDecompressibleGzip`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `RenderPage_WithGzipAcceptEncoding_SetsGzipContentEncoding`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`

**Key stack trace locations:**

- `at BareMetalWeb.Core.BmwContext.TryLogFirstWriteLatency() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Core/BmwContext.cs:line 324`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~HtmlRendererCompressionTests"
```

---

### JsBundleServiceCompressionTests

**Project:** `BareMetalWeb.Host.Tests`  
**Failing tests:** 4  
**Error:** `System.NullReferenceException : Object reference not set to an instance of an object.`

**Failing tests:**

- [ ] `TryServeAsync_WithBrotliAcceptEncoding_BodyIsDecompressibleBrotli`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_WithBrotliAcceptEncoding_SetsBrContentEncoding`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_WithGzipAcceptEncoding_SetsGzipContentEncoding`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_WithNoAcceptEncoding_NoContentEncodingHeader`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`

**Key stack trace locations:**

- `at BareMetalWeb.Core.BmwContext.TryLogFirstWriteLatency() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Core/BmwContext.cs:line 324`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~JsBundleServiceCompressionTests"
```

---

### JsBundleServiceTests

**Project:** `BareMetalWeb.Host.Tests`  
**Failing tests:** 10  
**Error:** `System.NullReferenceException : Object reference not set to an instance of an object.`

**Failing tests:**

- [ ] `BuildBundle_BootstrapIsIncludedWhenPresent`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `BuildBundle_ConcatenatesFilesInOrder`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `BuildBundle_DoesNotMinifyMinFiles`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `BuildBundle_MinifiesNonMinFiles`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_BundleContainsFileContent`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_BundlePath_ReturnsTrue`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_Returns304_WhenETagMatches`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_SetsCacheControlHeader`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_SetsCorrectContentType`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `TryServeAsync_SetsETagHeader`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`

**Key stack trace locations:**

- `at BareMetalWeb.Core.BmwContext.TryLogFirstWriteLatency() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Core/BmwContext.cs:line 324`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~JsBundleServiceTests"
```

---

### MfaSecretProtectorTests

**Project:** `BareMetalWeb.Data.Tests`  
**Failing tests:** 1  
**Error:** `Assert.Equal() Failure: Values differ`

**Failing tests:**

- [ ] `CreateDefault_CreatesKeyFile_AndReusesIt`
  - Error: `Assert.Equal() Failure: Values differ`

**Key stack trace locations:**

- `at BareMetalWeb.Data.Tests.MfaSecretProtectorTests.CreateDefault_CreatesKeyFile_AndReusesIt() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/MfaSecretProtectorTests.cs:line 469`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~MfaSecretProtectorTests"
```

---

### PrincipalAuthorizationPolicyTests

**Project:** `BareMetalWeb.Data.Tests`  
**Failing tests:** 22  
**Error:** `Assert.Equal() Failure: Values differ; Assert.False() Failure; Assert.NotNull() Failure: Value is null; Assert.True() Failure`

**Failing tests:**

- [ ] `AsRestrictedPrincipal_RestrictedRole_ReturnsPrincipal(role: DeploymentAgent)`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `AsRestrictedPrincipal_RestrictedRole_ReturnsPrincipal(role: DeploymentProcess)`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `AsRestrictedPrincipal_RestrictedRole_ReturnsPrincipal(role: TenantCallback)`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `AuditDeniedAsync_CreatesAccessDeniedEntry`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `CanManageApiKeys_RestrictedRole_ReturnsFalse(role: DeploymentAgent)`
  - Error: `Assert.False() Failure`
- [ ] `CanManageApiKeys_RestrictedRole_ReturnsFalse(role: DeploymentProcess)`
  - Error: `Assert.False() Failure`
- [ ] `CanManageApiKeys_RestrictedRole_ReturnsFalse(role: TenantCallback)`
  - Error: `Assert.False() Failure`
- [ ] `CheckEntityAction_DeploymentAgent_DeniesSpKeyOperations(action: "Create")`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `CheckEntityAction_DeploymentAgent_DeniesSpKeyOperations(action: "Update")`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `CheckEntityAction_DeploymentAgent_DeniesUpdateDelete(action: "Delete")`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `CheckEntityAction_DeploymentAgent_DeniesUpdateDelete(action: "Update")`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `CheckEntityAction_DeploymentProcess_DeniesDelete`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `CheckEntityAction_DeploymentProcess_DeniesSpKeyOperations(action: "Create")`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `CheckEntityAction_DeploymentProcess_DeniesSpKeyOperations(action: "Update")`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `CheckEntityAction_TenantCallback_DeniesCreateDelete(action: "Create")`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `CheckEntityAction_TenantCallback_DeniesCreateDelete(action: "Delete")`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `CheckEntityAction_TenantCallback_DeniesSpKeyOperations(action: "Create")`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `CheckEntityAction_TenantCallback_DeniesSpKeyOperations(action: "Update")`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `FilterOwnedRecords_ReturnsOnlyOwned`
  - Error: `Assert.Equal() Failure: Values differ`
- [ ] `IsRecordOwner_CaseInsensitiveMatch_ReturnsTrue`
  - Error: `Assert.True() Failure`
- [ ] `IsRecordOwner_MatchingCreatedBy_ReturnsTrue`
  - Error: `Assert.True() Failure`
- [ ] `IsRecordOwner_SelfAccess_SystemPrincipal_ReturnsTrue`
  - Error: `Assert.True() Failure`

**Key stack trace locations:**

- `at BareMetalWeb.Data.Tests.PrincipalAuthorizationPolicyTests.AsRestrictedPrincipal_RestrictedRole_ReturnsPrincipal(PrincipalRole role) in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.`
- `at BareMetalWeb.Data.Tests.PrincipalAuthorizationPolicyTests.AuditDeniedAsync_CreatesAccessDeniedEntry() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/PrincipalAuthorizationPo`
- `at BareMetalWeb.Data.Tests.PrincipalAuthorizationPolicyTests.CanManageApiKeys_RestrictedRole_ReturnsFalse(PrincipalRole role) in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/Pri`
- `at BareMetalWeb.Data.Tests.PrincipalAuthorizationPolicyTests.CheckEntityAction_DeploymentAgent_DeniesSpKeyOperations(String action) in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tes`
- `at BareMetalWeb.Data.Tests.PrincipalAuthorizationPolicyTests.CheckEntityAction_DeploymentAgent_DeniesUpdateDelete(String action) in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~PrincipalAuthorizationPolicyTests"
```

---

### RouteRegistrationExtensionsTests

**Project:** `BareMetalWeb.Host.Tests`  
**Failing tests:** 2  
**Error:** `Assert.Equal() Failure: Values differ`

**Failing tests:**

- [ ] `AllRegistrationMethods_ProduceNonOverlappingRoutes`
  - Error: `Assert.Equal() Failure: Values differ`
- [ ] `RegisterAdminRoutes_AlwaysRegistersTenRoutes`
  - Error: `Assert.Equal() Failure: Values differ`

**Key stack trace locations:**

- `at BareMetalWeb.Host.Tests.RouteRegistrationExtensionsTests.AllRegistrationMethods_ProduceNonOverlappingRoutes() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/RouteRegistratio`
- `at BareMetalWeb.Host.Tests.RouteRegistrationExtensionsTests.RegisterAdminRoutes_AlwaysRegistersTenRoutes() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/RouteRegistrationExten`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~RouteRegistrationExtensionsTests"
```

---

### SampleGalleryServiceTests

**Project:** `BareMetalWeb.Runtime.Tests`  
**Failing tests:** 1  
**Error:** `Assert.Equal() Failure: Values differ`

**Failing tests:**

- [ ] `GetAllPackages_Returns_FourPackages`
  - Error: `Assert.Equal() Failure: Values differ`

**Key stack trace locations:**

- `at BareMetalWeb.Runtime.Tests.SampleGalleryServiceTests.GetAllPackages_Returns_FourPackages() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Runtime.Tests/SampleGalleryServiceTests.cs:lin`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~SampleGalleryServiceTests"
```

---

### SearchIndexingTests

**Project:** `BareMetalWeb.Data.Tests`  
**Failing tests:** 47  
**Error:** `Assert.Contains() Failure: Item not found in set; Assert.Equal() Failure: Values differ; Assert.Single() Failure: The collection was empty; Assert.True() Failure`

**Failing tests:**

- [ ] `BTreeIndex_PrefixSearch_FindsMatches`
  - Error: `Assert.Equal() Failure: Values differ`
- [ ] `EnsureBuilt_BuildsIndexFromExistingObjects`
  - Error: `Assert.Equal() Failure: Values differ`
- [ ] `EnsureBuilt_BuildsIndexFromLoadAll`
  - Error: `Assert.Single() Failure: The collection was empty`
- [ ] `EnsureBuilt_DuplicateIds_LastWins`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `EnsureBuilt_SkipsNullAndEmptyIdEntities`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `HasIndexedFields_BTreeKind_StillDetected`
  - Error: `Assert.True() Failure`
- [ ] `HasIndexedFields_MultiFieldEntity_ReturnsAllIndexedFields`
  - Error: `Assert.True() Failure`
- [ ] `HasIndexedFields_TypeWithAttribute_ReturnsTrue`
  - Error: `Assert.True() Failure`
- [ ] `HasIndexedFields_WithIndexedProperties_ReturnsTrue`
  - Error: `Assert.True() Failure`
- [ ] `IndexObject_AfterEnsureBuilt_AddsToIndex`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_And_Search_FindsByExactToken`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_BTreeIndex_CanSearchByCategory`
  - Error: `Assert.Equal() Failure: Values differ`
- [ ] `IndexObject_BloomFilter_CanSearchByDescription`
  - Error: `Assert.Equal() Failure: Values differ`
- [ ] `IndexObject_IntEnumerable_TokenizesViaToString`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_IntField_SearchByNumberString`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_InvertedIndex_CanSearchByName`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_ListField_NullItems_DoesNotThrow`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_ListField_SearchByAnyTag`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_MultiField_SearchFindsFromEitherField`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_NonInvertedKind_FallsBackToInverted`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_NullableIntField_WithValue_IsSearchable`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_PersistsToFile_NewManagerCanSearch`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_ReindexSameId_UpdatesTokens`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_TreapIndex_CanSearchByTags`
  - Error: `Assert.Equal() Failure: Values differ`
- [ ] `IndexObject_UpdateExisting_UpdatesAllIndexes`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `IndexObject_VeryLongToken_IsIndexedCorrectly`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `RemoveObject_OnlyRemovesTargetEntity`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_AccentedCharacters_AreLowercased`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_CJKCharacters_AreIndexed`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_CaseInsensitive_FindsMatch`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_DifferentTypes_AreIsolated`
  - Error: `Assert.Single() Failure: The collection was empty`
- [ ] `Search_DigitsInTokens_ArePreserved`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_EmojiStripped_TokensSplit`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_MixedAlphanumericToken_IsKeptTogether`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_MultiField_MatchesAcrossFieldsIndependently`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_MultipleEntitiesSameToken_ReturnsAll`
  - Error: `Assert.Equal() Failure: Values differ`
- [ ] `Search_MultipleTokensInQuery_FindsAll`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_PrefixMatch_FindsToken`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_ReturnsAllMatchingIds`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_ShortQueryToken_FallsBackToContains`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_SingleCharToken_MatchesViaContainsFallback`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_SpecialCharactersStripped_TokensSplit`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_TokenizesOnPunctuation`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_TokensAreLowercased`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_TwoCharToken_ExactMatch`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_UnicodeLetters_AreIndexed`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `Search_WithMultipleTokens_ReturnsUnionOfResults`
  - Error: `Assert.Equal() Failure: Values differ`

**Key stack trace locations:**

- `at BareMetalWeb.Data.Tests.SearchIndexingTests.BTreeIndex_PrefixSearch_FindsMatches() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/SearchIndexingTests.cs:line 269`
- `at BareMetalWeb.Data.Tests.SearchIndexingTests.EnsureBuilt_BuildsIndexFromExistingObjects() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/SearchIndexingTests.cs:line 1061`
- `at BareMetalWeb.Data.Tests.SearchIndexingTests.EnsureBuilt_BuildsIndexFromLoadAll() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/SearchIndexingTests.cs:line 689`
- `at BareMetalWeb.Data.Tests.SearchIndexingTests.EnsureBuilt_DuplicateIds_LastWins() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/SearchIndexingTests.cs:line 1295`
- `at BareMetalWeb.Data.Tests.SearchIndexingTests.EnsureBuilt_SkipsNullAndEmptyIdEntities() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/SearchIndexingTests.cs:line 707`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~SearchIndexingTests"
```

---

### SettingsServiceTests

**Project:** `BareMetalWeb.Data.Tests`  
**Failing tests:** 1  
**Error:** `Assert.Equal() Failure: Strings differ`

**Failing tests:**

- [ ] `DataScaffold_SaveAsync_InvalidatesSettingsCacheForAppSetting`
  - Error: `Assert.Equal() Failure: Strings differ`

**Key stack trace locations:**

- `at BareMetalWeb.Data.Tests.SettingsServiceTests.DataScaffold_SaveAsync_InvalidatesSettingsCacheForAppSetting() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/SettingsServiceTes`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~SettingsServiceTests"
```

---

### SimdAccelerationTests

**Project:** `BareMetalWeb.Data.Tests`  
**Failing tests:** 2  
**Error:** `Assert.Contains() Failure: Item not found in set`

**Failing tests:**

- [ ] `BloomFilter_AddAndSearch_FindsExactToken`
  - Error: `Assert.Contains() Failure: Item not found in set`
- [ ] `BloomFilter_MultipleItems_AllFound`
  - Error: `Assert.Contains() Failure: Item not found in set`

**Key stack trace locations:**

- `at BareMetalWeb.Data.Tests.SimdAccelerationTests.BloomFilter_AddAndSearch_FindsExactToken() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/SimdAccelerationTests.cs:line 329`
- `at BareMetalWeb.Data.Tests.SimdAccelerationTests.BloomFilter_MultipleItems_AllFound() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/SimdAccelerationTests.cs:line 376`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~SimdAccelerationTests"
```

---

### StaticAssetCacheTests

**Project:** `BareMetalWeb.Host.Tests`  
**Failing tests:** 9  
**Error:** `System.NullReferenceException : Object reference not set to an instance of an object.`

**Failing tests:**

- [ ] `ServeAsync_BrotliRequested_SetsContentEncoding`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `ServeAsync_GzipRequested_SetsContentEncoding`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `ServeAsync_NonVersionedAsset_UsesCacheSeconds`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `ServeAsync_SetsContentLength`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `ServeAsync_SetsETagAndLastModifiedHeaders`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `ServeAsync_SetsStatus200AndContentType`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `ServeAsync_VersionedAsset_SetsImmutableCacheControl`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `ServeAsync_WritesRawBodyForGetRequest`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`
- [ ] `StaticFileService_UsesCacheWhenBuilt`
  - Error: `System.NullReferenceException : Object reference not set to an instance of an object.`

**Key stack trace locations:**

- `at BareMetalWeb.Core.BmwContext.TryLogFirstWriteLatency() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Core/BmwContext.cs:line 324`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~StaticAssetCacheTests"
```

---

### SystemEntitySchemaTests

**Project:** `BareMetalWeb.Data.Tests`  
**Failing tests:** 1  
**Error:** `Assert.Equal() Failure: Values differ`

**Failing tests:**

- [ ] `AllSchemas_AreNonNull`
  - Error: `Assert.Equal() Failure: Values differ`

**Key stack trace locations:**

- `at BareMetalWeb.Data.Tests.SystemEntitySchemaTests.AllSchemas_AreNonNull() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Data.Tests/SystemEntitySchemaTests.cs:line 16`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~SystemEntitySchemaTests"
```

---

### UserAuthTests

**Project:** `BareMetalWeb.Host.Tests`  
**Failing tests:** 3  
**Error:** `Assert.NotNull() Failure: Value is null; Assert.True() Failure`

**Failing tests:**

- [ ] `GetRequestUserAsync_BearerTokenHeader_ResolvesApiKey`
  - Error: `Assert.NotNull() Failure: Value is null`
- [ ] `HasValidApiKeyAsync_ValidApiKeyHeader_ReturnsTrue`
  - Error: `Assert.True() Failure`
- [ ] `HasValidApiKeyAsync_ValidBearerToken_ReturnsTrue`
  - Error: `Assert.True() Failure`

**Key stack trace locations:**

- `at BareMetalWeb.Host.Tests.UserAuthTests.GetRequestUserAsync_BearerTokenHeader_ResolvesApiKey() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/UserAuthTests.cs:line 50`
- `at BareMetalWeb.Host.Tests.UserAuthTests.HasValidApiKeyAsync_ValidApiKeyHeader_ReturnsTrue() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/UserAuthTests.cs:line 134`
- `at BareMetalWeb.Host.Tests.UserAuthTests.HasValidApiKeyAsync_ValidBearerToken_ReturnsTrue() in /home/runner/work/BareMetalWeb/BareMetalWeb/BareMetalWeb.Host.Tests/UserAuthTests.cs:line 77`

**Reproduce:**
```bash
dotnet test --filter "FullyQualifiedName~UserAuthTests"
```

---
