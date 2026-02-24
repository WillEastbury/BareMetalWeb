# Issue Categorization Analysis

This document provides a comprehensive categorization of all 26 open issues in the BareMetalWeb repository.

## Categorization Scheme

Issues are categorized along three dimensions:

### Priority
- **Critical**: Security vulnerabilities, data integrity issues, or broken core functionality
- **Important**: Significant bugs or essential features for usability
- **Nice to Have**: Useful enhancements that improve the experience but aren't essential
- **Superfluous**: Exploratory/research items not intended for immediate implementation

### Type
- **Security**: Security vulnerabilities or security-critical test failures
- **Bug**: Broken functionality or failing tests
- **New Feature Request**: New capabilities or features
- **Enrichment**: Improvements to existing functionality

### Component
- **Host**: BareMetalWeb.Host (routing, session, auth, server core)
- **API Extension**: API layer extensions and remote methods
- **HTML**: UI/HTML rendering and client-side functionality
- **Renderer**: Template rendering engine
- **Storage**: Data storage and persistence
- **Serializer**: Binary serialization
- **Indexing**: Search indexing infrastructure
- **Query**: Query and reporting layer
- **Scaffolder**: Data scaffolding and form generation
- **Other**: Build, testing, and other concerns

## Issue Categorization

### Critical Issues (3)

#### #75 - bug in MFA Tests
- **Priority**: Critical
- **Type**: Security
- **Component**: Host
- **Reason**: MFA validation test contains `Assert.True(result || !result)` which always passes. This is a no-op test that provides zero coverage for security-critical MFA authentication code. A regression in MFA validation would go undetected.

#### #76 - bUG IN mALFORMED COOKIE TEST
- **Priority**: Critical
- **Type**: Security
- **Component**: Host
- **Reason**: Cookie protection test accepts both null and valid results for malformed tokens (`Assert.True(result == null || result == original)`). Since CookieProtection is a security boundary for session integrity, accepting malformed inputs should be caught by tests to prevent silent security regressions.

#### #77 - BUG IN AUTO-ID GEN FOUND BY CODEX
- **Priority**: Critical
- **Type**: Bug
- **Component**: Scaffolder
- **Reason**: Auto-ID generation only works in the admin form flow but not in API endpoints or CSV import. Entities like Invoice using SequentialLong ID generation get GUIDs instead when created via `/api/{type}`, breaking data integrity and the advertised auto-generation behavior.

---

### Important Issues (8)

#### #60 - Field validation framework
- **Priority**: Important
- **Type**: New Feature Request
- **Component**: Scaffolder
- **Reason**: No field-level validation exists beyond HTML `required` attribute. Input validation is critical for data integrity and security. Forms currently accept any input without server-side validation.

#### #61 - Search, filtering and pagination on entity list views
- **Priority**: Important
- **Type**: New Feature Request
- **Component**: Query
- **Reason**: Entity list pages render every record with no search, filtering, or pagination. Essential for usability once datasets grow beyond a few dozen records.

#### #62 - Audit trail and change history for entities
- **Priority**: Important
- **Type**: New Feature Request
- **Component**: Storage
- **Reason**: No record of who changed what and when. Important for compliance, debugging, and accountability, especially with remote commands and computed fields.

#### #63 - File and image upload fields with storage integration
- **Priority**: Important
- **Type**: New Feature Request
- **Component**: Storage
- **Reason**: There's an `image-preview.js` on the frontend but no end-to-end upload-to-storage pipeline. File upload is a common requirement for many use cases.

#### #71 - Wire up secondary indexes: activate [DataIndex], add to framework and demo entities
- **Priority**: Important
- **Type**: New Feature Request
- **Component**: Indexing
- **Reason**: The `[DataIndex]` attribute, `SearchIndexManager`, and `IndexStore` infrastructure exist but aren't activated. Secondary indexes are important for search performance and multi-field queries.

#### #73 - Address Codex Review Comment
- **Priority**: Important
- **Type**: Bug
- **Component**: Host
- **Reason**: Code review finding that needs investigation and fix in RouteHandlers.cs. Details in linked review comment.

#### #74 - Address Stylesheet bug from codex
- **Priority**: Important
- **Type**: Bug
- **Component**: HTML
- **Reason**: Setting `themeLink.href = ''` in theme-switcher.js resolves to the current document URL, causing the browser to request the page as CSS. This creates unnecessary network traffic and can hit application routes unexpectedly.

#### #78 - Fix Failing Unit Test on session expiration
- **Priority**: Important
- **Type**: Bug
- **Component**: Host
- **Reason**: `UserAuthTests.GetSession_ActiveSession_ExtendsExpirationTime` is failing with `Assert.NotNull() Failure: Value is null`. Indicates potential bug in session expiration handling.

#### #86 - Fix Failed Test
- **Priority**: Important
- **Type**: Bug
- **Component**: Scaffolder
- **Reason**: `IdGenerationTests.BuildFormFields_ForCreate_ExcludesAutoGeneratedIdField` is failing. The test expects auto-generated ID fields to be excluded from create forms, but they're being included. Affects scaffolding reliability.

---

### Nice to Have Issues (12)

#### #57 - Virtual Objects: runtime-defined entity types from JSON metadata
- **Priority**: Nice to Have
- **Type**: New Feature Request
- **Component**: Scaffolder
- **Reason**: Support defining entity types via JSON metadata at startup rather than compile-time C# classes. Advanced feature for dynamic systems but not critical.

#### #58 - Computed properties: memoized snapshots vs live lookups on related entities
- **Priority**: Nice to Have
- **Type**: New Feature Request
- **Component**: Scaffolder
- **Reason**: Support computed/derived properties that resolve values from related entities. Useful feature but not critical for basic operations.

#### #59 - Remote Methods: server-side commands invocable from entity UI
- **Priority**: Nice to Have
- **Type**: New Feature Request
- **Component**: API Extension
- **Reason**: Allow decorating methods with `[RemoteCommand]` to invoke server-side logic from entity UI. Useful for custom workflows but not essential.

#### #64 - Bulk operations on entity list views
- **Priority**: Nice to Have
- **Type**: New Feature Request
- **Component**: HTML
- **Reason**: Select multiple rows and perform batch operations. Common admin feature but not critical for basic CRUD.

#### #65 - Export support for embedded/nested components
- **Priority**: Nice to Have
- **Type**: New Feature Request
- **Component**: Scaffolder
- **Reason**: CSV export exists for top-level entities but not for embedded/nested components. Useful but not essential.

#### #66 - Client-side calculated fields with expression engine
- **Priority**: Nice to Have
- **Type**: New Feature Request
- **Component**: HTML
- **Reason**: Lightweight calculated fields that run in the browser. Useful for real-time feedback but not critical.

#### #69 - Reporting layer: cross-entity joins, report definitions, and HTML report generator
- **Priority**: Nice to Have
- **Type**: New Feature Request
- **Component**: Query
- **Reason**: Full reporting framework with INNER JOIN semantics. Nice feature for analytics but not essential for core operations.

#### #70 - Reporting: LEFT, RIGHT, and FULL OUTER JOIN support
- **Priority**: Nice to Have
- **Type**: New Feature Request
- **Component**: Query
- **Reason**: Extends #69 with additional join types. Useful for advanced reporting but not critical.

#### #80 - Where there is a lookup field in the GUI at the moment we render the Title, and the related Looked up GUID (ID) and a button to open the linked entity
- **Priority**: Nice to Have
- **Type**: Enrichment
- **Component**: HTML
- **Reason**: Remove redundant GUID display from lookup fields to save screen real estate. Improves usability but not critical.

#### #84 - UI Fluff
- **Priority**: Nice to Have
- **Type**: Enrichment
- **Component**: HTML
- **Reason**: Render boolean True/False as green checked or red unchecked checkboxes. Nice visual improvement but not essential.

#### #79 - test output is verbose and challenging to scan for errors
- **Priority**: Nice to Have
- **Type**: Enrichment
- **Component**: Other
- **Reason**: Configure test runner to only output errors to reduce noise. Developer experience improvement.

#### #107 - New List features
- **Priority**: Nice to Have
- **Type**: New Feature Request
- **Component**: HTML
- **Reason**: Add filter/group/sort capabilities to list views. Useful enhancement but pagination/search (#61) is more critical.

---

### Superfluous Issues (2)

#### #67 - 🔬 Exploration: client-side rendering and partial client templating
- **Priority**: Superfluous
- **Type**: New Feature Request
- **Component**: Renderer
- **Reason**: Explicitly marked "⚠️ EXPLORATION ONLY — DO NOT MERGE". Design spike to investigate possibilities, not for implementation.

#### #68 - 🔬 Exploration: JS lookup() function for dynamic client-side data queries
- **Priority**: Superfluous
- **Type**: New Feature Request
- **Component**: HTML
- **Reason**: Explicitly marked "⚠️ EXPLORATION ONLY — DO NOT MERGE". Research-only exploration of client-side data access patterns.

---

## Summary Statistics

- **Total Issues**: 26
- **By Priority**:
  - Critical: 3 (11.5%)
  - Important: 9 (34.6%)
  - Nice to Have: 12 (46.2%)
  - Superfluous: 2 (7.7%)
- **By Type**:
  - Security: 2 (7.7%)
  - Bug: 7 (26.9%)
  - New Feature Request: 15 (57.7%)
  - Enrichment: 2 (7.7%)
- **By Component**:
  - Host: 5 (19.2%)
  - HTML: 8 (30.8%)
  - Scaffolder: 7 (26.9%)
  - Storage: 2 (7.7%)
  - Query: 3 (11.5%)
  - Indexing: 1 (3.8%)
  - API Extension: 1 (3.8%)
  - Renderer: 1 (3.8%)
  - Other: 1 (3.8%)

## Recommended Action Plan

### Immediate (Critical Issues)
1. **#75, #76**: Fix security test gaps in MFA and cookie protection
2. **#77**: Fix auto-ID generation for API and CSV flows

### Short-term (Important Issues)
1. **#78, #86**: Fix failing unit tests
2. **#73, #74**: Address code review findings
3. **#60**: Implement field validation framework (security/data integrity)
4. **#61**: Add search/filtering/pagination (usability blocker)
5. **#71**: Activate secondary indexes (performance)
6. **#62**: Add audit trail (compliance)
7. **#63**: Implement file upload (common use case)

### Medium-term (Nice to Have Features)
- Focus on UI polish (#80, #84, #107)
- Advanced features (#57, #58, #59, #64, #65, #66)
- Reporting layer (#69, #70)
- Developer experience (#79)

### Track but Don't Implement (Superfluous)
- #67, #68: Keep for research reference but don't merge

---

*Generated on 2026-02-18*
