# BareMetalWeb Test Infrastructure

This document provides an overview of the test infrastructure for the BareMetalWeb project.

## Overview

The test infrastructure consists of:

1. **Unit Test Projects** - One test project for each library component
2. **Performance Test Project** - Console application for benchmarking performance
3. **Test Framework** - xUnit for unit testing

## Unit Test Projects

### BareMetalWeb.Core.Tests

Tests for the Core library which contains foundational interfaces and models.

**Tests:**
- `TemplateLoopTests` - Tests for template loop data structures

**Coverage:**
- Template data structures
- Core models and records

### BareMetalWeb.Data.Tests

Tests for the Data library which handles serialization, data storage, and indexing.

**Tests:**
- `BinaryObjectSerializerTests` - Tests for binary serialization

**Coverage:**
- Binary serialization performance
- Object serialization with various data types
- List serialization

**Note:** Deserialization tests require schema definitions and are tested via integration tests with the full DataStore.

### BareMetalWeb.Rendering.Tests

Tests for the Rendering library which handles HTML rendering and CSRF protection.

**Tests:**
- `CsrfProtectionTests` - Tests for CSRF token generation and validation

**Coverage:**
- Token generation (uniqueness, format)
- Fixed-time string comparison (security)

### BareMetalWeb.API.Tests

Tests for the API library.

**Tests:**
- `PlaceholderTests` - Placeholder test (API library currently has no implementation)

**Coverage:**
- Placeholder for future API tests

### BareMetalWeb.Host.Tests

Tests for the Host library which contains the web server and authorization logic.

**Tests:**
- `AuthorizationTests` - Tests for the IsAuthorized method in BareMetalWebServer

**Coverage:**
- Empty/null/whitespace permissions allow public access
- "Public" keyword allows access for all users
- "AnonymousOnly" keyword restricts access to anonymous users only
- "Authenticated" keyword requires any authenticated user
- Specific permission requirements
- Multiple permission requirements (all must be present)
- Case-insensitive permission matching
- Edge cases (permissions that resolve to empty after parsing)

**Test Count:** 18 tests

## Performance Test Project

### BareMetalWeb.PerformanceTests

Console application that benchmarks key performance metrics.

**Features:**
- Sample data generation (Addresses, Customers, Products, Units)
- Binary serialization performance
- Search/indexing operations
- Configurable data sizes via command-line arguments

**See:** [BareMetalWeb.PerformanceTests/README.md](BareMetalWeb.PerformanceTests/README.md) for usage details.

## Running Tests

### Run All Unit Tests

```bash
dotnet test BareMetalWeb.sln
```

### Run Tests for a Specific Project

```bash
dotnet test BareMetalWeb.Core.Tests/
dotnet test BareMetalWeb.Data.Tests/
dotnet test BareMetalWeb.Rendering.Tests/
dotnet test BareMetalWeb.API.Tests/
dotnet test BareMetalWeb.Host.Tests/
```

### Run Performance Tests

```bash
dotnet run --project BareMetalWeb.PerformanceTests
```

With custom parameters:
```bash
dotnet run --project BareMetalWeb.PerformanceTests -- --addresses 1000 --customers 500 --products 250 --units 50
```

## Building Tests

### Build All Tests

```bash
dotnet build BareMetalWeb.sln
```

### Build Specific Test Project

```bash
dotnet build BareMetalWeb.Core.Tests/
dotnet build BareMetalWeb.PerformanceTests/
```

## Test Statistics

As of this implementation:

- **Total Unit Test Projects:** 5
- **Total Unit Tests:** 30
  - Core.Tests: 2 tests
  - Data.Tests: 5 tests
  - Rendering.Tests: 4 tests
  - API.Tests: 1 test
  - Host.Tests: 18 tests
- **Performance Test Projects:** 1
- **Test Framework:** xUnit 2.9.3
- **Target Framework:** .NET 9.0

## Test Guidelines

When adding new tests:

1. **Follow existing patterns** - Match the style and structure of existing tests
2. **Test naming** - Use descriptive names: `MethodName_Scenario_ExpectedBehavior`
3. **Arrange-Act-Assert** - Follow the AAA pattern in test methods
4. **One assertion per test** - Keep tests focused on a single behavior
5. **Use facts for simple tests** - Use `[Fact]` for tests without parameters
6. **Use theories for parameterized tests** - Use `[Theory]` with `[InlineData]` for data-driven tests
7. **Avoid testing internal classes** - Focus on public API unless specifically needed
8. **Mock carefully** - The project avoids heavy dependencies, minimize mocking

## Future Enhancements

Potential additions to the test infrastructure:

- Integration tests for full end-to-end scenarios
- Load tests for concurrent operations
- Deserialization tests with schema definitions
- SearchIndexManager tests (currently internal)
- Web API integration tests
- HTML rendering tests
- Template replacement tests
- Data store integration tests

## Notes

- The binary serializer uses schema-aware serialization, so deserialization tests require schema definitions
- SearchIndexManager is internal and is tested indirectly through DataStore operations
- Performance test results may vary based on system resources
- All test projects target .NET 9.0 to match the main projects
