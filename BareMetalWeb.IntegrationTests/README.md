# BareMetalWeb Integration Tests

This project contains integration tests that run against a deployed BareMetalWeb instance.

## Purpose

These tests verify:
- Basic HTTP connectivity to the deployed site
- Authentication and login functionality
- Protected page access control
- Static file serving
- API endpoint availability

## Configuration

The tests support the following environment variables:

### Optional (Auto-generated if not set)
- `CIMIGRATE_TEST_USERNAME` - Username for test account (auto-generated: `testuser_<random>`)
- `CIMIGRATE_TEST_PASSWORD` - Password for test account (auto-generated: `TestPass_<random>_!1aA`)

### Optional (Has default)
- `CIMIGRATE_BASE_URL` - Base URL of the deployed instance (defaults to `https://baremetalweb-cimigrate.azurewebsites.net`)

## Credential Management

**For CI/CD (Consistent Across Runs):**
- Set CIMIGRATE_TEST_USERNAME and CIMIGRATE_TEST_PASSWORD as GitHub secrets
- Tests will use these consistent credentials
- Required for testing against long-lived deployments

**For Local/Integration Testing (Random per Run):**
- Omit environment variables
- Tests auto-generate random credentials for each test run
- Credentials are consistent within a single test run
- Tests automatically use `/setup` endpoint on fresh instances

## Running Tests Locally

The integration tests can run in two modes:

### 1. Against a Deployed Instance (CI/CD or Manual Testing)

Set environment variables to use specific credentials:

```bash
# Set environment variables
export CIMIGRATE_TEST_USERNAME="your-test-username"
export CIMIGRATE_TEST_PASSWORD="your-test-password"
export CIMIGRATE_BASE_URL="https://baremetalweb-cimigrate.azurewebsites.net"

# Run integration tests
dotnet test BareMetalWeb.IntegrationTests
```

### 2. Against a Local or Fresh Instance

If environment variables are **not** set, the tests will:
- Generate random credentials (consistent within the test run)
- Automatically attempt to use the `/setup` endpoint if available
- Create the test user on a fresh BareMetalWeb instance

```bash
# No environment variables needed - tests auto-generate credentials
dotnet test BareMetalWeb.IntegrationTests
```

**Note:** Tests will fail with network errors if no server is running at the base URL. This is expected behavior.

## CI/CD Integration

These tests are automatically run by the `deploy-cimigrate.yml` workflow after deploying to Azure.

The workflow:
1. Builds and deploys the application to `baremetalweb-cimigrate.azurewebsites.net`
2. Waits 30 seconds for deployment to stabilize
3. Runs integration tests using secrets configured in GitHub

### Required GitHub Secrets

- `AZURE_CREDENTIALS_CIMIGRATE` - Azure service principal credentials for deployment
- `CIMIGRATE_TEST_USERNAME` - Test account username
- `CIMIGRATE_TEST_PASSWORD` - Test account password

## Test Account Setup

**For CI/CD:**
- Tests use credentials from GitHub Secrets (CIMIGRATE_TEST_USERNAME and CIMIGRATE_TEST_PASSWORD)
- Account must exist on the deployed instance
- Create the account manually or ensure it exists from a previous test run

**For Local/Fresh Instance:**
- Tests automatically create the account via `/setup` endpoint if needed
- No manual setup required
- Works with brand new BareMetalWeb instances

## Test Categories

### Smoke Tests
- `HomePage_Returns_Success` - Verifies the home page loads
- `StaticFiles_AreAccessible` - Verifies static assets are served

### Authentication Tests
- `Login_WithValidCredentials_Succeeds` - Verifies login with valid credentials
- `Login_WithInvalidCredentials_Fails` - Verifies login rejection with invalid credentials
- `ProtectedPage_WithoutAuthentication_Redirects` - Verifies access control

### API Tests
- `ApiEndpoint_RespondsCorrectly` - Verifies API endpoints are responding

## Troubleshooting

### Tests Fail with Network Errors

This is **expected** when running locally without a server:
- The tests attempt to connect to the base URL
- If no server is running, they fail with connection errors
- This confirms the tests are working correctly

### To Actually Run Tests Successfully

1. **Option A: Test against deployed instance**
   - Set CIMIGRATE_BASE_URL to a running instance
   - Set credentials (or let them auto-generate)
   - Run tests

2. **Option B: Run local server first**
   ```bash
   # Terminal 1: Start the server
   dotnet run --project BareMetalWeb.Host
   
   # Terminal 2: Run tests against local server
   export CIMIGRATE_BASE_URL="https://localhost:5001"
   dotnet test BareMetalWeb.IntegrationTests
   ```

### Tests Fail with Credential Issues

If tests run but fail with authentication errors:

1. **Check the deployed site** - Manually navigate to the base URL to verify it's running
2. **Verify credentials** - Ensure the test account exists and credentials are correct
3. **Check environment variables** - Ensure all required variables are set
4. **Review test output** - Error messages indicate what failed
5. **Wait for deployment** - The site may need time to warm up after deployment

## Local Development

For local testing with a locally running BareMetalWeb instance:

```bash
# Terminal 1: Start the BareMetalWeb server
cd BareMetalWeb.Host
dotnet run

# Terminal 2: Run integration tests
export CIMIGRATE_BASE_URL="https://localhost:5001"
dotnet test BareMetalWeb.IntegrationTests
```

The tests will:
1. Auto-generate random credentials
2. Use the `/setup` endpoint to create the test user (if it's a fresh instance)
3. Run all authentication and integration tests

Note: You may need to handle SSL certificate validation for local HTTPS testing. Consider using `export NODE_TLS_REJECT_UNAUTHORIZED=0` or similar for development.
