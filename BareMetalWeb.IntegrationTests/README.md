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

The tests require the following environment variables:

### Required
- `CIMIGRATE_TEST_USERNAME` - Username for test account
- `CIMIGRATE_TEST_PASSWORD` - Password for test account

### Optional
- `CIMIGRATE_BASE_URL` - Base URL of the deployed instance (defaults to `https://baremetalweb-cimigrate.azurewebsites.net`)

## Running Tests Locally

```bash
# Set environment variables
export CIMIGRATE_TEST_USERNAME="your-test-username"
export CIMIGRATE_TEST_PASSWORD="your-test-password"
export CIMIGRATE_BASE_URL="https://baremetalweb-cimigrate.azurewebsites.net"

# Run integration tests
dotnet test BareMetalWeb.IntegrationTests --filter "FullyQualifiedName~IntegrationTests"
```

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

Before running these tests for the first time:

1. Deploy the application to the target environment
2. Create a test user account with appropriate permissions
3. Store the credentials in GitHub Secrets (for CI) or environment variables (for local testing)

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

If tests fail:

1. **Check the deployed site** - Manually navigate to the base URL to verify it's running
2. **Verify credentials** - Ensure the test account exists and credentials are correct
3. **Check environment variables** - Ensure all required variables are set
4. **Review test output** - Error messages indicate what failed
5. **Wait for deployment** - The site may need time to warm up after deployment

## Local Development

For local testing against a local instance:

```bash
export CIMIGRATE_BASE_URL="https://localhost:5001"
export CIMIGRATE_TEST_USERNAME="testuser"
export CIMIGRATE_TEST_PASSWORD="testpass"

dotnet test BareMetalWeb.IntegrationTests
```

Note: You may need to handle SSL certificate validation for local HTTPS testing.
