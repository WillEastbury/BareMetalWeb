# Playwright End-to-End Tests

This directory contains Playwright tests for BareMetalWeb, focusing on testing the application in a clean-slate state.

## Setup

Install dependencies:

```bash
npm install
npx playwright install chromium
```

## Configuration

The tests use environment variables for OOBE setup credentials:

- **`SETUP_USERNAME`** - Username for initial setup (default: 'admin')
- **`SETUP_DISPLAYNAME`** - Display name for initial setup (default: 'Admin User')
- **`SETUP_PASSWORD`** - Password for initial setup (default: 'Admin123!')

These credentials are used when creating the initial admin account during the setup flow.

## Running Tests

### Against deployed site (CI Reset environment)

```bash
BASE_URL=https://baremetalweb-cireset.azurewebsites.net \
SETUP_USERNAME=admin \
SETUP_PASSWORD=YourSecurePassword123! \
npm test
```

### Against local development server

1. Start the BareMetalWeb server with data reset:
   ```bash
   cd ../../
   dotnet run --project BareMetalWeb.Host -- --data-reset
   ```

2. Run tests in another terminal:
   ```bash
   BASE_URL=http://localhost:5000 \
   SETUP_USERNAME=admin \
   SETUP_PASSWORD=Admin123! \
   npm test
   ```

### Run tests with UI mode (for debugging)

```bash
BASE_URL=https://baremetalweb-cireset.azurewebsites.net \
SETUP_PASSWORD=YourSecurePassword123! \
npm run test:ui
```

### Run tests in headed mode (see the browser)

```bash
BASE_URL=https://baremetalweb-cireset.azurewebsites.net \
SETUP_PASSWORD=YourSecurePassword123! \
npm run test:headed
```

## Test Structure

- `tests/setup-and-login.spec.ts` - Tests for initial setup process and login/logout flows

## CI/CD Integration

These tests are automatically run by the `deploy-cireset.yml` GitHub Actions workflow:

1. Build and test the .NET application
2. Deploy to Azure (baremetalweb-cireset.azurewebsites.net) with data reset flag
3. Wait for deployment to stabilize
4. Run Playwright tests against the deployed site with credentials from GitHub secrets

The workflow validates that:
- The initial setup process works correctly
- Login/logout flows function as expected
- Protected pages are properly secured
- The application can start from a clean state successfully
