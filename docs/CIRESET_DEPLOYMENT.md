# CI Reset Site Deployment and Testing

## Overview

The `deploy-cireset.yml` workflow deploys BareMetalWeb to the **baremetalweb-cireset.azurewebsites.net** Azure Web App with a clean data slate and runs automated Playwright tests to validate the setup and login processes.

## Purpose

This workflow serves as a continuous integration test environment that:

1. **Validates clean-slate deployments** - Ensures the application can start from scratch without data
2. **Tests initial setup flow** - Verifies that the first-time setup wizard works correctly
3. **Tests authentication** - Validates login, logout, and session management
4. **Catches regression issues** - Identifies breaking changes in core user flows

## Workflow Triggers

- **Automatic**: Runs on every push to `main` branch
- **Manual**: Can be triggered via workflow_dispatch in GitHub Actions UI

## Workflow Steps

### 1. Build and Test (.NET)
```yaml
- Restore dependencies
- Build in Release configuration
- Run unit tests
```

### 2. Publish with Data Reset Flag
```yaml
- Publish BareMetalWeb.Host to ./publish
- Create reset-data.flag file
```

The `reset-data.flag` tells the application to delete all data on startup (see `BareMetalWeb.Host/Program.cs:278-310`).

### 3. Deploy to Azure
```yaml
- Login to Azure using AZURE_CREDENTIALS_CIRESET secret
- Deploy to baremetalweb-cireset App Service
- Wait 30 seconds for deployment to stabilize
```

### 4. Run Playwright Tests
```yaml
- Setup Node.js
- Install Playwright and dependencies
- Run tests against deployed site
- Upload test reports and results as artifacts
```

## Required Secrets

The workflow requires the following GitHub secrets:

- **`AZURE_CREDENTIALS_CIRESET`** - Azure service principal credentials for the cireset site (already configured)
- **`CIMIGRATE_TEST_USERNAME`** - Username for the OOBE (Out-Of-Box Experience) setup account (already configured)
- **`CIMIGRATE_TEST_DISPLAYNAME`** - Display name for the OOBE setup account (already configured)
- **`CIMIGRATE_TEST_PASSWORD`** - Password for the OOBE setup account (already configured)

These should be configured in the repository settings under Settings → Secrets and variables → Actions.

### Setup Account Credentials

The OOBE setup credentials are used by the Playwright tests to create the initial admin account during the setup flow. The workflow uses the existing `CIMIGRATE_TEST_*` secrets that are shared across CI environments.

## Test Coverage

The Playwright tests in `tests/playwright/tests/setup-and-login.spec.ts` cover:

1. **Initial Setup Flow**
   - Redirect to /setup when no users exist
   - Form validation and submission
   - Automatic login after setup completion

2. **Login Flow**
   - Login page accessibility
   - Credential validation
   - Session creation
   - Post-login redirect

3. **Logout Flow**
   - Logout confirmation
   - Session termination
   - Post-logout state

4. **Authorization**
   - Protected page access control
   - Redirect to login when unauthorized

## Viewing Test Results

After each workflow run:

1. Go to the Actions tab in GitHub
2. Select the workflow run
3. Download artifacts:
   - `playwright-report` - HTML report with screenshots/videos of failures
   - `test-results` - JSON test results

## Local Testing

You can run the same tests locally against the deployed site:

```bash
cd tests/playwright
npm install
npx playwright install chromium
BASE_URL=https://baremetalweb-cireset.azurewebsites.net npm test
```

Or against a local development server with data reset:

```bash
# Terminal 1: Start server with data reset
cd BareMetalWeb.Host
dotnet run -- --data-reset

# Terminal 2: Run tests
cd tests/playwright
BASE_URL=http://localhost:5000 npm test
```

## Troubleshooting

### Tests are failing

1. Check the uploaded `playwright-report` artifact for screenshots and videos
2. Review the workflow logs for error messages
3. Verify the Azure deployment succeeded
4. Ensure the `reset-data.flag` was created and deployed

### Deployment is failing

1. Verify the `AZURE_CREDENTIALS_CIRESET` secret is configured correctly
2. Check that the Azure Web App `baremetalweb-cireset` exists
3. Ensure the service principal has appropriate permissions

### Tests timeout

The workflow waits 30 seconds after deployment. If the site takes longer to start:
- Increase the sleep duration in the workflow
- Check Azure App Service logs for startup issues

## Required Setup Actions

All required GitHub secrets are already configured:

### OOBE Setup Credentials (Already Configured)
- **`CIMIGRATE_TEST_USERNAME`** - Username for initial admin account
- **`CIMIGRATE_TEST_DISPLAYNAME`** - Display name for admin account
- **`CIMIGRATE_TEST_PASSWORD`** - Password for OOBE setup

These credentials are shared with other CI environments and used by Playwright tests during the OOBE setup flow.

### Azure Deployment (Already Configured)
- **`AZURE_CREDENTIALS_CIRESET`** - Service principal for Azure deployment

## Future Enhancements

Potential improvements to this workflow:

- Add performance testing (page load times, API response times)
- Test MFA setup flow
- Test data CRUD operations
- Add accessibility testing
- Test mobile viewports
- Add visual regression testing
