# CI Migration Deployment Setup

This document describes the setup process for the CI Migration deployment workflow.

## Overview

The `deploy-cimigrate.yml` workflow automatically builds, deploys to Azure, and runs integration tests against the `baremetalweb-cimigrate.azurewebsites.net` site.

## Required GitHub Secrets

Before the workflow can run successfully, the following secrets must be configured in the GitHub repository:

### 1. AZURE_CREDENTIALS_CIMIGRATE

Azure service principal credentials for deploying to the CI Migration environment.

**How to create:**

```bash
# Login to Azure
az login

# Create a service principal for the resource group
az ad sp create-for-rbac \
  --name "baremetalweb-cimigrate-deploy" \
  --role contributor \
  --scopes /subscriptions/{subscription-id}/resourceGroups/{resource-group} \
  --sdk-auth
```

Copy the entire JSON output and save it as the `AZURE_CREDENTIALS_CIMIGRATE` secret.

**Format:**
```json
{
  "clientId": "...",
  "clientSecret": "...",
  "subscriptionId": "...",
  "tenantId": "...",
  "resourceManagerEndpointUrl": "..."
}
```

### 2. CIMIGRATE_TEST_USERNAME

Username for the test account used by integration tests.

**How to set up:**

1. Deploy the application to `baremetalweb-cimigrate.azurewebsites.net`
2. Create a user account through the application UI or database
3. Save the username as the `CIMIGRATE_TEST_USERNAME` secret

**Example:** `testuser@example.com` or `citest`

### 3. CIMIGRATE_TEST_PASSWORD

Password for the test account used by integration tests.

**How to set up:**

1. Use a strong, randomly generated password
2. Set this password for the test user account
3. Save the password as the `CIMIGRATE_TEST_PASSWORD` secret

**Requirements:**
- Use a strong password (recommended: 16+ characters)
- Store securely in GitHub Secrets
- Rotate periodically for security

## Adding Secrets to GitHub

1. Navigate to your repository on GitHub
2. Go to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Add each secret with the name and value as described above

## Azure Web App Configuration

Ensure the Azure Web App `baremetalweb-cimigrate` is configured properly:

### App Settings

The following app settings may need to be configured in the Azure Portal:

```
ASPNETCORE_ENVIRONMENT=Production
WEBSITE_RUN_FROM_PACKAGE=1
```

### Deployment Settings

- **Platform:** .NET 9.0
- **Operating System:** Linux (recommended) or Windows
- **Deployment Method:** GitHub Actions (configured via this workflow)

## Workflow Behavior

### Triggers

The workflow runs on:
- Push to `main` branch
- Pull requests to `main` branch
- Manual trigger via `workflow_dispatch`

### Jobs

#### 1. build-and-deploy
- Checks out code
- Builds the solution
- Runs unit tests
- Publishes the application
- Deploys to Azure Web App

#### 2. integration-tests
- Runs only if deployment succeeds
- Waits 30 seconds for deployment to stabilize
- Executes integration tests against the deployed site
- Uses the configured test account credentials

## Troubleshooting

### Build Failures

- Check that all projects build successfully locally
- Review build logs in GitHub Actions
- Ensure .NET 9.0 SDK is available

### Deployment Failures

- Verify `AZURE_CREDENTIALS_CIMIGRATE` is correctly configured
- Check Azure service principal has contributor role on the resource group
- Verify the Web App name is correct (`baremetalweb-cimigrate`)

### Integration Test Failures

- Ensure test account exists on the deployed site
- Verify `CIMIGRATE_TEST_USERNAME` and `CIMIGRATE_TEST_PASSWORD` are correct
- Check that the site is accessible at `https://baremetalweb-cimigrate.azurewebsites.net`
- Review integration test logs for specific failure details
- Increase wait time in workflow if deployment takes longer than 30 seconds

### Manual Testing

To manually run integration tests locally:

```bash
export CIMIGRATE_BASE_URL="https://baremetalweb-cimigrate.azurewebsites.net"
export CIMIGRATE_TEST_USERNAME="your-test-username"
export CIMIGRATE_TEST_PASSWORD="your-test-password"

dotnet test BareMetalWeb.IntegrationTests
```

## Security Considerations

- **Never commit secrets** to the repository
- Store all sensitive values in GitHub Secrets
- Use strong, unique passwords for test accounts
- Rotate service principal credentials periodically
- Limit service principal permissions to only what's needed
- Review and audit secret access regularly

## Monitoring

After deployment:

1. Check the GitHub Actions workflow run for any errors
2. Verify the site is accessible at `https://baremetalweb-cimigrate.azurewebsites.net`
3. Review integration test results
4. Monitor Azure Application Insights (if configured)
5. Check Azure Web App logs for runtime errors

## Next Steps

1. Configure all required GitHub secrets
2. Create the test user account on the deployed site
3. Test the workflow with a manual trigger
4. Monitor the first few automated deployments
5. Set up notifications for deployment failures (optional)
