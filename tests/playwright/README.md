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

- **`CIMIGRATE_TEST_USERNAME`** - Username for initial setup (default: 'admin')
- **`CIMIGRATE_TEST_DISPLAYNAME`** - Display name for initial setup (default: 'Admin User')
- **`CIMIGRATE_TEST_PASSWORD`** - Password for initial setup (default: 'Admin123!')

These credentials are used when creating the initial admin account during the setup flow.

## Running Tests

### Against deployed site (CI Reset environment)

```bash
BASE_URL=https://baremetalweb-cireset.azurewebsites.net \
CIMIGRATE_TEST_USERNAME=admin \
CIMIGRATE_TEST_PASSWORD=YourSecurePassword123! \
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
   CIMIGRATE_TEST_USERNAME=admin \
   CIMIGRATE_TEST_PASSWORD=Admin123! \
   npm test
   ```

### Run tests with UI mode (for debugging)

```bash
BASE_URL=https://baremetalweb-cireset.azurewebsites.net \
CIMIGRATE_TEST_PASSWORD=YourSecurePassword123! \
npm run test:ui
```

### Run tests in headed mode (see the browser)

```bash
BASE_URL=https://baremetalweb-cireset.azurewebsites.net \
CIMIGRATE_TEST_PASSWORD=YourSecurePassword123! \
npm run test:headed
```

## Test Structure

Tests run in two Playwright projects. The **setup** project runs first; the **chromium** project depends on it and runs all remaining tests.

- `tests/setup-and-login.spec.ts` — Initial setup (create admin account), login, logout, and auth redirect tests. Runs as the `setup` project before all others.
- `tests/static-assets.spec.ts` — Verifies that key static files (`site.css`, `vnext-app.js`, etc.) are served with HTTP 200.
- `tests/navigation.spec.ts` — VNext SPA routing: `/UI` shell loads, entity list/create/detail/edit paths work, sidebar nav, browser back/forward, deep-linking.
- `tests/list-view.spec.ts` — Entity list view: table renders, search works, sort updates URL, lookup columns carry `data-lookup-field` attributes for resolution, export buttons present.
- `tests/create-edit.spec.ts` — Create/edit forms: Save button and inputs present, required-field validation blocks empty submit, record creation redirects to detail view, edit form populates with existing values.
- `tests/detail-view.spec.ts` — Detail view: field values in `<dl>`, Edit button links to edit form, breadcrumb navigation, lookup fields link to target entities, JSON export link present.
- `tests/admin-pages.spec.ts` — SSR admin routes: `/admin/logs`, `/admin/sample-data`, and `/reports` load for the admin user; unauthenticated access redirects to `/login`.
- `tests/helpers/auth.ts` — Shared `login()` helper used by all authenticated tests.

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
- The VNext SPA shell and all entity CRUD views load without errors
- Static assets are served correctly
- Admin system pages are accessible to admin users
- The application can start from a clean state successfully
