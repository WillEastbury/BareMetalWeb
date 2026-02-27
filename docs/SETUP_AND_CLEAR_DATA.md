# Setup and Clear Data Processes

This document explains the first-time setup flow (OOBE), the ways to reset all data at startup, the in-app admin wipe, and the sample-data generator.

---

## Table of Contents

- [First-Time Setup (OOBE)](#first-time-setup-oobe)
  - [How the Redirect Works](#how-the-redirect-works)
  - [Running the Setup Wizard](#running-the-setup-wizard)
  - [Default Data Seeded at Setup](#default-data-seeded-at-setup)
- [Resetting Data at Startup](#resetting-data-at-startup)
  - [Option 1 — reset-data.flag File](#option-1--reset-dataflag-file)
  - [Option 2 — Data:ResetOnStartup Config](#option-2--dataresetonstartup-config)
  - [Safety Guard](#safety-guard)
- [Admin Wipe-Data Endpoint](#admin-wipe-data-endpoint)
  - [Enabling the Endpoint](#enabling-the-endpoint)
  - [Using the Endpoint](#using-the-endpoint)
  - [Security Considerations](#security-considerations)
- [Sample Data Generator](#sample-data-generator)
  - [Generating Sample Data](#generating-sample-data)
  - [Clearing Existing Data Before Generation](#clearing-existing-data-before-generation)
- [Process Comparison](#process-comparison)

---

## First-Time Setup (OOBE)

BareMetalWeb has a built-in Out-of-Box Experience (OOBE). When no users exist in the data store, the server automatically forces all web requests through the setup wizard at `/setup`.

### How the Redirect Works

On every incoming request the server checks whether at least one user exists. If the store is empty:

1. Any request that does **not** already start with `/setup` (or the configured static-file path prefix) receives a `302 Found` redirect to `/setup`.
2. Static file requests are **not** redirected — the CSS/JS required to render the setup page must still be served.
3. Once a root user has been created the check passes immediately for all subsequent requests.

### Running the Setup Wizard

Navigate to your BareMetalWeb instance (or to `/setup` directly). You will see a form with three required fields:

| Field | Description |
|-------|-------------|
| **Username** | The login name for the initial admin account |
| **Email** | The email address for the admin account |
| **Password** | The password for the admin account |

On a successful POST the server:

1. Creates the first `User` record with all registered entity permissions plus `admin` and `monitoring`.
2. Signs the user in automatically.
3. Seeds the default reference data listed below.

The setup route is protected by CSRF — the form token is validated on every POST.

> **Note:** The setup endpoint immediately returns "Root user already exists" if a user account is present, so it cannot be used to overwrite an existing installation.

### Default Data Seeded at Setup

The following reference records are created automatically during setup if they do not already exist:

| Entity | Records created |
|--------|----------------|
| **Currency** | USD (US Dollar, base currency) and GBP (Pound Sterling) |
| **Unit of Measure** | "Each" (abbreviation `EA`) |
| **Address** | A placeholder address (`123 Example Street, London, SW1A 1AA, GB`) |
| **Report Definitions** | Customer List, Orders with Customer, and several other standard reports |
| **Settings** | `app.name`, `app.company`, `app.copyright` — seeded from `AppInfo` configuration values |

These defaults are safe to edit or delete after setup.

---

## Resetting Data at Startup

Two mechanisms allow a complete wipe of the data directory before the server begins accepting requests. Both delete the entire data root folder and recreate it as an empty directory, leaving the application ready for a fresh setup.

### Option 1 — reset-data.flag File

Create a file named `reset-data.flag` in the application content root (the same directory that contains `appsettings.json` and the published binaries):

```bash
# Linux / macOS
touch /path/to/app/reset-data.flag

# Windows PowerShell
New-Item -ItemType File "C:\path\to\app\reset-data.flag"
```

On the **next startup**:

1. The server detects the flag file.
2. The configured data root is deleted recursively.
3. An empty replacement directory is created.
4. The flag file is deleted so the reset does **not** repeat on subsequent starts.
5. A log entry `Data reset complete. Root: <path>` confirms the operation.

This is the recommended mechanism for CI/CD pipelines (see [CI Reset Deployment](CIRESET_DEPLOYMENT.md)).

### Option 2 — Data:ResetOnStartup Config

Set `Data:ResetOnStartup` to `true` in `appsettings.json` (or an environment-specific override):

```json
{
  "Data": {
    "ResetOnStartup": true
  }
}
```

> ⚠️ **Warning:** Unlike the flag-file mechanism, this setting **persists across restarts**. The data root is wiped on every startup until the setting is removed or set back to `false`. Only use this in throwaway environments where data loss is intentional.

### Safety Guard

Both mechanisms refuse to operate if the resolved data root path is the filesystem root (e.g. `/`, `C:\`, `D:\`). If an unsafe path is detected, the reset is skipped and an error is logged:

```
Refusing to reset data root '<path>'. Path is not safe.
```

The default data root is `<content-root>/Data`. Override it in `appsettings.json`:

```json
{
  "Data": {
    "Root": "/var/myapp/data"
  }
}
```

---

## Admin Wipe-Data Endpoint

The `/admin/wipe-data` route provides an in-browser way to delete all entity records without restarting the application. Unlike the startup-reset mechanisms above, it deletes data record-by-record through the registered entity handlers (indexes and any side effects are honoured) rather than deleting the data root folder.

The routes `GET /admin/wipe-data` and `POST /admin/wipe-data` are **always registered**. Access is gated at runtime by the `admin.allowWipeData` setting in the `AppSetting` store — if the setting is absent or empty, both endpoints return **HTTP 419** and refuse to proceed.

### Enabling the Endpoint

Set the `admin.allowWipeData` setting to a non-empty secret token. This can be seeded from `appsettings.json` at first startup:

```json
{
  "Admin": {
    "AllowWipeData": "my-secret-wipe-token"
  }
}
```

The value of this setting becomes the **confirmation token** the user must type exactly (case-sensitive) to trigger the wipe. Leave it empty (or omit it) to keep the endpoint disabled — it will return 419 for all requests.

You can also set or update the value at runtime through the **Settings** admin page (`/ssr/admin/data/settings`) without restarting the server.

> Only set this on staging, development, or test instances. Leave `AllowWipeData` empty (the default) in all production configurations.

### Using the Endpoint

1. Log in as a user with the `admin` permission.
2. Navigate to `/admin/wipe-data`.
3. Read the danger-zone warning carefully.
4. Enter the configured wipe token (the value of `admin.allowWipeData`) in the confirmation field.
5. Click **WIPE ALL DATA**.

On success, all records in every registered entity store are deleted one by one. The page shows a success banner listing the entity types that were cleared.

### Security Considerations

- The endpoint requires admin authentication — unauthenticated or non-admin requests are rejected.
- Every POST is validated with a CSRF token to prevent cross-site request forgery.
- The configured wipe token guards against accidental clicks and unauthorized access.
- The action is **irreversible** — there is no undo or recycle bin.

---

## Sample Data Generator

The `/admin/sample-data` route creates synthetic reference data useful for load testing, UI demonstrations, and search-index testing. It does **not** reset the application — it only adds (or optionally replaces) a configurable number of records.

### Generating Sample Data

1. Log in as a user with the `admin` permission.
2. Navigate to `/admin/sample-data`.
3. Set the count of records to generate for each entity type:

   | Field | Entity | Notes |
   |-------|--------|-------|
   | **Addresses** | Address | Required if customers > 0 |
   | **Customers** | Customer | At least one address needed |
   | **Units** | Unit of Measure | Required if products > 0 |
   | **Products** | Product | At least one unit of measure needed |
   | **Employees** | Employee | Self-referential hierarchy (first few become managers) |
   | **Orders** | Order | Requires at least one customer; auto-seeds currencies if none exist |
   | **To-Do Items** | ToDo | Standalone; generates varied deadlines and periodicities |
   | **Time Table Plans** | TimeTablePlan | Auto-seeds default subjects if none exist |
   | **Lesson Logs** | LessonLog | Auto-seeds default subjects if none exist |

4. Click **Generate**.

The generator appends new records to whatever already exists in the store.

### Clearing Existing Data Before Generation

Enable **Clear existing data** on the form to delete all existing Address, Customer, Unit of Measure, Product, Employee, Order, ToDo, TimeTablePlan, and LessonLog records before generating new ones. This lets you replace test data in one step without running a full data wipe.

> Note: `clearExisting` removes only the entity types listed in the form. Other entity types (invoices, users, currencies, subjects, etc.) are not affected.

#### Auto-seeded dependencies

When generating **Orders** and no currencies exist in the store, the generator automatically seeds five default currencies (USD, EUR, GBP, JPY, CAD) before creating orders.

When generating **Time Table Plans** or **Lesson Logs** and no subjects exist in the store, the generator automatically seeds ten default subjects (Mathematics, English, Science, History, Geography, Art, Music, Physical Education, Computing, Languages).

---

## Process Comparison

| Process | When it runs | Scope | Requires restart | Enabled by default |
|---------|-------------|-------|-----------------|-------------------|
| **OOBE Setup** (`/setup`) | Automatically when no users exist | Creates first user + seeds reference data | No | Yes (always active when user store is empty) |
| **reset-data.flag** | On next startup | Deletes entire data root folder | Yes | No (triggered by creating the flag file) |
| **Data:ResetOnStartup** | On every startup while `true` | Deletes entire data root folder | Yes (repeats every restart) | No |
| **Admin Wipe** (`/admin/wipe-data`) | On demand in browser | Deletes all records in all entity stores | No | No (returns 419 unless `admin.allowWipeData` setting is non-empty) |
| **Sample Data** (`/admin/sample-data`) | On demand in browser | Adds (or optionally replaces) test records | No | Yes (always available to admin users) |
