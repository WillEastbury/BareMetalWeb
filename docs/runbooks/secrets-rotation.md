# Secrets Rotation Runbook

## Purpose

Procedures for rotating encryption keys, API keys, SSL certificates, and service principals used by BareMetalWeb.

---

## Secret Inventory

| Secret | Storage | Scope | Rotation Impact |
|--------|---------|-------|-----------------|
| `BMW_WAL_ENCRYPTION_KEY` | Environment variable | Data encryption at rest | **HIGH** — requires data re-encryption |
| API Keys | Data store (`SystemPrincipal`) | Per-service API access | LOW — clients need updated key |
| Session cookies | DataProtection API | User sessions | LOW — users re-authenticate |
| `EntraId.ClientSecret` | `Metal.config` | Azure AD authentication | MEDIUM — SSO breaks until updated |
| `AZURE_CREDENTIALS_CIMIGRATE` | GitHub Secrets | CI/CD deployment | LOW — deploys fail until updated |
| SSL/TLS certificates | Kestrel config / reverse proxy | HTTPS termination | MEDIUM — HTTPS breaks if expired |

---

## 1. WAL Encryption Key Rotation

**Risk: HIGH** — Incorrect rotation makes all encrypted data unreadable.

### Current Setup

- Key: Base64-encoded 256-bit AES key in `BMW_WAL_ENCRYPTION_KEY` environment variable
- Algorithm: AES-256-GCM with HKDF-SHA256 per-file key derivation
- Scope: WAL segments, snapshots, log files (when encryption enabled)
- Format: 24-byte header (Magic `ENCF`, version, nonce) + ciphertext + 16-byte GCM tag

### Rotation Procedure

1. **Take a full backup with the current key:**
   ```bash
   # Ensure backup is created with current encryption key
   # The backup service will use the current BMW_WAL_ENCRYPTION_KEY
   ```

2. **Stop the server**

3. **Decrypt all data with the old key:**
   ```bash
   # The application handles transparent decryption on read
   # Data is re-encrypted on next write with whatever key is configured
   ```

4. **Set the new key:**
   ```bash
   export BMW_WAL_ENCRYPTION_KEY="<new-base64-encoded-256-bit-key>"

   # Generate a new key:
   openssl rand -base64 32
   ```

5. **Start the server** — new writes will use the new key

6. **Force re-encryption of existing data:**
   - Trigger compaction on all WAL segments — compaction reads with old key (via backward compatibility) and writes with new key
   - Or: Take a new snapshot (reads old, writes new)

7. **Verify:**
   ```bash
   curl -s http://localhost:5232/health | jq .
   # Verify reads still work (old data decrypted, new data encrypted with new key)
   ```

**Important:** The old key is no longer needed once all data has been re-encrypted via compaction.

**Warning:** If you lose the encryption key before all data is re-encrypted, the encrypted data is **permanently unrecoverable**.

---

## 2. API Key Rotation

### Procedure

1. **Generate a new API key** for the service principal

2. **Update the API key in the data store:**
   ```bash
   # Via admin API (requires admin authentication)
   curl -X PATCH http://localhost:5232/api/admin/system-principals/<principal-id> \
     -H "Content-Type: application/json" \
     -H "ApiKey: <current-admin-key>" \
     -d '{"apiKey": "<new-api-key>"}'
   ```

3. **Update clients** — distribute the new key to all services using the old one

4. **Verify** — test the new key works:
   ```bash
   curl -s -H "ApiKey: <new-key>" http://localhost:5232/api/health
   ```

5. **Revoke the old key** — once all clients are updated

### Bulk Rotation

For rotating all API keys at once (e.g., after a suspected breach):
1. Generate new keys for each principal
2. Update all at once
3. Distribute to clients
4. Monitor for 401 errors from clients still using old keys

---

## 3. Session Invalidation

To force all users to re-authenticate:

### Selective (Single User)

```bash
# Delete the user's session record from the data store
# Sessions are stored as UserSession entities
# Look up by userId and delete
```

### Global (All Sessions)

```bash
# Restart the server with DataProtection key rotation
# This invalidates all existing session cookies

# Or: Delete all UserSession records from the data store
```

**Impact:** All active users will be logged out and need to re-authenticate. MFA challenges will be reset.

---

## 4. EntraID / OAuth Client Secret

### Procedure

1. **Generate new client secret** in Azure Portal:
   - Azure AD → App Registrations → your app → Certificates & secrets → New client secret

2. **Update `Metal.config`:**
   ```
   EntraId.ClientSecret|<new-secret>
   ```

3. **Restart the server** — configuration is loaded at startup via `BmwConfig.Load()`

4. **Verify SSO login** works with the new secret

5. **Delete the old secret** in Azure Portal

**Note:** `BmwConfig` automatically masks secrets in logs (replaced with "****"), so the old secret won't appear in log files.

---

## 5. CI/CD Deployment Credentials

### Azure Service Principal (GitHub Actions)

1. **Create new service principal** or reset credentials:
   ```bash
   az ad sp credential reset --id <app-id>
   ```

2. **Update GitHub Secrets:**
   - Repository → Settings → Secrets and variables → Actions
   - Update `AZURE_CREDENTIALS_CIMIGRATE` with new JSON credentials:
     ```json
     {
       "clientId": "<app-id>",
       "clientSecret": "<new-secret>",
       "subscriptionId": "<sub-id>",
       "tenantId": "<tenant-id>"
     }
     ```

3. **Test** — trigger a deployment workflow:
   ```bash
   gh workflow run deploy-cimigrate.yml --repo WillEastbury/BareMetalWeb
   ```

4. **Update other secrets** if applicable:
   - `CIMIGRATE_TEST_USERNAME`
   - `CIMIGRATE_TEST_PASSWORD`

---

## 6. SSL/TLS Certificate Rotation

### If Using Reverse Proxy (Recommended)

1. Obtain new certificate from your CA
2. Update the reverse proxy (nginx, Azure App Gateway, etc.)
3. No BareMetalWeb restart needed

### If Using Kestrel Directly

1. Obtain new certificate
2. Update `appsettings.json` Kestrel HTTPS configuration
3. Restart the server

---

## Prevention

- **Rotation schedule:**
  | Secret | Frequency |
  |--------|-----------|
  | Encryption key | Annually or after suspected compromise |
  | API keys | Quarterly |
  | OAuth client secrets | Before expiration (track in calendar) |
  | SSL certificates | Before expiration (automate with Let's Encrypt/ACME) |
  | CI/CD credentials | Annually |

- **Never store secrets in code** — use environment variables or secret management (Azure Key Vault, etc.)
- **Audit secret access** — monitor who/what accesses secrets
- **Use short-lived credentials** where possible (e.g., managed identity instead of service principal)

---

## Escalation

| Condition | Action |
|-----------|--------|
| Encryption key lost | **Data is unrecoverable** — restore from unencrypted backup if available |
| Multiple secrets compromised simultaneously | Treat as active breach — see [Security Incident](security-incident.md) |
| Cannot rotate without downtime | Schedule maintenance window; notify users |
| Azure AD app registration compromised | Contact Azure AD admin; revoke all credentials; create new app registration |
