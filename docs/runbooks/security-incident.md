# Security Incident Response Runbook

## Purpose

Procedures for responding to suspected security breaches, unauthorized access, and data exposure incidents.

---

## Severity Classification

| Level | Description | Examples |
|-------|-------------|----------|
| **CRITICAL** | Active breach, data exfiltration | Unauthorized admin access, WAL data exported |
| **HIGH** | Credential compromise, vulnerability exploited | API key leaked, brute-force successful |
| **MEDIUM** | Suspicious activity, potential exposure | Unusual login patterns, rate limit bypass attempts |
| **LOW** | Policy violation, minor exposure | Weak password detected, session not expiring |

---

## Symptoms

- Unusual spike in authentication failures (401/403 responses)
- Successful logins from unexpected locations/IPs
- API key usage from unknown sources
- Rate limiter triggered excessively from single IP
- Unauthorized data access patterns in logs
- Unexpected admin operations in audit trail

---

## Immediate Response (CRITICAL/HIGH)

### 1. Contain

```bash
# Block suspicious IP at network level (if possible)
# iptables -A INPUT -s <suspicious-ip> -j DROP

# Check active sessions
grep '"statusCode":200' Data/Logs/*.log | grep -i "admin\|session" | tail -20

# Check rate limiter — is the attacker being throttled?
curl -s http://localhost:5232/metrics/prometheus | grep bmw_requests_throttled

# Check for brute-force attempts
grep '"statusCode":401' Data/Logs/*.log | awk -F'"sourceIp":"' '{print $2}' | awk -F'"' '{print $1}' | sort | uniq -c | sort -rn | head -10
```

### 2. Assess Scope

```bash
# What endpoints were accessed?
grep '<suspicious-ip>' Data/Logs/*.log | awk -F'"path":"' '{print $2}' | awk -F'"' '{print $1}' | sort | uniq -c | sort -rn

# Were any admin operations performed?
grep '<suspicious-ip>' Data/Logs/*.log | grep -i "admin\|delete\|wipe\|export"

# Were any API keys used?
grep '<suspicious-ip>' Data/Logs/*.log | grep -i "apikey\|ApiKey"

# Check for data exfiltration (large responses, bulk reads)
grep '<suspicious-ip>' Data/Logs/*.log | grep '"method":"GET"' | wc -l
```

### 3. Invalidate Credentials

See [Secrets Rotation](secrets-rotation.md) for detailed procedures. Quick actions:

```bash
# Rotate API keys — requires database update
# The compromised API key must be revoked in the SystemPrincipal store

# Invalidate all sessions (nuclear option)
# Delete session records from the data store
# Users will need to re-authenticate

# Rotate encryption key (if key was compromised)
# WARNING: This makes existing encrypted data unreadable until re-encrypted
# See secrets-rotation.md for the full procedure
```

---

## Diagnosis Deep Dive

### Authentication Analysis

```bash
# Login attempt patterns (check for credential stuffing)
grep "login\|Login\|authenticate" Data/Logs/*.log | tail -50

# MFA bypass attempts
grep "mfa\|MFA\|totp" Data/Logs/*.log | grep -i "fail" | tail -20

# Session anomalies (concurrent sessions from different IPs)
grep "session" Data/Logs/*.log | grep '"statusCode":200' | \
  awk -F'"userId":"' '{print $2}' | awk -F'"' '{print $1}' | sort | uniq -c | sort -rn | head -10
```

### Application-Level Checks

```bash
# Check if Admin.AllowWipeData was enabled (critical)
grep "AllowWipeData\|wipe" Data/Metal.config Data/Logs/*.log

# Check for OAuth/EntraID configuration tampering
grep "EntraId\|ClientId\|TenantId" Data/Metal.config

# Check for configuration changes
ls -lt Data/Metal.config
# Compare against known-good configuration
```

### WAL Data Integrity

```bash
# Check for unexpected data deletions (tombstones)
curl -s http://localhost:5232/metrics/prometheus | grep bmw_wal

# Check backup integrity — compare latest backup count vs current
grep '\[BMW WAL\] Recovery complete' Data/Logs/*.log | tail -5
```

---

## Resolution

### After Containment

1. **Document everything** — timeline, IPs, endpoints accessed, data potentially exposed
2. **Preserve evidence** — copy logs before rotation: `cp -r Data/Logs/ /secure/evidence/`
3. **Rotate all credentials** — see [Secrets Rotation](secrets-rotation.md)
4. **Patch vulnerability** — if a code vulnerability was exploited, deploy fix
5. **Notify stakeholders** — follow your organization's breach notification policy

### Hardening Measures

1. **Tighten rate limits** — reduce `MaxReadsPerMinute` and `MaxWritesPerMinute` in `ApiRateLimiter`
2. **Enable PII redaction** — `Logging.RedactPII|true` in `Metal.config`
3. **Review auth settings:**
   ```
   Auth.AllowAccountCreation|false    # Disable open registration
   Admin.AllowWipeData|false          # Never in production
   ```
4. **Enable encryption at rest** — set `BMW_WAL_ENCRYPTION_KEY` if not already configured
5. **Review HTTPS settings** — `Https.RedirectMode|Always`

---

## Prevention

- **Monitor auth failures** — alert on > 10 failures/minute from single IP
- **Enable MFA** for all admin accounts
- **Rotate API keys** on a regular schedule (quarterly minimum)
- **Restrict `Admin.AllowWipeData`** — never enable in production
- **Review access logs** regularly for unusual patterns
- **Keep secrets out of logs** — `BmwConfig` automatically masks sensitive values with "****"
- **Use network-level protections** — WAF, IP allowlisting for admin endpoints

### Rate Limiting as Defense

BareMetalWeb has built-in protection:

| Protection | Mechanism | Config |
|------------|-----------|--------|
| Login brute-force | Per-IP + per-user exponential backoff | `AttemptTracker` (10 attempts → 10s backoff) |
| Registration abuse | Per-IP limit | 3 attempts per window (`RegisterIpMaxAttempts`) |
| API abuse | Per-identity sliding window | 300 reads/min, 60 writes/min |
| MFA brute-force | 6 failures → 10s exponential backoff | Built-in |

---

## Escalation

| Condition | Action |
|-----------|--------|
| Confirmed data breach | Follow legal/compliance breach notification procedures |
| Encryption key compromised | Rotate immediately; re-encrypt all data at rest |
| Cannot determine scope of breach | Engage external security team for forensic analysis |
| Ongoing active attack | Consider taking service offline until contained |
