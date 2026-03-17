using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Auth operations on BaseDataObject records using generic field access.
/// Replaces typed User.SetPassword/VerifyPassword/etc. for the metadata-only architecture.
/// Works with both typed User objects and DataRecord instances.
/// </summary>
public static class UserAuthHelper
{
    private static string? GetString(BaseDataObject record, DataEntityMetadata meta, string fieldName)
    {
        var field = meta.FindField(fieldName);
        return field?.GetValueFn(record)?.ToString();
    }

    private static int GetInt(BaseDataObject record, DataEntityMetadata meta, string fieldName)
    {
        var field = meta.FindField(fieldName);
        if (field == null) return 0;
        var val = field.GetValueFn(record);
        if (val is int i) return i;
        if (val != null && int.TryParse(val.ToString(), out var parsed)) return parsed;
        return 0;
    }

    private static DateTime? GetDateTimeNullable(BaseDataObject record, DataEntityMetadata meta, string fieldName)
    {
        var field = meta.FindField(fieldName);
        if (field == null) return null;
        var val = field.GetValueFn(record);
        if (val is DateTime dt) return dt;
        if (val != null && DateTime.TryParse(val.ToString(), out var parsed)) return parsed;
        return null;
    }

    private static long GetLong(BaseDataObject record, DataEntityMetadata meta, string fieldName)
    {
        var field = meta.FindField(fieldName);
        if (field == null) return 0;
        var val = field.GetValueFn(record);
        if (val is long l) return l;
        if (val is int i) return i;
        if (val != null && long.TryParse(val.ToString(), out var parsed)) return parsed;
        return 0;
    }

    private static bool GetBool(BaseDataObject record, DataEntityMetadata meta, string fieldName)
    {
        var field = meta.FindField(fieldName);
        if (field == null) return false;
        var val = field.GetValueFn(record);
        if (val is bool b) return b;
        if (val != null && bool.TryParse(val.ToString(), out var parsed)) return parsed;
        return false;
    }

    private static void Set(BaseDataObject record, DataEntityMetadata meta, string fieldName, object? value)
    {
        meta.FindField(fieldName)?.SetValueFn(record, value);
    }

    // ── Password ────────────────────────────────────────────────────

    public static void SetPassword(BaseDataObject record, DataEntityMetadata meta, string password, int? iterations = null)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Password cannot be empty.", nameof(password));

        var current = GetInt(record, meta, "PasswordIterations");
        var effective = iterations ?? (current > 0 ? current : 100_000);
        var result = PasswordHasher.CreateHash(password, effective);

        Set(record, meta, "PasswordHash", result.Hash);
        Set(record, meta, "PasswordSalt", result.Salt);
        Set(record, meta, "PasswordIterations", result.Iterations);
    }

    public static bool VerifyPassword(BaseDataObject record, DataEntityMetadata meta, string password)
    {
        var hash = GetString(record, meta, "PasswordHash");
        var salt = GetString(record, meta, "PasswordSalt");

        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(hash) || string.IsNullOrWhiteSpace(salt))
            return false;

        var iterations = GetInt(record, meta, "PasswordIterations");
        if (iterations <= 0) iterations = 100_000;
        return PasswordHasher.Verify(password, hash, salt, iterations);
    }

    // ── Lockout ─────────────────────────────────────────────────────

    public static bool IsLockedOut(BaseDataObject record, DataEntityMetadata meta)
    {
        var lockout = GetDateTimeNullable(record, meta, "LockoutUntilUtc");
        return lockout.HasValue && lockout.Value > DateTime.UtcNow;
    }

    public static void RegisterFailedLogin(BaseDataObject record, DataEntityMetadata meta, int maxFailed = 5, TimeSpan? lockoutDuration = null)
    {
        var count = GetInt(record, meta, "FailedLoginCount") + 1;
        Set(record, meta, "FailedLoginCount", count);
        if (count >= maxFailed)
            Set(record, meta, "LockoutUntilUtc", DateTime.UtcNow.Add(lockoutDuration ?? TimeSpan.FromMinutes(15)));
    }

    public static void RegisterSuccessfulLogin(BaseDataObject record, DataEntityMetadata meta)
    {
        Set(record, meta, "FailedLoginCount", 0);
        Set(record, meta, "LockoutUntilUtc", null);
        Set(record, meta, "LastLoginUtc", DateTime.UtcNow);
    }

    public static void ResetLockout(BaseDataObject record, DataEntityMetadata meta)
    {
        Set(record, meta, "FailedLoginCount", 0);
        Set(record, meta, "LockoutUntilUtc", null);
    }

    // ── MFA state access ────────────────────────────────────────────

    public static bool IsMfaEnabled(BaseDataObject record, DataEntityMetadata meta)
        => GetBool(record, meta, "MfaEnabled");

    public static string? GetMfaSecret(BaseDataObject record, DataEntityMetadata meta)
        => GetString(record, meta, "MfaSecret");

    public static long GetMfaLastVerifiedStep(BaseDataObject record, DataEntityMetadata meta)
        => GetLong(record, meta, "MfaLastVerifiedStep");

    public static void SetMfaLastVerifiedStep(BaseDataObject record, DataEntityMetadata meta, long step)
        => Set(record, meta, "MfaLastVerifiedStep", step);

    public static string? GetMfaSecretEncrypted(BaseDataObject record, DataEntityMetadata meta)
        => GetString(record, meta, "MfaSecretEncrypted");

    public static void SetMfaSecretEncrypted(BaseDataObject record, DataEntityMetadata meta, string? value)
        => Set(record, meta, "MfaSecretEncrypted", value);

    public static string? GetMfaPendingSecret(BaseDataObject record, DataEntityMetadata meta)
        => GetString(record, meta, "MfaPendingSecret");

    public static void SetMfaPendingSecret(BaseDataObject record, DataEntityMetadata meta, string? value)
        => Set(record, meta, "MfaPendingSecret", value);

    public static DateTime? GetMfaPendingExpiresUtc(BaseDataObject record, DataEntityMetadata meta)
        => GetDateTimeNullable(record, meta, "MfaPendingExpiresUtc");

    public static void SetMfaPendingExpiresUtc(BaseDataObject record, DataEntityMetadata meta, DateTime? value)
        => Set(record, meta, "MfaPendingExpiresUtc", value);

    public static int GetMfaPendingFailedAttempts(BaseDataObject record, DataEntityMetadata meta)
        => GetInt(record, meta, "MfaPendingFailedAttempts");

    public static void SetMfaPendingFailedAttempts(BaseDataObject record, DataEntityMetadata meta, int value)
        => Set(record, meta, "MfaPendingFailedAttempts", value);

    public static string? GetMfaPendingSecretEncrypted(BaseDataObject record, DataEntityMetadata meta)
        => GetString(record, meta, "MfaPendingSecretEncrypted");

    public static void SetMfaPendingSecretEncrypted(BaseDataObject record, DataEntityMetadata meta, string? value)
        => Set(record, meta, "MfaPendingSecretEncrypted", value);

    public static void SetMfaEnabled(BaseDataObject record, DataEntityMetadata meta, bool value)
        => Set(record, meta, "MfaEnabled", value);

    public static void SetMfaSecret(BaseDataObject record, DataEntityMetadata meta, string? value)
        => Set(record, meta, "MfaSecret", value);

    public static string[]? GetMfaBackupCodeHashes(BaseDataObject record, DataEntityMetadata meta)
    {
        var field = meta.FindField("MfaBackupCodeHashes");
        if (field == null) return null;
        var val = field.GetValueFn(record);
        if (val is string[] arr) return arr;
        if (val is IEnumerable<string> enumerable) return new List<string>(enumerable).ToArray();
        if (val is string s && !string.IsNullOrEmpty(s)) return s.Split(',');
        return Array.Empty<string>();
    }

    public static void SetMfaBackupCodeHashes(BaseDataObject record, DataEntityMetadata meta, string[] value)
        => Set(record, meta, "MfaBackupCodeHashes", value);

    public static DateTime? GetMfaBackupCodesGeneratedUtc(BaseDataObject record, DataEntityMetadata meta)
        => GetDateTimeNullable(record, meta, "MfaBackupCodesGeneratedUtc");

    public static void SetMfaBackupCodesGeneratedUtc(BaseDataObject record, DataEntityMetadata meta, DateTime? value)
        => Set(record, meta, "MfaBackupCodesGeneratedUtc", value);

    // ── Common user property access ─────────────────────────────────

    public static string GetUserName(BaseDataObject record, DataEntityMetadata meta)
        => GetString(record, meta, "UserName") ?? string.Empty;

    public static string GetDisplayName(BaseDataObject record, DataEntityMetadata meta)
        => GetString(record, meta, "DisplayName") ?? string.Empty;

    public static string GetEmail(BaseDataObject record, DataEntityMetadata meta)
        => GetString(record, meta, "Email") ?? string.Empty;

    public static bool GetIsActive(BaseDataObject record, DataEntityMetadata meta)
        => GetBool(record, meta, "IsActive");

    public static string[] GetPermissions(BaseDataObject record, DataEntityMetadata meta)
    {
        var field = meta.FindField("Permissions");
        if (field == null) return Array.Empty<string>();
        var val = field.GetValueFn(record);
        if (val is string[] arr) return arr;
        if (val is IEnumerable<string> enumerable) return new List<string>(enumerable).ToArray();
        if (val is string s && !string.IsNullOrEmpty(s)) return s.Split(',');
        return Array.Empty<string>();
    }

    // ── SystemPrincipal API key helpers ─────────────────────────────

    public static List<string> GetApiKeyHashes(BaseDataObject record, DataEntityMetadata meta)
    {
        var field = meta.FindField("ApiKeyHashes");
        if (field == null) return new List<string>();
        var val = field.GetValueFn(record);
        if (val is List<string> list) return list;
        if (val is IEnumerable<string> enumerable) return new List<string>(enumerable);
        if (val is string s && !string.IsNullOrEmpty(s)) return new List<string>(s.Split(','));
        return new List<string>();
    }

    public static void AddApiKey(BaseDataObject record, DataEntityMetadata meta, string apiKey, int iterations = 100_000)
    {
        var hashes = GetApiKeyHashes(record, meta);
        var encoded = EncodeApiKey(record, meta, apiKey);
        var (hash, salt, iter) = PasswordHasher.CreateHash(encoded, iterations);
        hashes.Add($"{hash}:{salt}:{iter}");
        Set(record, meta, "ApiKeyHashes", hashes);
    }

    public static bool HasApiKey(BaseDataObject record, DataEntityMetadata meta, string apiKey)
    {
        var hashes = GetApiKeyHashes(record, meta);
        if (string.IsNullOrWhiteSpace(apiKey) || hashes.Count == 0)
            return false;

        var encoded = EncodeApiKey(record, meta, apiKey);
        foreach (var entry in hashes)
        {
            if (TryParseHashEntry(entry, out var hash, out var salt, out var iterations)
                && PasswordHasher.Verify(encoded, hash, salt, iterations))
                return true;
        }
        return false;
    }

    public static string GenerateRawApiKey()
    {
        Span<byte> bytes = stackalloc byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static async ValueTask<BaseDataObject?> FindByApiKeyAsync(string apiKey, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            return null;

        if (!DataScaffold.TryGetEntity("system-principals", out var meta))
            return await SystemPrincipal.FindByApiKeyAsync(apiKey, cancellationToken).ConfigureAwait(false);

        var principals = await meta.Handlers.QueryAsync(null, cancellationToken).ConfigureAwait(false);
        foreach (var principal in principals)
        {
            if (!GetIsActive(principal, meta))
                continue;
            if (HasApiKey(principal, meta, apiKey))
                return principal;
        }
        return null;
    }

    private static string EncodeApiKey(BaseDataObject record, DataEntityMetadata meta, string apiKey)
    {
        var name = GetUserName(record, meta);
        if (string.IsNullOrWhiteSpace(name))
            name = GetDisplayName(record, meta);
        if (string.IsNullOrWhiteSpace(name))
            name = record.Key.ToString();
        var payload = $"{name}:{apiKey}";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
    }

    private static bool TryParseHashEntry(string entry, out string hash, out string salt, out int iterations)
    {
        hash = string.Empty;
        salt = string.Empty;
        iterations = 0;

        if (string.IsNullOrWhiteSpace(entry))
            return false;

        var parts = entry.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 3)
            return false;

        if (!int.TryParse(parts[2], out iterations))
            return false;

        hash = parts[0];
        salt = parts[1];
        return !string.IsNullOrWhiteSpace(hash) && !string.IsNullOrWhiteSpace(salt);
    }

    // ── Generic user lookup helpers ─────────────────────────────────

    public static async ValueTask<BaseDataObject?> FindUserByEmailOrUserNameAsync(string value, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        if (!DataScaffold.TryGetEntity("users", out var meta))
            return null;

        var normalized = value.Trim();
        var users = await meta.Handlers.QueryAsync(null, cancellationToken).ConfigureAwait(false);
        foreach (var user in users)
        {
            var email = GetEmail(user, meta);
            var userName = GetUserName(user, meta);
            if (string.Equals(email, normalized, StringComparison.OrdinalIgnoreCase)
                || string.Equals(userName, normalized, StringComparison.OrdinalIgnoreCase))
                return user;
        }
        return null;
    }

    public static async ValueTask<BaseDataObject?> FindUserByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email))
            return null;

        if (!DataScaffold.TryGetEntity("users", out var meta))
            return null;

        var normalized = email.Trim();
        var users = await meta.Handlers.QueryAsync(null, cancellationToken).ConfigureAwait(false);
        foreach (var user in users)
        {
            if (string.Equals(GetEmail(user, meta), normalized, StringComparison.OrdinalIgnoreCase))
                return user;
        }
        return null;
    }

    public static async ValueTask<BaseDataObject?> FindUserByUserNameAsync(string userName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userName))
            return null;

        if (!DataScaffold.TryGetEntity("users", out var meta))
            return null;

        var normalized = userName.Trim();
        var users = await meta.Handlers.QueryAsync(null, cancellationToken).ConfigureAwait(false);
        foreach (var user in users)
        {
            if (string.Equals(GetUserName(user, meta), normalized, StringComparison.OrdinalIgnoreCase))
                return user;
        }
        return null;
    }

    public static async ValueTask<bool> ExistsByEmailOrUserNameAsync(string value, CancellationToken cancellationToken = default)
        => await FindUserByEmailOrUserNameAsync(value, cancellationToken).ConfigureAwait(false) != null;

    /// <summary>
    /// Load a user by key using the generic DataScaffold handlers.
    /// </summary>
    public static async ValueTask<BaseDataObject?> GetUserByIdAsync(uint key, CancellationToken cancellationToken = default)
    {
        if (!DataScaffold.TryGetEntity("users", out var meta))
            return null;
        return await meta.Handlers.LoadAsync(key, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Save a user record using the generic DataScaffold handlers.
    /// </summary>
    public static async ValueTask SaveUserAsync(BaseDataObject record, CancellationToken cancellationToken = default)
    {
        if (!DataScaffold.TryGetEntity("users", out var meta))
            return;
        await meta.Handlers.SaveAsync(record, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Get the DataEntityMetadata for users. Returns null if not registered.
    /// </summary>
    public static DataEntityMetadata? GetUserMeta()
        => DataScaffold.TryGetEntity("users", out var meta) ? meta : null;

    /// <summary>
    /// Get the DataEntityMetadata for system-principals. Returns null if not registered.
    /// </summary>
    public static DataEntityMetadata? GetPrincipalMeta()
        => DataScaffold.TryGetEntity("system-principals", out var meta) ? meta : null;
}
