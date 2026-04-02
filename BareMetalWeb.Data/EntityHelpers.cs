using System;
using System.Collections.Generic;
using System.Text;

namespace BareMetalWeb.Data;

/// <summary>
/// Static helpers for UserSession DataRecords.
/// Replaces the typed UserSession class.
/// </summary>
public static class UserSessionHelper
{
    private static void Guard(DataRecord record)
    {
        var name = record.EntityTypeName;
        if (!string.Equals(name, "UserSession", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(name, "user-sessions", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(record.Schema?.Slug, "user-sessions", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Expected UserSession record, got '{name}'.");
    }

    public static bool IsExpired(DataRecord record, DateTime utcNow)
    {
        Guard(record);
        if (IsRevoked(record))
            return true;
        var expires = record.GetFieldValue(UserSessionFields.ExpiresUtc);
        if (expires is DateTime dt) return utcNow >= dt;
        if (expires != null && DateTime.TryParse(expires.ToString(), out var parsed)) return utcNow >= parsed;
        return true;
    }

    public static string GetUserId(DataRecord record)
        => record.GetFieldValue(UserSessionFields.UserId)?.ToString() ?? string.Empty;

    public static void SetUserId(DataRecord record, string value)
        => record.SetFieldValue(UserSessionFields.UserId, value);

    public static string GetUserName(DataRecord record)
        => record.GetFieldValue(UserSessionFields.UserName)?.ToString() ?? string.Empty;

    public static void SetUserName(DataRecord record, string value)
        => record.SetFieldValue(UserSessionFields.UserName, value);

    public static string GetDisplayName(DataRecord record)
        => record.GetFieldValue(UserSessionFields.DisplayName)?.ToString() ?? string.Empty;

    public static void SetDisplayName(DataRecord record, string value)
        => record.SetFieldValue(UserSessionFields.DisplayName, value);

    public static string[] GetPermissions(DataRecord record)
    {
        var val = record.GetFieldValue(UserSessionFields.Permissions);
        if (val is string[] arr) return arr;
        if (val is string s && !string.IsNullOrEmpty(s))
            return s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return Array.Empty<string>();
    }

    public static void SetPermissions(DataRecord record, string[] value)
        => record.SetFieldValue(UserSessionFields.Permissions, value);

    public static DateTime GetIssuedUtc(DataRecord record)
        => record.GetFieldValue(UserSessionFields.IssuedUtc) is DateTime dt ? dt : default;

    public static void SetIssuedUtc(DataRecord record, DateTime value)
        => record.SetFieldValue(UserSessionFields.IssuedUtc, value);

    public static DateTime GetExpiresUtc(DataRecord record)
        => record.GetFieldValue(UserSessionFields.ExpiresUtc) is DateTime dt ? dt : default;

    public static void SetExpiresUtc(DataRecord record, DateTime value)
        => record.SetFieldValue(UserSessionFields.ExpiresUtc, value);

    public static DateTime GetLastSeenUtc(DataRecord record)
        => record.GetFieldValue(UserSessionFields.LastSeenUtc) is DateTime dt ? dt : default;

    public static void SetLastSeenUtc(DataRecord record, DateTime value)
        => record.SetFieldValue(UserSessionFields.LastSeenUtc, value);

    public static bool GetRememberMe(DataRecord record)
        => record.GetFieldValue(UserSessionFields.RememberMe) is true;

    public static void SetRememberMe(DataRecord record, bool value)
        => record.SetFieldValue(UserSessionFields.RememberMe, value);

    public static bool IsRevoked(DataRecord record)
        => record.GetFieldValue(UserSessionFields.IsRevoked) is true;

    public static void SetIsRevoked(DataRecord record, bool value)
        => record.SetFieldValue(UserSessionFields.IsRevoked, value);
}

/// <summary>
/// Static helpers for MfaChallenge DataRecords.
/// </summary>
public static class MfaChallengeHelper
{
    private static void Guard(DataRecord record)
    {
        var name = record.EntityTypeName;
        if (!string.Equals(name, "MfaChallenge", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(name, "mfa-challenges", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(record.Schema?.Slug, "mfa-challenges", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Expected MfaChallenge record, got '{name}'.");
    }

    public static bool IsExpired(DataRecord record)
    {
        Guard(record);
        if (GetIsUsed(record)) return true;
        var expires = record.GetFieldValue(MfaChallengeFields.ExpiresUtc);
        if (expires is DateTime dt) return DateTime.UtcNow >= dt;
        if (expires != null && DateTime.TryParse(expires.ToString(), out var parsed)) return DateTime.UtcNow >= parsed;
        return true;
    }

    public static string GetUserId(DataRecord record)
        => record.GetFieldValue(MfaChallengeFields.UserId)?.ToString() ?? string.Empty;

    public static void SetUserId(DataRecord record, string value)
        => record.SetFieldValue(MfaChallengeFields.UserId, value);

    public static bool GetRememberMe(DataRecord record)
        => record.GetFieldValue(MfaChallengeFields.RememberMe) is true;

    public static void SetRememberMe(DataRecord record, bool value)
        => record.SetFieldValue(MfaChallengeFields.RememberMe, value);

    public static DateTime GetExpiresUtc(DataRecord record)
        => record.GetFieldValue(MfaChallengeFields.ExpiresUtc) is DateTime dt ? dt : default;

    public static void SetExpiresUtc(DataRecord record, DateTime value)
        => record.SetFieldValue(MfaChallengeFields.ExpiresUtc, value);

    public static bool GetIsUsed(DataRecord record)
        => record.GetFieldValue(MfaChallengeFields.IsUsed) is true;

    public static void SetIsUsed(DataRecord record, bool value)
        => record.SetFieldValue(MfaChallengeFields.IsUsed, value);
}

/// <summary>
/// Static helpers for DeviceCodeAuth DataRecords.
/// </summary>
public static class DeviceCodeAuthHelper
{
    private static void Guard(DataRecord record)
    {
        var name = record.EntityTypeName;
        if (!string.Equals(name, "DeviceCodeAuth", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(name, "device-code-auth", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(record.Schema?.Slug, "device-code-auth", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Expected DeviceCodeAuth record, got '{name}'.");
    }

    public static bool IsExpired(DataRecord record, DateTime utcNow)
    {
        Guard(record);
        var expires = record.GetFieldValue(DeviceCodeAuthFields.ExpiresUtc);
        if (expires is DateTime dt) return utcNow >= dt;
        if (expires != null && DateTime.TryParse(expires.ToString(), out var parsed)) return utcNow >= parsed;
        return true;
    }

    public static string GetUserCode(DataRecord record)
        => record.GetFieldValue(DeviceCodeAuthFields.UserCode)?.ToString() ?? string.Empty;

    public static void SetUserCode(DataRecord record, string value)
        => record.SetFieldValue(DeviceCodeAuthFields.UserCode, value);

    public static string GetDeviceCode(DataRecord record)
        => record.GetFieldValue(DeviceCodeAuthFields.DeviceCode)?.ToString() ?? string.Empty;

    public static void SetDeviceCode(DataRecord record, string value)
        => record.SetFieldValue(DeviceCodeAuthFields.DeviceCode, value);

    public static DateTime GetExpiresUtc(DataRecord record)
        => record.GetFieldValue(DeviceCodeAuthFields.ExpiresUtc) is DateTime dt ? dt : default;

    public static void SetExpiresUtc(DataRecord record, DateTime value)
        => record.SetFieldValue(DeviceCodeAuthFields.ExpiresUtc, value);

    public static string GetStatus(DataRecord record)
        => record.GetFieldValue(DeviceCodeAuthFields.Status)?.ToString() ?? "pending";

    public static void SetStatus(DataRecord record, string value)
        => record.SetFieldValue(DeviceCodeAuthFields.Status, value);

    public static string GetUserId(DataRecord record)
        => record.GetFieldValue(DeviceCodeAuthFields.UserId)?.ToString() ?? string.Empty;

    public static void SetUserId(DataRecord record, string value)
        => record.SetFieldValue(DeviceCodeAuthFields.UserId, value);

    public static string GetClientDescription(DataRecord record)
        => record.GetFieldValue(DeviceCodeAuthFields.ClientDescription)?.ToString() ?? string.Empty;

    public static void SetClientDescription(DataRecord record, string value)
        => record.SetFieldValue(DeviceCodeAuthFields.ClientDescription, value);

    private static readonly char[] CodeChars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789".ToCharArray();

    public static string GenerateUserCode()
    {
        var bytes = new byte[8];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        var chars = new char[9];
        for (int i = 0; i < 4; i++)
            chars[i] = CodeChars[bytes[i] % CodeChars.Length];
        chars[4] = '-';
        for (int i = 0; i < 4; i++)
            chars[i + 5] = CodeChars[bytes[i + 4] % CodeChars.Length];
        return new string(chars);
    }

    public static string GenerateDeviceCode()
    {
        var bytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

/// <summary>
/// Static helpers for SystemPrincipal DataRecords.
/// API key management methods that work with plain DataRecord instances.
/// </summary>
public static class SystemPrincipalHelper
{
    private static void Guard(DataRecord record)
    {
        var name = record.EntityTypeName;
        if (!string.Equals(name, "SystemPrincipal", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(name, "system-principals", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(record.Schema?.Slug, "system-principals", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Expected SystemPrincipal record, got '{name}'.");
    }

    public static List<string> GetApiKeyHashes(DataRecord record)
    {
        var val = record.GetFieldValue(SystemPrincipalFields.ApiKeyHashes);
        if (val is List<string> list) return list;
        if (val is IEnumerable<string> enumerable) return new List<string>(enumerable);
        if (val is string s && !string.IsNullOrEmpty(s))
            return new List<string>(s.Split(',', StringSplitOptions.RemoveEmptyEntries));
        var newList = new List<string>();
        record.SetFieldValue(SystemPrincipalFields.ApiKeyHashes, newList);
        return newList;
    }

    public static void AddApiKey(DataRecord record, string apiKey, int iterations = 100_000)
    {
        Guard(record);
        var encoded = EncodeApiKey(record, apiKey);
        var (hash, salt, iter) = PasswordHasher.CreateHash(encoded, iterations);
        GetApiKeyHashes(record).Add($"{hash}:{salt}:{iter}");
    }

    public static bool HasApiKey(DataRecord record, string apiKey)
    {
        Guard(record);
        var hashes = GetApiKeyHashes(record);
        if (string.IsNullOrWhiteSpace(apiKey) || hashes.Count == 0)
            return false;

        var encoded = EncodeApiKey(record, apiKey);
        foreach (var entry in hashes)
        {
            if (TryParseHashEntry(entry, out var hash, out var salt, out var iterations)
                && PasswordHasher.Verify(encoded, hash, salt, iterations))
                return true;
        }
        return false;
    }

    public static async ValueTask<DataRecord?> FindByApiKeyAsync(string apiKey, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            return null;

        var principals = await DataStoreProvider.Current.QueryAsync("SystemPrincipal", null, cancellationToken).ConfigureAwait(false);
        foreach (var record in principals)
        {
            var isActive = record.GetFieldValue(UserFields.IsActive);
            if (isActive is not true) continue;
            if (HasApiKey(record, apiKey))
                return record;
        }
        return null;
    }

    public static string GenerateRawApiKey()
    {
        Span<byte> bytes = stackalloc byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static PrincipalRole GetRole(DataRecord record)
    {
        var val = record.GetFieldValue(SystemPrincipalFields.Role);
        if (val is PrincipalRole r) return r;
        if (val is string s && Enum.TryParse<PrincipalRole>(s, true, out var parsed)) return parsed;
        return PrincipalRole.FullAccess;
    }

    public static string GetOwnerTenantId(DataRecord record)
        => record.GetFieldValue(SystemPrincipalFields.OwnerTenantId)?.ToString() ?? string.Empty;

    public static string GetOwnerInstanceId(DataRecord record)
        => record.GetFieldValue(SystemPrincipalFields.OwnerInstanceId)?.ToString() ?? string.Empty;

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

    private static string EncodeApiKey(DataRecord record, string apiKey)
    {
        var principalName = GetPrincipalName(record);
        var payload = $"{principalName}:{apiKey}";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
    }

    private static string GetPrincipalName(DataRecord record)
    {
        var userName = record.GetFieldValue(UserFields.UserName)?.ToString();
        if (!string.IsNullOrWhiteSpace(userName))
            return userName;
        var displayName = record.GetFieldValue(UserFields.DisplayName)?.ToString();
        if (!string.IsNullOrWhiteSpace(displayName))
            return displayName;
        return record.Key.ToString();
    }
}

/// <summary>
/// Static helpers for DashboardDefinition DataRecords.
/// </summary>
public static class DashboardDefinitionHelper
{
    public static List<DashboardTile> DeserializeTiles(string json)
        => BmwManualJson.DeserializeDashboardTiles(json);

    public static string GetName(DataRecord record)
        => record.GetFieldValue(DashboardDefinitionFields.Name)?.ToString() ?? string.Empty;

    public static string GetTilesJson(DataRecord record)
        => record.GetFieldValue(DashboardDefinitionFields.TilesJson)?.ToString() ?? "[]";

    public static List<DashboardTile> GetTiles(DataRecord record)
        => DeserializeTiles(GetTilesJson(record));
}
