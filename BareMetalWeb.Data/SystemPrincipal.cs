using System;
using System.Collections.Generic;
using System.Text;

namespace BareMetalWeb.Data;

[DataEntity("System Principals", ShowOnNav = false, NavGroup = "Admin", NavOrder = 20, Permissions = "admin")]
public sealed class SystemPrincipal : User
{
    private const int Ord_ApiKeyHashes = User.TotalFieldCount + 0;
    private const int Ord_OwnerInstanceId = User.TotalFieldCount + 1;
    private const int Ord_OwnerTenantId = User.TotalFieldCount + 2;
    private const int Ord_Role = User.TotalFieldCount + 3;
    internal new const int TotalFieldCount = User.TotalFieldCount + 4;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("ApiKeyHashes", Ord_ApiKeyHashes),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("DisplayName", User.BaseFieldCount + 1),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Email", User.BaseFieldCount + 2),
        new FieldSlot("FailedLoginCount", User.BaseFieldCount + 9),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("IsActive", User.BaseFieldCount + 7),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("LastLoginUtc", User.BaseFieldCount + 8),
        new FieldSlot("LockoutUntilUtc", User.BaseFieldCount + 10),
        new FieldSlot("MfaBackupCodeHashes", User.BaseFieldCount + 19),
        new FieldSlot("MfaBackupCodesGeneratedUtc", User.BaseFieldCount + 20),
        new FieldSlot("MfaEnabled", User.BaseFieldCount + 11),
        new FieldSlot("MfaLastVerifiedStep", User.BaseFieldCount + 13),
        new FieldSlot("MfaPendingExpiresUtc", User.BaseFieldCount + 16),
        new FieldSlot("MfaPendingFailedAttempts", User.BaseFieldCount + 17),
        new FieldSlot("MfaPendingSecret", User.BaseFieldCount + 15),
        new FieldSlot("MfaPendingSecretEncrypted", User.BaseFieldCount + 18),
        new FieldSlot("MfaSecret", User.BaseFieldCount + 12),
        new FieldSlot("MfaSecretEncrypted", User.BaseFieldCount + 14),
        new FieldSlot("OwnerInstanceId", Ord_OwnerInstanceId),
        new FieldSlot("OwnerTenantId", Ord_OwnerTenantId),
        new FieldSlot("PasswordHash", User.BaseFieldCount + 3),
        new FieldSlot("PasswordIterations", User.BaseFieldCount + 5),
        new FieldSlot("PasswordSalt", User.BaseFieldCount + 4),
        new FieldSlot("Permissions", User.BaseFieldCount + 6),
        new FieldSlot("Role", Ord_Role),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("UserName", User.BaseFieldCount + 0),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public SystemPrincipal() : base(TotalFieldCount) { }
    public SystemPrincipal(string createdBy) : base(TotalFieldCount, createdBy) { }

    [DataField(Label = "API Keys", Order = 10, Required = false, List = false, View = false, Edit = true, Create = true, Placeholder = "one key per line")]
    public List<string> ApiKeyHashes
    {
        get => (List<string>?)_values[Ord_ApiKeyHashes] ?? new();
        set => _values[Ord_ApiKeyHashes] = value;
    }

    [DataField(Label = "Principal Role", Order = 11, Required = false, List = true, View = true, Edit = true, Create = true)]
    public PrincipalRole Role
    {
        get => _values[Ord_Role] is PrincipalRole r ? r : PrincipalRole.FullAccess;
        set => _values[Ord_Role] = value;
    }

    [DataField(Label = "Owner Tenant ID", Order = 12, Required = false, List = true, View = true, Edit = true, Create = true, Placeholder = "tenant scope (TenantCallback only)")]
    public string OwnerTenantId
    {
        get => (string?)_values[Ord_OwnerTenantId] ?? string.Empty;
        set => _values[Ord_OwnerTenantId] = value;
    }

    [DataField(Label = "Owner Instance ID", Order = 13, Required = false, List = true, View = true, Edit = true, Create = true, Placeholder = "instance scope (TenantCallback only)")]
    public string OwnerInstanceId
    {
        get => (string?)_values[Ord_OwnerInstanceId] ?? string.Empty;
        set => _values[Ord_OwnerInstanceId] = value;
    }

    public static async ValueTask<SystemPrincipal?> FindByApiKeyAsync(string apiKey, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            return null;

        var principals = await DataStoreProvider.Current.QueryAsync<SystemPrincipal>(null, cancellationToken).ConfigureAwait(false);
        foreach (var principal in principals)
        {
            if (principal == null || !principal.IsActive)
                continue;
            if (principal.HasApiKey(apiKey))
                return principal;
        }

        return null;
    }

    public void AddApiKey(string apiKey, int iterations = 100_000)
    {
        var encoded = EncodeApiKey(apiKey);
        var (hash, salt, iter) = PasswordHasher.CreateHash(encoded, iterations);
        ApiKeyHashes.Add($"{hash}:{salt}:{iter}");
    }

    public bool HasApiKey(string apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey) || ApiKeyHashes.Count == 0)
            return false;

        var encoded = EncodeApiKey(apiKey);
        foreach (var entry in ApiKeyHashes)
        {
            if (TryParseHashEntry(entry, out var hash, out var salt, out var iterations)
                && PasswordHasher.Verify(encoded, hash, salt, iterations))
            {
                return true;
            }
        }

        return false;
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

    public static string GenerateRawApiKey()
    {
        Span<byte> bytes = stackalloc byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private string EncodeApiKey(string apiKey)
    {
        var principalName = GetPrincipalName();
        var payload = $"{principalName}:{apiKey}";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
    }

    private string GetPrincipalName()
    {
        if (!string.IsNullOrWhiteSpace(UserName))
            return UserName;
        if (!string.IsNullOrWhiteSpace(DisplayName))
            return DisplayName;
        return Key.ToString();
    }
}
