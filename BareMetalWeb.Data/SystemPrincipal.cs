using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace BareMetalWeb.Data;

[DataEntity("System Principals", ShowOnNav = false, NavGroup = "", NavOrder = 0)]
public sealed class SystemPrincipal : User
{
    [DataField(Label = "API Keys", Order = 10, Required = false, List = false, View = false, Edit = true, Create = true, Placeholder = "one key per line")]
    public List<string> ApiKeyHashes { get; set; } = new();

    public static SystemPrincipal? FindByApiKey(string apiKey)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            return null;

        foreach (var principal in DataStoreProvider.Current.Query<SystemPrincipal>(null))
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
        => Guid.NewGuid().ToString("N");

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
        return Id ?? string.Empty;
    }
}
