using System.Collections.Concurrent;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Provides cached access to application settings stored in the <see cref="AppSetting"/>
/// object store. Settings are read on first access and cached in memory.
/// Use <see cref="InvalidateCache()"/> or <see cref="InvalidateCache(string)"/> after
/// saving a setting to ensure subsequent reads return the updated value.
///
/// When multitenancy is enabled each tenant has its own isolated cache keyed by
/// <see cref="TenantContext.TenantId"/>.  Settings for the active tenant are
/// resolved automatically via <see cref="DataStoreProvider.CurrentTenant"/>.
/// </summary>
public static class SettingsService
{
    // Per-tenant caches: tenantId → (settingId → value)
    private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, string>> _tenantCaches =
        new(StringComparer.OrdinalIgnoreCase);

    // Convenience accessor for the cache belonging to the currently active tenant (or "_system").
    private static ConcurrentDictionary<string, string> CurrentCache =>
        _tenantCaches.GetOrAdd(
            DataStoreProvider.CurrentTenant?.TenantId ?? "_system",
            _ => new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase));

    /// <summary>
    /// Gets the value of a setting by its ID.
    /// Returns <paramref name="defaultValue"/> if the setting does not exist in the store.
    /// Results are cached in memory until the cache is invalidated.
    /// </summary>
    public static string GetValue(string settingId, string defaultValue = "")
    {
        var cache = CurrentCache;
        if (cache.TryGetValue(settingId, out var cached))
            return cached;

        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = nameof(AppSetting.SettingId), Operator = QueryOperator.Equals, Value = settingId }
            },
            Top = 1
        };

        var settings = DataStoreProvider.Current.Query<AppSetting>(query);
        var setting = settings.FirstOrDefault(s => string.Equals(s.SettingId, settingId, StringComparison.OrdinalIgnoreCase));
        if (setting != null)
        {
            cache[settingId] = setting.Value;
            return setting.Value;
        }

        return defaultValue;
    }

    /// <summary>
    /// Optional callback invoked whenever a single setting is removed from the cache.
    /// Register this in the host layer to propagate value changes to in-memory server state.
    /// The argument is the setting ID that was invalidated.
    /// </summary>
    public static Action<string>? OnSettingInvalidated { get; set; }

    /// <summary>Clears all cached settings for the currently active tenant so the next read hits the store.</summary>
    public static void InvalidateCache()
    {
        var tenantId = DataStoreProvider.CurrentTenant?.TenantId ?? "_system";
        _tenantCaches.TryRemove(tenantId, out _);
    }

    /// <summary>Removes a single setting from the active tenant's cache and notifies any registered listener.</summary>
    public static void InvalidateCache(string settingId)
    {
        CurrentCache.TryRemove(settingId, out _);
        OnSettingInvalidated?.Invoke(settingId);
    }

    /// <summary>
    /// Seeds the store with the supplied default settings, skipping any that already exist.
    /// Invalidates the in-memory cache afterwards.
    /// </summary>
    public static async ValueTask EnsureDefaultsAsync(
        IDataObjectStore store,
        IEnumerable<(string SettingId, string Value, string Description)> defaults,
        string createdBy,
        CancellationToken cancellationToken = default)
    {
        var existing = (await store.QueryAsync<AppSetting>(null, cancellationToken).ConfigureAwait(false))
            .GroupBy(s => s.SettingId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        foreach (var (settingId, value, description) in defaults)
        {
            if (existing.TryGetValue(settingId, out var existingSetting))
            {
                // Promote an existing empty value when the configured default is non-empty
                if (!string.IsNullOrEmpty(value) && string.IsNullOrEmpty(existingSetting.Value))
                {
                    existingSetting.Value = value;
                    existingSetting.UpdatedBy = createdBy;
                    await store.SaveAsync(existingSetting, cancellationToken).ConfigureAwait(false);
                }
                continue;
            }

            var setting = new AppSetting
            {
                SettingId = settingId,
                Value = value,
                Description = description,
                CreatedBy = createdBy,
                UpdatedBy = createdBy
            };
            await store.SaveAsync(setting, cancellationToken).ConfigureAwait(false);
        }

        InvalidateCache();
    }
}
