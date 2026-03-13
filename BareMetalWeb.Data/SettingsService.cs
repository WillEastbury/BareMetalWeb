using System.Collections.Concurrent;
using BareMetalWeb.Core;
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
    private static bool TryGetSettingsMeta(out DataEntityMetadata meta)
        => DataScaffold.TryGetEntity("app-settings", out meta)
            || DataScaffold.TryGetEntity("settings", out meta);

    private static string GetFieldString(BaseDataObject obj, DataEntityMetadata meta, string fieldName)
        => meta.FindField(fieldName)?.GetValueFn(obj)?.ToString() ?? string.Empty;

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

        if (!TryGetSettingsMeta(out var meta))
            return defaultValue;

        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = "SettingId", Operator = QueryOperator.Equals, Value = settingId }
            },
            Top = 1
        };

        var settings = meta.Handlers.QueryAsync(query, CancellationToken.None).GetAwaiter().GetResult();
        BaseDataObject? setting = null;
        foreach (var s in settings)
        {
            if (s is BaseDataObject obj
                && string.Equals(GetFieldString(obj, meta, "SettingId"), settingId, StringComparison.OrdinalIgnoreCase))
            {
                setting = obj;
                break;
            }
        }
        if (setting != null)
        {
            var settingValue = GetFieldString(setting, meta, "Value");
            cache[settingId] = settingValue;
            return settingValue;
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
        if (!TryGetSettingsMeta(out var meta))
        {
            InvalidateCache();
            return;
        }

        var existing = new Dictionary<string, BaseDataObject>(StringComparer.OrdinalIgnoreCase);
        var allSettings = await meta.Handlers.QueryAsync(null, cancellationToken).ConfigureAwait(false);
        foreach (var s in allSettings)
        {
            if (s is not BaseDataObject settingObj)
                continue;

            var existingSettingId = GetFieldString(settingObj, meta, "SettingId");
            if (!string.IsNullOrWhiteSpace(existingSettingId) && !existing.ContainsKey(existingSettingId))
                existing[existingSettingId] = settingObj;
        }

        foreach (var (settingId, value, description) in defaults)
        {
            if (existing.TryGetValue(settingId, out var existingSetting))
            {
                // Promote an existing empty value when the configured default is non-empty
                if (!string.IsNullOrEmpty(value) && string.IsNullOrEmpty(GetFieldString(existingSetting, meta, "Value")))
                {
                    meta.FindField("Value")?.SetValueFn(existingSetting, value);
                    existingSetting.UpdatedBy = createdBy;
                    await meta.Handlers.SaveAsync(existingSetting, cancellationToken).ConfigureAwait(false);
                }
                continue;
            }

            var setting = meta.Handlers.Create();
            setting.CreatedBy = createdBy;
            setting.UpdatedBy = createdBy;
            meta.FindField("SettingId")?.SetValueFn(setting, settingId);
            meta.FindField("Value")?.SetValueFn(setting, value);
            meta.FindField("Description")?.SetValueFn(setting, description);
            await DataScaffold.ApplyAutoIdAsync(meta, setting, cancellationToken).ConfigureAwait(false);
            await meta.Handlers.SaveAsync(setting, cancellationToken).ConfigureAwait(false);
        }

        InvalidateCache();
    }
}
