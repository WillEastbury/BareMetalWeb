using System.Collections.Concurrent;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Provides cached access to application settings stored in the <see cref="AppSetting"/>
/// object store. Settings are read on first access and cached in memory.
/// Use <see cref="InvalidateCache()"/> or <see cref="InvalidateCache(string)"/> after
/// saving a setting to ensure subsequent reads return the updated value.
/// </summary>
public static class SettingsService
{
    private static readonly ConcurrentDictionary<string, string> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Gets the value of a setting by its ID.
    /// Returns <paramref name="defaultValue"/> if the setting does not exist in the store.
    /// Results are cached in memory until the cache is invalidated.
    /// </summary>
    public static string GetValue(string settingId, string defaultValue = "")
    {
        if (_cache.TryGetValue(settingId, out var cached))
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
            _cache[settingId] = setting.Value;
            return setting.Value;
        }

        return defaultValue;
    }

    /// <summary>Clears all cached settings so the next read hits the store.</summary>
    public static void InvalidateCache() => _cache.Clear();

    /// <summary>Removes a single setting from the cache.</summary>
    public static void InvalidateCache(string settingId) =>
        _cache.TryRemove(settingId, out _);

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
            .ToDictionary(s => s.SettingId, StringComparer.OrdinalIgnoreCase);

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
