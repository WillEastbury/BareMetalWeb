using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[Collection("DataStoreProvider")]
public class SettingsServiceTests : IDisposable
{
    private readonly IDataObjectStore _previousStore;
    private readonly DataObjectStore _testStore;
    private readonly InMemoryProvider _provider;

    public SettingsServiceTests()
    {
        _previousStore = DataStoreProvider.Current;
        _provider = new InMemoryProvider();
        _testStore = new DataObjectStore();
        _testStore.RegisterProvider(_provider);
        DataStoreProvider.Current = _testStore;
        SettingsService.InvalidateCache();
        SettingsService.OnSettingInvalidated = null;
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _previousStore;
        SettingsService.InvalidateCache();
        SettingsService.OnSettingInvalidated = null;
    }

    private sealed class InMemoryProvider : IDataProvider
    {
        private readonly Dictionary<(Type, uint), BaseDataObject> _store = new();
        private uint _nextKey = 1;

        public string Name => "InMemory";
        public string IndexRootPath => string.Empty;
        public string IndexFolderName => string.Empty;
        public string IndexLogExtension => string.Empty;
        public string IndexSnapshotExtension => string.Empty;
        public string IndexTempExtension => string.Empty;

        public bool CanHandle(Type type) => true;

        public void Save<T>(T obj) where T : BaseDataObject
        {
            if (obj.Key == 0)
                obj.Key = _nextKey++;
            _store[(typeof(T), obj.Key)] = obj;
        }

        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Save(obj);
            return ValueTask.CompletedTask;
        }

        public T? Load<T>(uint key) where T : BaseDataObject =>
            _store.TryGetValue((typeof(T), key), out var obj) ? obj as T : null;

        public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject =>
            ValueTask.FromResult(Load<T>(key));

        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject =>
            _store.Values.OfType<T>();

        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject =>
            ValueTask.FromResult(Query<T>(query));

        public int Count<T>(QueryDefinition? query = null) where T : BaseDataObject =>
            Query<T>(query).Count();

        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject =>
            ValueTask.FromResult(Count<T>(query));

        public void Delete<T>(uint key) where T : BaseDataObject =>
            _store.Remove((typeof(T), key));

        public ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Delete<T>(key);
            return ValueTask.CompletedTask;
        }

        public IDisposable AcquireIndexLock(string entityName, string fieldName) => new DummyDisposable();
        public bool IndexFileExists(string entityName, string fieldName, IndexFileKind kind) => false;
        public Stream OpenIndexRead(string entityName, string fieldName, IndexFileKind kind) => throw new NotImplementedException();
        public Stream OpenIndexAppend(string entityName, string fieldName, IndexFileKind kind) => throw new NotImplementedException();
        public Stream OpenIndexWriteTemp(string entityName, string fieldName, IndexFileKind kind, out string tempToken) => throw new NotImplementedException();
        public void CommitIndexTemp(string entityName, string fieldName, IndexFileKind kind, string tempToken) => throw new NotImplementedException();
        public bool PagedFileExists(string entityName, string fileName) => false;
        public IPagedFile OpenPagedFile(string entityName, string fileName, int pageSize, FileAccess access) => throw new NotImplementedException();
        public ValueTask DeletePagedFileAsync(string entityName, string fileName, CancellationToken cancellationToken = default) => throw new NotImplementedException();

        private readonly Dictionary<string, uint> _seqIds = new();
        public uint NextSequentialKey(string entityName)
        {
            _seqIds.TryGetValue(entityName, out uint current);
            current++;
            _seqIds[entityName] = current;
            return current;
        }
        public void SeedSequentialKey(string entityName, uint floor)
        {
            if (!_seqIds.TryGetValue(entityName, out uint current) || current < floor)
                _seqIds[entityName] = floor;
        }

        private sealed class DummyDisposable : IDisposable { public void Dispose() { } }
    }

    // ── AppSetting entity ───────────────────────────────────────────────────

    [Fact]
    public void AppSetting_EntityAttribute_RequiresAdminPermission()
    {
        var attr = typeof(AppSetting)
            .GetCustomAttributes(typeof(DataEntityAttribute), inherit: false)
            .Cast<DataEntityAttribute>()
            .Single();

        Assert.Equal("admin", attr.Permissions);
    }

    [Fact]
    public void AppSetting_DefaultsAreCorrect()
    {
        var setting = new AppSetting();
        Assert.Equal(0u, setting.Key);
        Assert.Equal(string.Empty, setting.SettingId);
        Assert.Equal(string.Empty, setting.Value);
        Assert.Equal(string.Empty, setting.Description);
    }

    [Fact]
    public void AppSetting_CanBeCreatedWithValues()
    {
        var setting = new AppSetting
        {
            SettingId = WellKnownSettings.AppName,
            Value = "MyApp",
            Description = "Application display name"
        };

        Assert.Equal(WellKnownSettings.AppName, setting.SettingId);
        Assert.Equal("MyApp", setting.Value);
        Assert.Equal("Application display name", setting.Description);
    }

    // ── WellKnownSettings constants ─────────────────────────────────────────

    [Fact]
    public void WellKnownSettings_Constants_HaveExpectedValues()
    {
        Assert.Equal("app.name", WellKnownSettings.AppName);
        Assert.Equal("app.company", WellKnownSettings.AppCompany);
        Assert.Equal("app.copyright", WellKnownSettings.AppCopyright);
        Assert.Equal("app.privacyPolicyUrl", WellKnownSettings.AppPrivacyPolicyUrl);
    }

    [Fact]
    public void WellKnownSettings_KestrelConstants_HaveExpectedValues()
    {
        Assert.Equal("kestrel.http2.enabled", WellKnownSettings.KestrelHttp2Enabled);
        Assert.Equal("kestrel.http3.enabled", WellKnownSettings.KestrelHttp3Enabled);
        Assert.Equal("kestrel.http2.maxStreamsPerConnection", WellKnownSettings.KestrelMaxStreamsPerConnection);
        Assert.Equal("kestrel.http2.initialConnectionWindowSize", WellKnownSettings.KestrelInitialConnectionWindowSize);
        Assert.Equal("kestrel.http2.initialStreamWindowSize", WellKnownSettings.KestrelInitialStreamWindowSize);
        Assert.Equal("threadpool.minWorkerThreads", WellKnownSettings.ThreadPoolMinWorkerThreads);
        Assert.Equal("threadpool.minIOThreads", WellKnownSettings.ThreadPoolMinIOThreads);
        Assert.Equal("gc.serverMode", WellKnownSettings.GCServerMode);
    }

    [Fact]
    public async Task EnsureDefaultsAsync_SeedsKestrelSettings()
    {
        var defaults = new[]
        {
            (WellKnownSettings.KestrelHttp2Enabled, "True", "Enable HTTP/2"),
            (WellKnownSettings.KestrelHttp3Enabled, "False", "Enable HTTP/3"),
            (WellKnownSettings.KestrelMaxStreamsPerConnection, "100", "Max streams"),
            (WellKnownSettings.ThreadPoolMinWorkerThreads, "0", "Min worker threads"),
            (WellKnownSettings.GCServerMode, "True", "Server GC"),
        };

        await SettingsService.EnsureDefaultsAsync(_testStore, defaults, "admin");

        var all = _testStore.Query<AppSetting>().ToList();
        Assert.Equal(5, all.Count);
        Assert.Contains(all, s => s.SettingId == WellKnownSettings.KestrelHttp2Enabled && s.Value == "True");
        Assert.Contains(all, s => s.SettingId == WellKnownSettings.KestrelMaxStreamsPerConnection && s.Value == "100");
        Assert.Contains(all, s => s.SettingId == WellKnownSettings.GCServerMode && s.Value == "True");
    }

    // ── SettingsService.GetValue ─────────────────────────────────────────────

    [Fact]
    public void GetValue_ReturnsDefaultValue_WhenSettingDoesNotExist()
    {
        var result = SettingsService.GetValue("nonexistent.setting", "fallback");
        Assert.Equal("fallback", result);
    }

    [Fact]
    public void GetValue_ReturnsEmptyString_WhenNoDefaultAndSettingMissing()
    {
        var result = SettingsService.GetValue("nonexistent.setting");
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void GetValue_ReturnsStoredValue_WhenSettingExists()
    {
        // Arrange
        var setting = new AppSetting
        {
            SettingId = "test.setting",
            Value = "stored-value"
        };
        _testStore.Save(setting);

        // Act
        var result = SettingsService.GetValue("test.setting", "default");

        // Assert
        Assert.Equal("stored-value", result);
    }

    [Fact]
    public void GetValue_IsCaseInsensitive()
    {
        // Arrange
        var setting = new AppSetting { SettingId = "Test.Setting", Value = "hello" };
        _testStore.Save(setting);

        // Act — query with different casing
        var result = SettingsService.GetValue("test.setting");

        Assert.Equal("hello", result);
    }

    [Fact]
    public void GetValue_CachesResult_OnSubsequentCalls()
    {
        // Arrange
        var setting = new AppSetting { SettingId = "cached.setting", Value = "original" };
        _testStore.Save(setting);

        // Prime the cache
        var first = SettingsService.GetValue("cached.setting");

        // Mutate the stored value directly (bypass SettingsService so cache is stale)
        setting.Value = "mutated";
        _testStore.Save(setting);

        // Second call should still return the cached value
        var second = SettingsService.GetValue("cached.setting");

        Assert.Equal("original", first);
        Assert.Equal("original", second);
    }

    // ── SettingsService.InvalidateCache ────────────────────────────────────

    [Fact]
    public void InvalidateCache_Single_FiresOnSettingInvalidatedCallback()
    {
        // Arrange
        var fired = new List<string>();
        SettingsService.OnSettingInvalidated = id => fired.Add(id);

        // Act
        SettingsService.InvalidateCache("some.setting");

        // Assert
        Assert.Single(fired);
        Assert.Equal("some.setting", fired[0]);
    }

    [Fact]
    public void InvalidateCache_Full_DoesNotFireOnSettingInvalidatedCallback()
    {
        // Full-cache invalidation does not know which keys changed, so the callback
        // must NOT be invoked (callers must refresh themselves if needed).
        var fired = new List<string>();
        SettingsService.OnSettingInvalidated = id => fired.Add(id);

        SettingsService.InvalidateCache();

        Assert.Empty(fired);
    }

    [Fact]
    public void InvalidateCache_Single_RefreshesValueForThatKey()
    {
        // Arrange
        var setting = new AppSetting { SettingId = "refresh.setting", Value = "v1" };
        _testStore.Save(setting);

        _ = SettingsService.GetValue("refresh.setting");   // prime cache

        setting.Value = "v2";
        _testStore.Save(setting);

        // Invalidate only this key
        SettingsService.InvalidateCache("refresh.setting");

        // Act
        var result = SettingsService.GetValue("refresh.setting");

        Assert.Equal("v2", result);
    }

    [Fact]
    public void InvalidateCache_Full_RefreshesAllValues()
    {
        // Arrange
        var s1 = new AppSetting { SettingId = "key1", Value = "a" };
        var s2 = new AppSetting { SettingId = "key2", Value = "b" };
        _testStore.Save(s1);
        _testStore.Save(s2);

        _ = SettingsService.GetValue("key1");
        _ = SettingsService.GetValue("key2");

        s1.Value = "aa";
        s2.Value = "bb";
        _testStore.Save(s1);
        _testStore.Save(s2);

        SettingsService.InvalidateCache();

        Assert.Equal("aa", SettingsService.GetValue("key1"));
        Assert.Equal("bb", SettingsService.GetValue("key2"));
    }

    // ── SettingsService.EnsureDefaultsAsync ────────────────────────────────

    [Fact]
    public async Task EnsureDefaultsAsync_SeedsNewSettings()
    {
        // Arrange
        var defaults = new[]
        {
            (WellKnownSettings.AppName,      "TestApp",  "App name"),
            (WellKnownSettings.AppCompany,   "Acme Ltd", "Company"),
            (WellKnownSettings.AppCopyright, "2025",     "Copyright"),
        };

        // Act
        await SettingsService.EnsureDefaultsAsync(_testStore, defaults, "admin");

        // Assert
        var all = _testStore.Query<AppSetting>().ToList();
        Assert.Equal(3, all.Count);
        Assert.Contains(all, s => s.SettingId == WellKnownSettings.AppName && s.Value == "TestApp");
        Assert.Contains(all, s => s.SettingId == WellKnownSettings.AppCompany && s.Value == "Acme Ltd");
        Assert.Contains(all, s => s.SettingId == WellKnownSettings.AppCopyright && s.Value == "2025");
    }

    [Fact]
    public async Task EnsureDefaultsAsync_SkipsExistingSettings()
    {
        // Arrange — pre-populate one setting
        var existing = new AppSetting { SettingId = WellKnownSettings.AppName, Value = "ExistingApp" };
        _testStore.Save(existing);

        var defaults = new[]
        {
            (WellKnownSettings.AppName,    "NewApp",   "App name"),
            (WellKnownSettings.AppCompany, "Acme Ltd", "Company"),
        };

        // Act
        await SettingsService.EnsureDefaultsAsync(_testStore, defaults, "admin");

        // Assert — the existing setting must not be overwritten
        var all = _testStore.Query<AppSetting>().ToList();
        var appName = all.First(s => s.SettingId == WellKnownSettings.AppName);
        Assert.Equal("ExistingApp", appName.Value);

        // The missing one is added
        Assert.Contains(all, s => s.SettingId == WellKnownSettings.AppCompany && s.Value == "Acme Ltd");
    }

    [Fact]
    public async Task EnsureDefaultsAsync_SetsCacheInvalidated_SoNextReadHitsStore()
    {
        // Arrange — prime a stale cache entry
        _ = SettingsService.GetValue(WellKnownSettings.AppName);  // -> empty string, cached

        var defaults = new[]
        {
            (WellKnownSettings.AppName, "FreshApp", "App name"),
        };

        // Act
        await SettingsService.EnsureDefaultsAsync(_testStore, defaults, "admin");

        // After EnsureDefaultsAsync the cache should have been cleared
        var result = SettingsService.GetValue(WellKnownSettings.AppName);
        Assert.Equal("FreshApp", result);
    }

    [Fact]
    public async Task EnsureDefaultsAsync_SetsCreatedBy_OnNewRecords()
    {
        var defaults = new[]
        {
            (WellKnownSettings.AppName, "MyApp", "App name"),
        };

        await SettingsService.EnsureDefaultsAsync(_testStore, defaults, "setup-user");

        var setting = _testStore.Query<AppSetting>().First();
        Assert.Equal("setup-user", setting.CreatedBy);
        Assert.Equal("setup-user", setting.UpdatedBy);
    }

    [Fact]
    public async Task EnsureDefaultsAsync_PromotesEmptyExistingValue_WhenDefaultIsNonEmpty()
    {
        // Arrange — setting already exists in the store with an empty value (e.g. seeded on first run
        // before AllowWipeData was configured), then appsettings.json is updated with a real token.
        var existing = new AppSetting
        {
            SettingId = WellKnownSettings.AllowWipeData,
            Value = "",
            Description = "Wipe token"
        };
        _testStore.Save(existing);

        var defaults = new[]
        {
            (WellKnownSettings.AllowWipeData, "my-secret-token", "Wipe token"),
        };

        // Act
        await SettingsService.EnsureDefaultsAsync(_testStore, defaults, "system");

        // Assert — the empty value must have been promoted to the configured token
        var stored = _testStore.Query<AppSetting>()
            .First(s => s.SettingId == WellKnownSettings.AllowWipeData);
        Assert.Equal("my-secret-token", stored.Value);
        Assert.Equal("system", stored.UpdatedBy);
    }

    [Fact]
    public async Task EnsureDefaultsAsync_DoesNotOverwriteNonEmptyExistingValue()
    {
        // Arrange — a user has intentionally set a custom token via the admin UI
        var existing = new AppSetting
        {
            SettingId = WellKnownSettings.AllowWipeData,
            Value = "admin-chosen-token",
            Description = "Wipe token"
        };
        _testStore.Save(existing);

        var defaults = new[]
        {
            (WellKnownSettings.AllowWipeData, "config-token", "Wipe token"),
        };

        // Act
        await SettingsService.EnsureDefaultsAsync(_testStore, defaults, "system");

        // Assert — the admin-chosen value must not be overwritten
        var stored = _testStore.Query<AppSetting>()
            .First(s => s.SettingId == WellKnownSettings.AllowWipeData);
        Assert.Equal("admin-chosen-token", stored.Value);
    }

    // ── DataScaffold.SaveAsync cache invalidation ───────────────────────────

    [Fact]
    public async Task DataScaffold_SaveAsync_InvalidatesSettingsCacheForAppSetting()
    {
        // Arrange — seed a setting and prime the cache
        var setting = new AppSetting { SettingId = WellKnownSettings.AllowWipeData, Value = "old-token" };
        _testStore.Save(setting);
        var cached = SettingsService.GetValue(WellKnownSettings.AllowWipeData);
        Assert.Equal("old-token", cached); // confirm cache was primed

        // Update the stored value directly so the in-memory store has the new value
        setting.Value = "new-token";

        // Build a minimal metadata whose SaveAsync delegates to the test store
        var handlers = new DataEntityHandlers(
            Create: () => new AppSetting(),
            LoadAsync: (key, ct) => ValueTask.FromResult((BaseDataObject?)_testStore.Query<AppSetting>().FirstOrDefault(s => s.Key == key)),
            SaveAsync: (obj, ct) => { _testStore.Save((AppSetting)obj); return ValueTask.CompletedTask; },
            DeleteAsync: (key, ct) => { _testStore.Delete<AppSetting>(key); return ValueTask.CompletedTask; },
            QueryAsync: (q, ct) => ValueTask.FromResult(_testStore.Query<AppSetting>(q).Cast<BaseDataObject>()),
            CountAsync: (q, ct) => ValueTask.FromResult(_testStore.Query<AppSetting>(q).Count())
        );
        var metadata = new DataEntityMetadata(
            Type: typeof(AppSetting),
            Name: "Settings",
            Slug: "settings",
            Permissions: "admin",
            ShowOnNav: false,
            NavGroup: null,
            NavOrder: 0,
            IdGeneration: AutoIdStrategy.Sequential,
            ViewType: ViewType.Table,
            ParentField: null,
            Fields: Array.Empty<DataFieldMetadata>(),
            Handlers: handlers,
            Commands: Array.Empty<RemoteCommandMetadata>()
        );

        // Act — save via DataScaffold; this should invalidate the cache
        await DataScaffold.SaveAsync(metadata, setting);

        // Assert — cache must have been cleared; next GetValue reads the updated store value
        var result = SettingsService.GetValue(WellKnownSettings.AllowWipeData);
        Assert.Equal("new-token", result);
    }
}
