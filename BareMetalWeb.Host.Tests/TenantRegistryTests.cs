using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Tests for <see cref="TenantRegistry"/> — host-to-tenant resolution, fallback
/// behaviour, and per-request <see cref="DataStoreProvider.CurrentTenant"/> scoping.
/// </summary>
public sealed class TenantRegistryTests : IDisposable
{
    private readonly string _tmpRoot;
    private readonly IDataObjectStore _systemStore;
    private readonly IDataProvider _systemProvider;
    private readonly TenantContext _systemTenant;
    private readonly IDataObjectStore _originalSystemStore;
    private readonly IDataProvider? _originalPrimaryProvider;

    public TenantRegistryTests()
    {
        _tmpRoot = Path.Combine(Path.GetTempPath(), "TenantRegistryTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmpRoot);

        _systemStore    = new DataObjectStore();
        _systemProvider = new NoOpProvider();
        _systemTenant   = new TenantContext("_system", _tmpRoot, _tmpRoot, _systemStore, _systemProvider);

        // Save & set static state
        _originalSystemStore     = DataStoreProvider.SystemStore;
        _originalPrimaryProvider = DataStoreProvider.PrimaryProvider;
        DataStoreProvider.SystemStore    = _systemStore;
        DataStoreProvider.PrimaryProvider = _systemProvider;
    }

    public void Dispose()
    {
        DataStoreProvider.SystemStore    = _originalSystemStore;
        DataStoreProvider.PrimaryProvider = _originalPrimaryProvider;
        try { Directory.Delete(_tmpRoot, recursive: true); } catch { /* best-effort */ }
    }

    // ── MultitenancyOptions ──────────────────────────────────────────────────

    [Fact]
    public void MultitenancyOptions_Defaults_AreDisabled()
    {
        var opts = new MultitenancyOptions();
        Assert.False(opts.Enabled);
        Assert.Equal("_system", opts.DefaultTenantId);
        Assert.Empty(opts.Tenants);
    }

    // ── TenantContext ────────────────────────────────────────────────────────

    [Fact]
    public void TenantContext_StoresAllProperties()
    {
        var store    = new DataObjectStore();
        var provider = new NoOpProvider();
        var ctx = new TenantContext("tenant1", "/data/t1", "/logs/t1", store, provider);

        Assert.Equal("tenant1", ctx.TenantId);
        Assert.Equal("/data/t1", ctx.DataRoot);
        Assert.Equal("/logs/t1", ctx.LogFolder);
        Assert.Same(store, ctx.Store);
        Assert.Same(provider, ctx.Provider);
    }

    // ── TenantRegistry.IsEnabled ─────────────────────────────────────────────

    [Fact]
    public void IsEnabled_WhenDisabled_ReturnsFalse()
    {
        var registry = BuildRegistry(enabled: false);
        Assert.False(registry.IsEnabled);
    }

    [Fact]
    public void IsEnabled_WhenEnabled_ReturnsTrue()
    {
        var registry = BuildRegistry(enabled: true);
        Assert.True(registry.IsEnabled);
    }

    // ── TenantRegistry.RegisterSystemTenant ──────────────────────────────────

    [Fact]
    public void RegisterSystemTenant_ExposedViaSystemTenantProperty()
    {
        var registry = BuildRegistry(enabled: false);
        registry.RegisterSystemTenant(_systemTenant);

        Assert.Same(_systemTenant, registry.SystemTenant);
    }

    // ── TenantRegistry.Initialize ────────────────────────────────────────────

    [Fact]
    public void Initialize_RegistersTenantsByHost()
    {
        var opts = new MultitenancyOptions
        {
            Enabled = true,
            Tenants = new List<TenantOptions>
            {
                new() { Host = "tenant1.example.com", TenantId = "t1", DataRoot = Path.Combine(_tmpRoot, "t1"), LogFolder = Path.Combine(_tmpRoot, "logs_t1") }
            }
        };
        var registry = new TenantRegistry(opts, _tmpRoot);
        registry.RegisterSystemTenant(_systemTenant);

        var t1Store    = new DataObjectStore();
        var t1Provider = new NoOpProvider();
        registry.Initialize(
            storeFactory: (id, root) =>
            {
                DataStoreProvider.PrimaryProvider = t1Provider;
                return (t1Store, t1Provider);
            },
            systemLogger: new NullLogger());

        Assert.Equal(2, registry.AllTenants.Count); // system + t1
    }

    [Fact]
    public void Initialize_SkipsEntryWithEmptyHost()
    {
        var opts = new MultitenancyOptions
        {
            Enabled = true,
            Tenants = new List<TenantOptions>
            {
                new() { Host = "", TenantId = "noop", DataRoot = Path.Combine(_tmpRoot, "noop"), LogFolder = Path.Combine(_tmpRoot, "logs_noop") }
            }
        };
        var registry = new TenantRegistry(opts, _tmpRoot);
        registry.RegisterSystemTenant(_systemTenant);

        registry.Initialize(storeFactory: (_, __) =>
        {
            var p = new NoOpProvider();
            return (new DataObjectStore(), p);
        }, systemLogger: new NullLogger());

        // Only the system tenant — the empty-host entry was skipped
        Assert.Single(registry.AllTenants);
    }

    // ── TenantRegistry.ResolveForRequest ─────────────────────────────────────

    [Fact]
    public void ResolveForRequest_WhenDisabled_ReturnsNull()
    {
        var registry = BuildRegistry(enabled: false);
        registry.RegisterSystemTenant(_systemTenant);

        var ctx = MakeContext("any.host.com");
        var scope = registry.ResolveForRequest(ctx.ToBmw());

        Assert.Null(scope);
        // Current should still be system store (no scope was set)
        Assert.Null(DataStoreProvider.CurrentTenant);
    }

    [Fact]
    public void ResolveForRequest_WhenEnabled_MatchesRegisteredHost()
    {
        var tenantRoot = Path.Combine(_tmpRoot, "t1");
        Directory.CreateDirectory(tenantRoot);

        var opts = new MultitenancyOptions
        {
            Enabled = true,
            Tenants = new List<TenantOptions>
            {
                new() { Host = "t1.example.com", TenantId = "t1", DataRoot = tenantRoot, LogFolder = tenantRoot }
            }
        };
        var registry = new TenantRegistry(opts, _tmpRoot);
        registry.RegisterSystemTenant(_systemTenant);

        registry.Initialize(
            storeFactory: (id, root) =>
            {
                var p = new NoOpProvider();
                return (new DataObjectStore(), p);
            },
            systemLogger: new NullLogger());

        var httpCtx = MakeContext("t1.example.com");
        using var scope = registry.ResolveForRequest(httpCtx.ToBmw());

        Assert.NotNull(scope);
        Assert.Equal("t1", DataStoreProvider.CurrentTenant?.TenantId);
        // The resolved store must be the tenant's isolated store — not the system store
        Assert.NotSame(_systemStore, DataStoreProvider.Current);
    }

    [Fact]
    public void ResolveForRequest_UnknownHost_FallsBackToSystemTenant()
    {
        var opts = new MultitenancyOptions { Enabled = true };
        var registry = new TenantRegistry(opts, _tmpRoot);
        registry.RegisterSystemTenant(_systemTenant);

        var httpCtx = MakeContext("unknown.host.com");
        using var scope = registry.ResolveForRequest(httpCtx.ToBmw());

        Assert.NotNull(scope);
        Assert.Equal("_system", DataStoreProvider.CurrentTenant?.TenantId);
    }

    [Fact]
    public void ResolveForRequest_Scope_Disposed_ClearsTenantContext()
    {
        var opts = new MultitenancyOptions { Enabled = true };
        var registry = new TenantRegistry(opts, _tmpRoot);
        registry.RegisterSystemTenant(_systemTenant);

        var httpCtx = MakeContext("unknown.host.com");
        var scope = registry.ResolveForRequest(httpCtx.ToBmw());

        Assert.NotNull(DataStoreProvider.CurrentTenant);
        scope!.Dispose();
        Assert.Null(DataStoreProvider.CurrentTenant);
    }

    [Fact]
    public void ResolveForRequest_HostMatchingIsCaseInsensitive()
    {
        var tenantRoot = Path.Combine(_tmpRoot, "ci");
        Directory.CreateDirectory(tenantRoot);
        var opts = new MultitenancyOptions
        {
            Enabled = true,
            Tenants = new List<TenantOptions>
            {
                new() { Host = "Tenant.EXAMPLE.COM", TenantId = "ci", DataRoot = tenantRoot, LogFolder = tenantRoot }
            }
        };
        var registry = new TenantRegistry(opts, _tmpRoot);
        registry.RegisterSystemTenant(_systemTenant);
        registry.Initialize(
            storeFactory: (_, __) => { var p = new NoOpProvider(); return (new DataObjectStore(), p); },
            systemLogger: new NullLogger());

        // Request with lower-case host
        using var scope = registry.ResolveForRequest(MakeContext("tenant.example.com").ToBmw());
        Assert.Equal("ci", DataStoreProvider.CurrentTenant?.TenantId);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private TenantRegistry BuildRegistry(bool enabled)
    {
        var opts = new MultitenancyOptions { Enabled = enabled };
        return new TenantRegistry(opts, _tmpRoot);
    }

    private static HttpContext MakeContext(string host)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Host = new HostString(host);
        return ctx;
    }

    private sealed class NullLogger : IBufferedLogger
    {
        public void LogInfo(string message) { }
        public void LogError(string message, Exception ex) { }
        public Task RunAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public void OnApplicationStopping(CancellationTokenSource cts, Task loggerTask) { }
    }

    private sealed class NoOpProvider : IDataProvider
    {
        public string Name => "NoOp";
        public string IndexRootPath => string.Empty;
        public string IndexFolderName => string.Empty;
        public string IndexLogExtension => string.Empty;
        public string IndexSnapshotExtension => string.Empty;
        public string IndexTempExtension => string.Empty;
        public bool CanHandle(Type type) => true;
        public void Save<T>(T obj) where T : BaseDataObject { }
        public ValueTask SaveAsync<T>(T obj, CancellationToken ct = default) where T : BaseDataObject => ValueTask.CompletedTask;
        public T? Load<T>(uint key) where T : BaseDataObject => null;
        public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken ct = default) where T : BaseDataObject => ValueTask.FromResult<T?>(null);
        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject => Array.Empty<T>();
        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken ct = default) where T : BaseDataObject => ValueTask.FromResult<IEnumerable<T>>(Array.Empty<T>());
        public int Count<T>(QueryDefinition? query = null) where T : BaseDataObject => 0;
        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken ct = default) where T : BaseDataObject => ValueTask.FromResult(0);
        public void Delete<T>(uint key) where T : BaseDataObject { }
        public ValueTask DeleteAsync<T>(uint key, CancellationToken ct = default) where T : BaseDataObject => ValueTask.CompletedTask;
        public IDisposable AcquireIndexLock(string e, string f) => new D();
        public bool IndexFileExists(string e, string f, IndexFileKind k) => false;
        public System.IO.Stream OpenIndexRead(string e, string f, IndexFileKind k) => throw new NotImplementedException();
        public System.IO.Stream OpenIndexAppend(string e, string f, IndexFileKind k) => throw new NotImplementedException();
        public System.IO.Stream OpenIndexWriteTemp(string e, string f, IndexFileKind k, out string t) => throw new NotImplementedException();
        public void CommitIndexTemp(string e, string f, IndexFileKind k, string t) => throw new NotImplementedException();
        public bool PagedFileExists(string e, string f) => false;
        public BareMetalWeb.Core.Interfaces.IPagedFile OpenPagedFile(string e, string f, int ps, System.IO.FileAccess a) => throw new NotImplementedException();
        public ValueTask DeletePagedFileAsync(string e, string f, CancellationToken ct = default) => throw new NotImplementedException();
        public void RenamePagedFile(string e, string o, string n) => throw new NotImplementedException();
        public uint NextSequentialKey(string e) => 0;
        public void SeedSequentialKey(string e, uint floor) { }
        private sealed class D : IDisposable { public void Dispose() { } }

        // ── Non-generic stubs ──────────────────────────────────────────
        public void Save(string e, BaseDataObject o) => throw new NotSupportedException();
        public ValueTask SaveAsync(string e, BaseDataObject o, CancellationToken ct = default) => throw new NotSupportedException();
        public BaseDataObject? Load(string e, uint k) => throw new NotSupportedException();
        public ValueTask<BaseDataObject?> LoadAsync(string e, uint k, CancellationToken ct = default) => throw new NotSupportedException();
        public IEnumerable<BaseDataObject> Query(string e, QueryDefinition? q = null) => throw new NotSupportedException();
        public ValueTask<IEnumerable<BaseDataObject>> QueryAsync(string e, QueryDefinition? q = null, CancellationToken ct = default) => throw new NotSupportedException();
        public int Count(string e, QueryDefinition? q = null) => throw new NotSupportedException();
        public ValueTask<int> CountAsync(string e, QueryDefinition? q = null, CancellationToken ct = default) => throw new NotSupportedException();
        public void Delete(string e, uint k) => throw new NotSupportedException();
        public ValueTask DeleteAsync(string e, uint k, CancellationToken ct = default) => throw new NotSupportedException();
    }
}
