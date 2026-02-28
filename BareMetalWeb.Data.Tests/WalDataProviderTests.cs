using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for <see cref="WalDataProvider"/>: CRUD operations, cross-instance persistence,
/// query/count, delete, sequential IDs, and the WAL recovery path.
/// </summary>
public sealed class WalDataProviderTests : IDisposable
{
    private readonly string _dir;

    public WalDataProviderTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "BmwWalProviderTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); }
        catch { /* best-effort */ }
    }

    // ── Helper: minimal AppSetting-like object ───────────────────────────────

    private static AppSetting MakeSetting(string settingId, string value = "v")
        => new() { SettingId = settingId, Value = value, Description = "desc" };

    // ── Save / Load ───────────────────────────────────────────────────────────

    [Fact]
    public void Save_ThenLoad_SameInstance_ReturnsObject()
    {
        // Arrange
        using var provider = new WalDataProvider(_dir);
        var setting = MakeSetting("key1", "hello");

        // Act
        provider.Save(setting);
        var loaded = provider.Load<AppSetting>(setting.Id);

        // Assert
        Assert.NotNull(loaded);
        Assert.Equal("key1",  loaded.SettingId);
        Assert.Equal("hello", loaded.Value);
    }

    [Fact]
    public void Save_ThenLoad_FreshInstance_ReturnsObject()
    {
        // Arrange: write with one provider instance
        string id;
        using (var p1 = new WalDataProvider(_dir))
        {
            var s = MakeSetting("k2");
            p1.Save(s);
            id = s.Id;
        }

        // Act: read with a completely separate provider (simulates app restart)
        using var p2 = new WalDataProvider(_dir);
        var loaded = p2.Load<AppSetting>(id);

        // Assert
        Assert.NotNull(loaded);
        Assert.Equal("k2", loaded.SettingId);
    }

    [Fact]
    public void Load_NonExistentId_ReturnsNull()
    {
        using var provider = new WalDataProvider(_dir);
        var result = provider.Load<AppSetting>(Guid.NewGuid().ToString("N"));
        Assert.Null(result);
    }

    [Fact]
    public void Save_UpdateExisting_ReturnsUpdatedValue()
    {
        using var provider = new WalDataProvider(_dir);
        var setting = MakeSetting("upd", "original");
        provider.Save(setting);

        setting.Value = "updated";
        provider.Save(setting);

        var loaded = provider.Load<AppSetting>(setting.Id);
        Assert.NotNull(loaded);
        Assert.Equal("updated", loaded.Value);
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Query_NoFilter_ReturnsAllSaved()
    {
        using var provider = new WalDataProvider(_dir);
        for (int i = 0; i < 5; i++)
            provider.Save(MakeSetting("q_" + i));

        var results = provider.Query<AppSetting>();
        Assert.Equal(5, results.Count());
    }

    [Fact]
    public void Query_FreshInstance_ReturnsAllSaved()
    {
        using (var p1 = new WalDataProvider(_dir))
            for (int i = 0; i < 4; i++)
                p1.Save(MakeSetting("r_" + i));

        using var p2 = new WalDataProvider(_dir);
        Assert.Equal(4, p2.Query<AppSetting>().Count());
    }

    [Fact]
    public void Query_WithEqualityFilter_ReturnsMatchingRecords()
    {
        // AppSetting must be registered with DataScaffold for filter evaluation
        BareMetalWeb.Core.DataScaffold.RegisterEntity<AppSetting>();

        using var provider = new WalDataProvider(_dir);
        provider.Save(MakeSetting("needle",  "yes"));
        provider.Save(MakeSetting("haystack", "no"));

        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = nameof(AppSetting.SettingId), Operator = QueryOperator.Equals, Value = "needle" }
            }
        };

        var results = provider.Query<AppSetting>(query).ToList();
        Assert.Single(results);
        Assert.Equal("needle", results[0].SettingId);
    }

    // ── Count ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Count_NoFilter_ReturnsCorrectCount()
    {
        using var provider = new WalDataProvider(_dir);
        for (int i = 0; i < 6; i++)
            provider.Save(MakeSetting("c" + i));

        Assert.Equal(6, provider.Count<AppSetting>());
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    [Fact]
    public void Delete_ExistingRecord_LoadReturnsNull()
    {
        using var provider = new WalDataProvider(_dir);
        var s = MakeSetting("del");
        provider.Save(s);

        provider.Delete<AppSetting>(s.Id);

        Assert.Null(provider.Load<AppSetting>(s.Id));
    }

    [Fact]
    public void Delete_ExistingRecord_QueryExcludesIt()
    {
        using var provider = new WalDataProvider(_dir);
        var s1 = MakeSetting("keep");
        var s2 = MakeSetting("gone");
        provider.Save(s1);
        provider.Save(s2);

        provider.Delete<AppSetting>(s2.Id);

        var results = provider.Query<AppSetting>().ToList();
        Assert.Single(results);
        Assert.Equal("keep", results[0].SettingId);
    }

    [Fact]
    public void Delete_FreshInstance_LoadReturnsNull()
    {
        string id;
        using (var p1 = new WalDataProvider(_dir))
        {
            var s = MakeSetting("gone2");
            p1.Save(s);
            id = s.Id;
            p1.Delete<AppSetting>(id);
        }

        using var p2 = new WalDataProvider(_dir);
        Assert.Null(p2.Load<AppSetting>(id));
        Assert.Equal(0, p2.Count<AppSetting>());
    }

    [Fact]
    public void Delete_NonExistentId_DoesNotThrow()
    {
        using var provider = new WalDataProvider(_dir);
        var exception = Record.Exception(
            () => provider.Delete<AppSetting>(Guid.NewGuid().ToString("N")));
        Assert.Null(exception);
    }

    // ── Async variants ────────────────────────────────────────────────────────

    [Fact]
    public async Task SaveAsync_LoadAsync_RoundTrip()
    {
        using var provider = new WalDataProvider(_dir);
        var s = MakeSetting("async_key", "async_val");
        await provider.SaveAsync(s);
        var loaded = await provider.LoadAsync<AppSetting>(s.Id);

        Assert.NotNull(loaded);
        Assert.Equal("async_val", loaded.Value);
    }

    [Fact]
    public async Task QueryAsync_ReturnsRecords()
    {
        using var provider = new WalDataProvider(_dir);
        provider.Save(MakeSetting("a1"));
        provider.Save(MakeSetting("a2"));
        var results = await provider.QueryAsync<AppSetting>();
        Assert.Equal(2, results.Count());
    }

    // ── Sequential IDs ────────────────────────────────────────────────────────

    [Fact]
    public void NextSequentialId_IsMonotonicAcrossInstances()
    {
        string id1, id2;
        using (var p1 = new WalDataProvider(_dir))
            id1 = p1.NextSequentialId("MyEntity");

        using (var p2 = new WalDataProvider(_dir))
            id2 = p2.NextSequentialId("MyEntity");

        Assert.True(long.Parse(id2) > long.Parse(id1));
    }

    [Fact]
    public void SeedSequentialId_AdvancesCounter()
    {
        using var provider = new WalDataProvider(_dir);
        provider.SeedSequentialId("SeedEntity", 100);
        var next = provider.NextSequentialId("SeedEntity");
        Assert.True(long.Parse(next) > 100);
    }

    // ── Multiple saves survive restart ───────────────────────────────────────

    [Fact]
    public void BulkSave_FreshInstance_AllRecordsLoaded()
    {
        const int count = 25;
        var savedIds = new List<string>();

        using (var p1 = new WalDataProvider(_dir))
        {
            for (int i = 0; i < count; i++)
            {
                var s = MakeSetting("bulk_" + i, "val_" + i);
                p1.Save(s);
                savedIds.Add(s.Id);
            }
        }

        using var p2 = new WalDataProvider(_dir);
        int loaded = 0;
        foreach (var id in savedIds)
        {
            if (p2.Load<AppSetting>(id) != null) loaded++;
        }

        Assert.Equal(count, loaded);
        Assert.Equal(count, p2.Count<AppSetting>());
    }

    // ── ETag + timestamps set on save ─────────────────────────────────────────

    [Fact]
    public void Save_SetsETagAndTimestamps()
    {
        using var provider = new WalDataProvider(_dir);
        var s = MakeSetting("meta");

        provider.Save(s);

        Assert.NotEmpty(s.ETag);
        Assert.NotEqual(default, s.CreatedOnUtc);
        Assert.NotEqual(default, s.UpdatedOnUtc);
    }

    // ── IdMap file roundtrip ──────────────────────────────────────────────────

    [Fact]
    public void IdMap_PersistsAndReloads_Correctly()
    {
        string id1, id2;
        using (var p1 = new WalDataProvider(_dir))
        {
            var s1 = MakeSetting("m1"); p1.Save(s1); id1 = s1.Id;
            var s2 = MakeSetting("m2"); p1.Save(s2); id2 = s2.Id;
        }

        // Assert idmap file was created
        var idMapPath = Path.Combine(_dir, "wal", "AppSetting_idmap.bin");
        Assert.True(File.Exists(idMapPath));

        // Reload with fresh instance and verify both records accessible
        using var p2 = new WalDataProvider(_dir);
        Assert.NotNull(p2.Load<AppSetting>(id1));
        Assert.NotNull(p2.Load<AppSetting>(id2));
    }

    // ── CanHandle always returns true ─────────────────────────────────────────

    [Fact]
    public void CanHandle_AnyType_ReturnsTrue()
    {
        using var provider = new WalDataProvider(_dir);
        Assert.True(provider.CanHandle(typeof(AppSetting)));
        Assert.True(provider.CanHandle(typeof(object)));
    }
}
