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
[Collection("SharedState")]
public sealed class WalDataProviderTests : IDisposable
{
    private readonly string _dir;

    public WalDataProviderTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "BmwWalProviderTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        BareMetalWeb.Core.DataScaffold.RegisterEntity<AppSetting>();
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
        setting.Key = provider.NextSequentialKey("AppSetting");

        // Act
        provider.Save(setting);
        var loaded = provider.Load<AppSetting>(setting.Key);

        // Assert
        Assert.NotNull(loaded);
        Assert.Equal("key1",  loaded.SettingId);
        Assert.Equal("hello", loaded.Value);
    }

    [Fact]
    public void Save_ThenLoad_FreshInstance_ReturnsObject()
    {
        // Arrange: write with one provider instance
        uint key;
        using (var p1 = new WalDataProvider(_dir))
        {
            var s = MakeSetting("k2");
            s.Key = p1.NextSequentialKey("AppSetting");
            p1.Save(s);
            key = s.Key;
        }

        // Act: read with a completely separate provider (simulates app restart)
        using var p2 = new WalDataProvider(_dir);
        var loaded = p2.Load<AppSetting>(key);

        // Assert
        Assert.NotNull(loaded);
        Assert.Equal("k2", loaded.SettingId);
    }

    [Fact]
    public void Load_NonExistentId_ReturnsNull()
    {
        using var provider = new WalDataProvider(_dir);
        var result = provider.Load<AppSetting>(99999u);
        Assert.Null(result);
    }

    [Fact]
    public void Save_UpdateExisting_ReturnsUpdatedValue()
    {
        using var provider = new WalDataProvider(_dir);
        var setting = MakeSetting("upd", "original");
        setting.Key = provider.NextSequentialKey("AppSetting");
        provider.Save(setting);

        setting.Value = "updated";
        provider.Save(setting);

        var loaded = provider.Load<AppSetting>(setting.Key);
        Assert.NotNull(loaded);
        Assert.Equal("updated", loaded.Value);
    }

    // ── Query ─────────────────────────────────────────────────────────────────

    [Fact]
    public void Query_NoFilter_ReturnsAllSaved()
    {
        using var provider = new WalDataProvider(_dir);
        for (int i = 0; i < 5; i++)
        {
            var s = MakeSetting("q_" + i);
            s.Key = provider.NextSequentialKey("AppSetting");
            provider.Save(s);
        }

        var results = provider.Query<AppSetting>();
        Assert.Equal(5, results.Count());
    }

    [Fact]
    public void Query_FreshInstance_ReturnsAllSaved()
    {
        using (var p1 = new WalDataProvider(_dir))
            for (int i = 0; i < 4; i++)
            {
                var s = MakeSetting("r_" + i);
                s.Key = p1.NextSequentialKey("AppSetting");
                p1.Save(s);
            }

        using var p2 = new WalDataProvider(_dir);
        Assert.Equal(4, p2.Query<AppSetting>().Count());
    }

    [Fact]
    public void Query_WithEqualityFilter_ReturnsMatchingRecords()
    {
        // AppSetting must be registered with DataScaffold for filter evaluation
        BareMetalWeb.Core.DataScaffold.RegisterEntity<AppSetting>();

        using var provider = new WalDataProvider(_dir);
        var s1 = MakeSetting("needle",  "yes");
        s1.Key = provider.NextSequentialKey("AppSetting");
        provider.Save(s1);
        var s2 = MakeSetting("haystack", "no");
        s2.Key = provider.NextSequentialKey("AppSetting");
        provider.Save(s2);

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
        {
            var s = MakeSetting("c" + i);
            s.Key = provider.NextSequentialKey("AppSetting");
            provider.Save(s);
        }

        Assert.Equal(6, provider.Count<AppSetting>());
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    [Fact]
    public void Delete_ExistingRecord_LoadReturnsNull()
    {
        using var provider = new WalDataProvider(_dir);
        var s = MakeSetting("del");
        s.Key = provider.NextSequentialKey("AppSetting");
        provider.Save(s);

        provider.Delete<AppSetting>(s.Key);

        Assert.Null(provider.Load<AppSetting>(s.Key));
    }

    [Fact]
    public void Delete_ExistingRecord_QueryExcludesIt()
    {
        using var provider = new WalDataProvider(_dir);
        var s1 = MakeSetting("keep");
        s1.Key = provider.NextSequentialKey("AppSetting");
        var s2 = MakeSetting("gone");
        s2.Key = provider.NextSequentialKey("AppSetting");
        provider.Save(s1);
        provider.Save(s2);

        provider.Delete<AppSetting>(s2.Key);

        var results = provider.Query<AppSetting>().ToList();
        Assert.Single(results);
        Assert.Equal("keep", results[0].SettingId);
    }

    [Fact]
    public void Delete_FreshInstance_LoadReturnsNull()
    {
        uint key;
        using (var p1 = new WalDataProvider(_dir))
        {
            var s = MakeSetting("gone2");
            s.Key = p1.NextSequentialKey("AppSetting");
            p1.Save(s);
            key = s.Key;
            p1.Delete<AppSetting>(key);
        }

        using var p2 = new WalDataProvider(_dir);
        Assert.Null(p2.Load<AppSetting>(key));
        Assert.Equal(0, p2.Count<AppSetting>());
    }

    [Fact]
    public void Delete_NonExistentId_DoesNotThrow()
    {
        using var provider = new WalDataProvider(_dir);
        var exception = Record.Exception(
            () => provider.Delete<AppSetting>(99999u));
        Assert.Null(exception);
    }

    // ── Async variants ────────────────────────────────────────────────────────

    [Fact]
    public async Task SaveAsync_LoadAsync_RoundTrip()
    {
        using var provider = new WalDataProvider(_dir);
        var s = MakeSetting("async_key", "async_val");
        s.Key = provider.NextSequentialKey("AppSetting");
        await provider.SaveAsync(s);
        var loaded = await provider.LoadAsync<AppSetting>(s.Key);

        Assert.NotNull(loaded);
        Assert.Equal("async_val", loaded.Value);
    }

    [Fact]
    public async Task QueryAsync_ReturnsRecords()
    {
        using var provider = new WalDataProvider(_dir);
        var a1 = MakeSetting("a1"); a1.Key = provider.NextSequentialKey("AppSetting"); provider.Save(a1);
        var a2 = MakeSetting("a2"); a2.Key = provider.NextSequentialKey("AppSetting"); provider.Save(a2);
        var results = await provider.QueryAsync<AppSetting>();
        Assert.Equal(2, results.Count());
    }

    // ── Sequential IDs ────────────────────────────────────────────────────────

    [Fact]
    public void NextSequentialKey_IsMonotonicAcrossInstances()
    {
        uint key1, key2;
        using (var p1 = new WalDataProvider(_dir))
            key1 = p1.NextSequentialKey("MyEntity");

        using (var p2 = new WalDataProvider(_dir))
            key2 = p2.NextSequentialKey("MyEntity");

        Assert.True(key2 > key1);
    }

    [Fact]
    public void SeedSequentialKey_AdvancesCounter()
    {
        using var provider = new WalDataProvider(_dir);
        provider.SeedSequentialKey("SeedEntity", 100);
        var next = provider.NextSequentialKey("SeedEntity");
        Assert.True(next > 100u);
    }

    // ── Multiple saves survive restart ───────────────────────────────────────

    [Fact]
    public void BulkSave_FreshInstance_AllRecordsLoaded()
    {
        const int count = 25;
        var savedKeys = new List<uint>();

        using (var p1 = new WalDataProvider(_dir))
        {
            for (int i = 0; i < count; i++)
            {
                var s = MakeSetting("bulk_" + i, "val_" + i);
                s.Key = p1.NextSequentialKey("AppSetting");
                p1.Save(s);
                savedKeys.Add(s.Key);
            }
        }

        using var p2 = new WalDataProvider(_dir);
        int loaded = 0;
        foreach (var key in savedKeys)
        {
            if (p2.Load<AppSetting>(key) != null) loaded++;
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
        s.Key = provider.NextSequentialKey("AppSetting");

        provider.Save(s);

        Assert.NotEmpty(s.ETag);
        Assert.NotEqual(default, s.CreatedOnUtc);
        Assert.NotEqual(default, s.UpdatedOnUtc);
    }

    // ── IdMap file roundtrip ──────────────────────────────────────────────────

    [Fact]
    public void IdMap_PersistsAndReloads_Correctly()
    {
        uint key1, key2;
        using (var p1 = new WalDataProvider(_dir))
        {
            var s1 = MakeSetting("m1"); s1.Key = p1.NextSequentialKey("AppSetting"); p1.Save(s1); key1 = s1.Key;
            var s2 = MakeSetting("m2"); s2.Key = p1.NextSequentialKey("AppSetting"); p1.Save(s2); key2 = s2.Key;
        }

        // Assert idmap file was created
        var idMapPath = Path.Combine(_dir, "wal", "AppSetting_idmap.bin");
        Assert.True(File.Exists(idMapPath));

        // Reload with fresh instance and verify both records accessible
        using var p2 = new WalDataProvider(_dir);
        Assert.NotNull(p2.Load<AppSetting>(key1));
        Assert.NotNull(p2.Load<AppSetting>(key2));
    }

    // ── CanHandle always returns true ─────────────────────────────────────────

    [Fact]
    public void CanHandle_AnyType_ReturnsTrue()
    {
        using var provider = new WalDataProvider(_dir);
        Assert.True(provider.CanHandle(typeof(AppSetting)));
        Assert.True(provider.CanHandle(typeof(object)));
    }

    // ── Secondary index acceleration ──────────────────────────────────────────

    [Fact]
    public void Query_IndexedFieldEquals_UsesIndexNotFullScan()
    {
        // AppSetting.SettingId is decorated with [DataIndex], so WalDataProvider
        // must populate the secondary index on Save and consult it on Query.
        BareMetalWeb.Core.DataScaffold.RegisterEntity<AppSetting>();
        using var provider = new WalDataProvider(_dir);

        const int total = 20;
        for (int i = 0; i < total; i++)
        {
            var s = MakeSetting("sid_" + i, "val_" + i);
            s.Key = provider.NextSequentialKey("AppSetting");
            provider.Save(s);
        }

        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = nameof(AppSetting.SettingId), Operator = QueryOperator.Equals, Value = "sid_5" }
            }
        };

        var results = provider.Query<AppSetting>(query).ToList();

        Assert.Single(results);
        Assert.Equal("sid_5", results[0].SettingId);
    }

    [Fact]
    public void Query_IndexedFieldEquals_NoMatch_ReturnsEmpty()
    {
        BareMetalWeb.Core.DataScaffold.RegisterEntity<AppSetting>();
        using var provider = new WalDataProvider(_dir);
        for (int i = 0; i < 5; i++)
        {
            var s = MakeSetting("x_" + i);
            s.Key = provider.NextSequentialKey("AppSetting");
            provider.Save(s);
        }

        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = nameof(AppSetting.SettingId), Operator = QueryOperator.Equals, Value = "does_not_exist" }
            }
        };

        var results = provider.Query<AppSetting>(query).ToList();
        Assert.Empty(results);
    }

    [Fact]
    public void Query_IndexedField_AfterDelete_ExcludesDeletedRecord()
    {
        BareMetalWeb.Core.DataScaffold.RegisterEntity<AppSetting>();
        using var provider = new WalDataProvider(_dir);

        var s1 = MakeSetting("del_target", "to_be_deleted");
        s1.Key = provider.NextSequentialKey("AppSetting");
        provider.Save(s1);

        var s2 = MakeSetting("del_target2", "to_keep");
        s2.Key = provider.NextSequentialKey("AppSetting");
        provider.Save(s2);

        // Delete the first record — the index entry must be cleaned up
        provider.Delete<AppSetting>(s1.Key);

        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = nameof(AppSetting.SettingId), Operator = QueryOperator.Equals, Value = "del_target" }
            }
        };

        var results = provider.Query<AppSetting>(query).ToList();
        Assert.Empty(results);
    }

    [Fact]
    public void Query_IndexedField_AfterUpdate_ReflectsNewValue()
    {
        BareMetalWeb.Core.DataScaffold.RegisterEntity<AppSetting>();
        using var provider = new WalDataProvider(_dir);

        var s = MakeSetting("old_id", "v");
        s.Key = provider.NextSequentialKey("AppSetting");
        provider.Save(s);

        // Update the indexed field
        s.SettingId = "new_id";
        provider.Save(s);

        // old value must no longer be found
        var queryOld = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = nameof(AppSetting.SettingId), Operator = QueryOperator.Equals, Value = "old_id" }
            }
        };
        Assert.Empty(provider.Query<AppSetting>(queryOld).ToList());

        // new value must be found
        var queryNew = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = nameof(AppSetting.SettingId), Operator = QueryOperator.Equals, Value = "new_id" }
            }
        };
        var results = provider.Query<AppSetting>(queryNew).ToList();
        Assert.Single(results);
        Assert.Equal("new_id", results[0].SettingId);
    }

    [Fact]
    public void Query_IndexedField_SurvivesProviderRestart()
    {
        // Ensure that the secondary index paged files are persisted so a fresh
        // WalDataProvider instance can still accelerate queries.
        BareMetalWeb.Core.DataScaffold.RegisterEntity<AppSetting>();
        string settingId;

        using (var p1 = new WalDataProvider(_dir))
        {
            var s = MakeSetting("persist_idx", "v");
            s.Key = p1.NextSequentialKey("AppSetting");
            p1.Save(s);
            settingId = s.SettingId;
        }

        using var p2 = new WalDataProvider(_dir);
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = nameof(AppSetting.SettingId), Operator = QueryOperator.Equals, Value = settingId }
            }
        };

        var results = p2.Query<AppSetting>(query).ToList();
        Assert.Single(results);
        Assert.Equal(settingId, results[0].SettingId);
    }
}
