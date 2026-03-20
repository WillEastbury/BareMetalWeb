using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[Collection("WalDataRecord")]
public class WalDataRecordTests : IDisposable
{
    private readonly string _tempDir;
    private readonly WalDataProvider _provider;
    private readonly EntitySchema _schema;

    public WalDataRecordTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"wal-dr-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _provider = new WalDataProvider(_tempDir);
        _schema = new EntitySchema.Builder("Widget", "widgets")
            .AddField("Name", FieldType.StringUtf8, typeof(string), required: true, maxLength: 100)
            .AddField("Price", FieldType.Decimal, typeof(decimal))
            .AddField("Active", FieldType.Bool, typeof(bool))
            .AddField("Category", FieldType.StringUtf8, typeof(string), indexed: true)
            .Build();
    }

    public void Dispose()
    {
        (_provider as IDisposable)?.Dispose();
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    // ── Save + Load round-trip ─────────────────────────────────────────────

    [Fact]
    public void SaveRecord_LoadRecord_RoundTrips()
    {
        var record = _schema.CreateRecord();
        record.Key = 1;
        record.SetField(_schema, "Name", "Sprocket");
        record.SetField(_schema, "Price", 9.99m);
        record.SetField(_schema, "Active", true);
        record.SetField(_schema, "Category", "Hardware");

        _provider.SaveRecord(record, _schema);

        var loaded = _provider.LoadRecord(1, _schema);
        Assert.NotNull(loaded);
        Assert.Equal(1u, loaded.Key);
        Assert.Equal("Widget", loaded.EntityTypeName);
        Assert.Equal("Sprocket", loaded.GetField(_schema, "Name"));
        Assert.Equal(9.99m, loaded.GetField(_schema, "Price"));
        Assert.Equal(true, loaded.GetField(_schema, "Active"));
        Assert.Equal("Hardware", loaded.GetField(_schema, "Category"));
    }

    [Fact]
    public void SaveRecord_SetsTimestampsAndETag()
    {
        var record = _schema.CreateRecord();
        record.Key = 2;
        record.SetField(_schema, "Name", "Gear");

        _provider.SaveRecord(record, _schema);

        var loaded = _provider.LoadRecord(2, _schema);
        Assert.NotNull(loaded);
        Assert.True(loaded.CreatedOnUtc > DateTime.MinValue);
        Assert.True(loaded.UpdatedOnUtc > DateTime.MinValue);
        Assert.False(string.IsNullOrEmpty(loaded.ETag));
    }

    [Fact]
    public void SaveRecord_Update_PreservesKey()
    {
        var record = _schema.CreateRecord();
        record.Key = 3;
        record.SetField(_schema, "Name", "Original");
        _provider.SaveRecord(record, _schema);

        var updated = _schema.CreateRecord();
        updated.Key = 3;
        updated.SetField(_schema, "Name", "Updated");
        _provider.SaveRecord(updated, _schema);

        var reloaded = _provider.LoadRecord(3, _schema)!;
        Assert.Equal("Updated", reloaded.GetField(_schema, "Name"));
        Assert.Equal(3u, reloaded.Key);
    }

    // ── Load missing ───────────────────────────────────────────────────────

    [Fact]
    public void LoadRecord_MissingKey_ReturnsNull()
    {
        Assert.Null(_provider.LoadRecord(999, _schema));
    }

    // ── Query ──────────────────────────────────────────────────────────────

    [Fact]
    public void QueryRecords_ReturnsAll()
    {
        SaveTestRecords();

        var all = _provider.QueryRecords(_schema).ToList();
        Assert.Equal(3, all.Count);
    }

    [Fact]
    public void QueryRecords_WithFilter()
    {
        SaveTestRecords();

        var query = new QueryDefinition();
        query.Clauses.Add(new QueryClause { Field = "Category", Operator = QueryOperator.Equals, Value = "Electronics" });

        var filtered = _provider.QueryRecords(_schema, query).ToList();
        Assert.Equal(2, filtered.Count);
        Assert.All(filtered, r => Assert.Equal("Electronics", r.GetField(_schema, "Category")));
    }

    [Fact]
    public void QueryRecords_WithSort()
    {
        SaveTestRecords();

        var query = new QueryDefinition();
        query.Sorts.Add(new SortClause { Field = "Name", Direction = SortDirection.Asc });

        var sorted = _provider.QueryRecords(_schema, query).ToList();
        Assert.Equal("Alpha", sorted[0].GetField(_schema, "Name"));
        Assert.Equal("Beta", sorted[1].GetField(_schema, "Name"));
        Assert.Equal("Gamma", sorted[2].GetField(_schema, "Name"));
    }

    [Fact]
    public void QueryRecords_WithPaging()
    {
        SaveTestRecords();

        var query = new QueryDefinition { Skip = 1, Top = 1 };
        var paged = _provider.QueryRecords(_schema, query).ToList();
        Assert.Single(paged);
    }

    // ── Count ──────────────────────────────────────────────────────────────

    [Fact]
    public void CountRecords_ReturnsCorrectCount()
    {
        SaveTestRecords();
        Assert.Equal(3, _provider.CountRecords(_schema));
    }

    [Fact]
    public void CountRecords_WithFilter()
    {
        SaveTestRecords();

        var query = new QueryDefinition();
        query.Clauses.Add(new QueryClause { Field = "Category", Operator = QueryOperator.Equals, Value = "Tools" });

        Assert.Equal(1, _provider.CountRecords(_schema, query));
    }

    // ── Delete ─────────────────────────────────────────────────────────────

    [Fact]
    public void DeleteRecord_RemovesFromStore()
    {
        var record = _schema.CreateRecord();
        record.Key = 10;
        record.SetField(_schema, "Name", "ToDelete");
        _provider.SaveRecord(record, _schema);

        Assert.NotNull(_provider.LoadRecord(10, _schema));

        _provider.DeleteRecord(10, _schema);

        Assert.Null(_provider.LoadRecord(10, _schema));
    }

    [Fact]
    public void DeleteRecord_DecrementsCount()
    {
        SaveTestRecords();
        Assert.Equal(3, _provider.CountRecords(_schema));

        _provider.DeleteRecord(1, _schema);
        Assert.Equal(2, _provider.CountRecords(_schema));
    }

    [Fact]
    public void DeleteRecord_MissingKey_NoOp()
    {
        _provider.DeleteRecord(999, _schema); // should not throw
    }

    // ── Deser cache ────────────────────────────────────────────────────────

    [Fact]
    public void LoadRecord_CachesResult()
    {
        var record = _schema.CreateRecord();
        record.Key = 20;
        record.SetField(_schema, "Name", "Cached");
        _provider.SaveRecord(record, _schema);

        var first = _provider.LoadRecord(20, _schema);
        var second = _provider.LoadRecord(20, _schema);

        // Same reference from cache
        Assert.Same(first, second);
    }

    [Fact]
    public void SaveRecord_InvalidatesCacheOnUpdate()
    {
        var record = _schema.CreateRecord();
        record.Key = 21;
        record.SetField(_schema, "Name", "V1");
        _provider.SaveRecord(record, _schema);

        var cached = _provider.LoadRecord(21, _schema)!;
        Assert.Equal("V1", cached.GetField(_schema, "Name"));

        var updated = _schema.CreateRecord();
        updated.Key = 21;
        updated.SetField(_schema, "Name", "V2");
        _provider.SaveRecord(updated, _schema);

        var fresh = _provider.LoadRecord(21, _schema)!;
        Assert.Equal("V2", fresh.GetField(_schema, "Name"));
        Assert.NotSame(cached, fresh);
    }

    // ── Async variants ─────────────────────────────────────────────────────

    [Fact]
    public async Task AsyncMethods_Work()
    {
        var record = _schema.CreateRecord();
        record.Key = 30;
        record.SetField(_schema, "Name", "Async");
        record.SetField(_schema, "Category", "AsyncCat");

        await _provider.SaveRecordAsync(record, _schema);

        var loaded = await _provider.LoadRecordAsync(30, _schema);
        Assert.NotNull(loaded);
        Assert.Equal("Async", loaded!.GetField(_schema, "Name"));

        var all = await _provider.QueryRecordsAsync(_schema);
        Assert.Single(all);

        var count = await _provider.CountRecordsAsync(_schema);
        Assert.Equal(1, count);

        await _provider.DeleteRecordAsync(30, _schema);
        Assert.Null(await _provider.LoadRecordAsync(30, _schema));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private void SaveTestRecords()
    {
        var r1 = _schema.CreateRecord(); r1.Key = 1;
        r1.SetField(_schema, "Name", "Alpha"); r1.SetField(_schema, "Price", 10m); r1.SetField(_schema, "Active", true); r1.SetField(_schema, "Category", "Electronics");
        _provider.SaveRecord(r1, _schema);

        var r2 = _schema.CreateRecord(); r2.Key = 2;
        r2.SetField(_schema, "Name", "Beta"); r2.SetField(_schema, "Price", 20m); r2.SetField(_schema, "Active", false); r2.SetField(_schema, "Category", "Electronics");
        _provider.SaveRecord(r2, _schema);

        var r3 = _schema.CreateRecord(); r3.Key = 3;
        r3.SetField(_schema, "Name", "Gamma"); r3.SetField(_schema, "Price", 30m); r3.SetField(_schema, "Active", true); r3.SetField(_schema, "Category", "Tools");
        _provider.SaveRecord(r3, _schema);
    }
}
