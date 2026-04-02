using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for Phase 3: virtual entities backed by DataRecord + WAL
/// via DataEntityHandlers (the same pipeline used by DataScaffold).
/// </summary>
[Collection("WalDataRecord")]
public class VirtualEntityDataRecordTests : IDisposable
{
    private readonly string _tempDir;
    private readonly WalDataProvider _provider;
    private readonly EntitySchema _schema;
    private readonly DataEntityHandlers _handlers;

    public VirtualEntityDataRecordTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"ve-dr-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        _provider = new WalDataProvider(_tempDir);
        _schema = new EntitySchema.Builder("Ticket", "tickets")
            .AddField("Title", FieldType.StringUtf8, typeof(string), required: true, maxLength: 200)
            .AddField("Description", FieldType.StringUtf8, typeof(string), nullable: true)
            .AddField("Priority", FieldType.Int32, typeof(int))
            .AddField("IsOpen", FieldType.Bool, typeof(bool))
            .Build();

        // Build handlers exactly as RuntimeEntityModel.ToEntityMetadata(walProvider, schema) does
        _handlers = new DataEntityHandlers(
            Create: () => _schema.CreateRecord(),
            LoadAsync: async (id, ct) =>
            {
                var rec = await _provider.LoadRecordAsync(id, _schema, ct).ConfigureAwait(false);
                return rec;
            },
            SaveAsync: async (obj, ct) =>
            {
                if (obj is DataRecord rec)
                    await _provider.SaveRecordAsync(rec, _schema, ct).ConfigureAwait(false);
            },
            DeleteAsync: (id, ct) => _provider.DeleteRecordAsync(id, _schema, ct),
            QueryAsync: async (query, ct) =>
            {
                var items = await _provider.QueryRecordsAsync(_schema, query, ct).ConfigureAwait(false);
                return items.Cast<DataRecord>();
            },
            CountAsync: (query, ct) => _provider.CountRecordsAsync(_schema, query, ct)
        );
    }

    public void Dispose()
    {
        (_provider as IDisposable)?.Dispose();
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    // ── Create ─────────────────────────────────────────────────────────────

    [Fact]
    public void Create_ReturnsDataRecordWithCorrectEntityTypeName()
    {
        var obj = _handlers.Create();
        Assert.IsType<DataRecord>(obj);
        var rec = (DataRecord)obj;
        Assert.Equal("Ticket", rec.EntityTypeName);
        Assert.NotNull(rec.Schema);
        Assert.Equal(DataRecord.BaseFieldCount + 4, rec.FieldCount);
    }

    // ── CRUD round-trip via handlers ───────────────────────────────────────

    [Fact]
    public async Task SaveAndLoad_RoundTripsViaHandlers()
    {
        var obj = _handlers.Create();
        var rec = (DataRecord)obj;
        rec.Key = 1;
        rec.SetField(_schema, "Title", "Fix login bug");
        rec.SetField(_schema, "Description", "Users cannot log in after password reset");
        rec.SetField(_schema, "Priority", 1);
        rec.SetField(_schema, "IsOpen", true);

        await _handlers.SaveAsync(rec, CancellationToken.None);

        var loaded = await _handlers.LoadAsync(1, CancellationToken.None);
        Assert.NotNull(loaded);
        Assert.IsType<DataRecord>(loaded);
        var loadedRec = (DataRecord)loaded;
        Assert.Equal(1u, loadedRec.Key);
        Assert.Equal("Fix login bug", loadedRec.GetField(_schema, "Title"));
        Assert.Equal("Users cannot log in after password reset", loadedRec.GetField(_schema, "Description"));
        Assert.Equal(1, loadedRec.GetField(_schema, "Priority"));
        Assert.Equal(true, loadedRec.GetField(_schema, "IsOpen"));
    }

    [Fact]
    public async Task Load_MissingKey_ReturnsNull()
    {
        var result = await _handlers.LoadAsync(9999, CancellationToken.None);
        Assert.Null(result);
    }

    [Fact]
    public async Task Delete_RemovesRecord()
    {
        var rec = (DataRecord)_handlers.Create();
        rec.Key = 10;
        rec.SetField(_schema, "Title", "To be deleted");
        await _handlers.SaveAsync(rec, CancellationToken.None);

        await _handlers.DeleteAsync(10, CancellationToken.None);

        var loaded = await _handlers.LoadAsync(10, CancellationToken.None);
        Assert.Null(loaded);
    }

    // ── Query + Count ─────────────────────────────────────────────────────

    [Fact]
    public async Task QueryAndCount_AllRecords()
    {
        for (uint i = 1; i <= 3; i++)
        {
            var rec = (DataRecord)_handlers.Create();
            rec.Key = i;
            rec.SetField(_schema, "Title", $"Ticket {i}");
            rec.SetField(_schema, "Priority", (int)i);
            rec.SetField(_schema, "IsOpen", true);
            await _handlers.SaveAsync(rec, CancellationToken.None);
        }

        var all = (await _handlers.QueryAsync(null, CancellationToken.None)).ToList();
        Assert.Equal(3, all.Count);
        Assert.All(all, obj => Assert.IsType<DataRecord>(obj));

        var count = await _handlers.CountAsync(null, CancellationToken.None);
        Assert.Equal(3, count);
    }

    [Fact]
    public async Task Query_WithFilter_ReturnsMatching()
    {
        var open = (DataRecord)_handlers.Create();
        open.Key = 1; open.SetField(_schema, "Title", "Open ticket"); open.SetField(_schema, "IsOpen", true);
        await _handlers.SaveAsync(open, CancellationToken.None);

        var closed = (DataRecord)_handlers.Create();
        closed.Key = 2; closed.SetField(_schema, "Title", "Closed ticket"); closed.SetField(_schema, "IsOpen", false);
        await _handlers.SaveAsync(closed, CancellationToken.None);

        var query = new QueryDefinition();
        query.Clauses.Add(new QueryClause { Field = "IsOpen", Operator = QueryOperator.Equals, Value = "True" });

        var results = (await _handlers.QueryAsync(query, CancellationToken.None)).ToList();
        Assert.Single(results);
        Assert.Equal(1u, results[0].Key);
    }

    // ── Ordinal-indexed field access ─────────────────────────────────

    [Fact]
    public void OrdinalIndexed_GetSetValue_OnDataRecord()
    {
        var rec = _schema.CreateRecord();
        rec.Key = 1;

        // Direct ordinal access (as RuntimeEntityModel does)
        int titleOrd = _schema.TryGetOrdinal("Title", out var tOrd) ? tOrd : -1;
        rec.SetValue(titleOrd, "Hello World");
        Assert.Equal("Hello World", rec.GetValue(titleOrd));

        int priorityOrd = _schema.TryGetOrdinal("Priority", out var pOrd) ? pOrd : -1;
        rec.SetValue(priorityOrd, 42);
        Assert.Equal(42, rec.GetValue(priorityOrd));
    }

    [Fact]
    public void NameBased_GetSetValue_ViaSchema()
    {
        var rec = _schema.CreateRecord();
        int titleOrd = _schema.TryGetOrdinal("Title", out var tOrd) ? tOrd : -1;
        rec.SetValue(titleOrd, "Test title");

        // Name-based access via DataRecord.GetFieldByName
        Assert.Equal("Test title", rec.GetFieldByName("Title"));
    }

    // ── DataRecord.Schema property ────────────────────────────────────────

    [Fact]
    public void DataRecord_Schema_IsSetFromConstructor()
    {
        var rec = new DataRecord(_schema);
        Assert.Same(_schema, rec.Schema);
        Assert.Equal("Ticket", rec.EntityTypeName);
    }

    [Fact]
    public void DataRecord_FieldCount_Constructor_HasNoSchema()
    {
        var rec = new DataRecord(5);
        Assert.Null(rec.Schema);
    }
}
