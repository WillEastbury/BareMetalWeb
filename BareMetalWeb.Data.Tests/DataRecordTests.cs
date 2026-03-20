using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class DataRecordTests
{
    // ── Construction ───────────────────────────────────────────────────────

    [Fact]
    public void Constructor_FieldCount_AllocatesCorrectSize()
    {
        var record = new DataRecord(10);
        Assert.Equal(10, record.FieldCount);
    }

    [Fact]
    public void Constructor_Schema_SetsEntityTypeNameAndSize()
    {
        var schema = BuildTestSchema();
        var record = new DataRecord(schema);

        Assert.Equal("TestEntity", record.EntityTypeName);
        Assert.Equal(BaseDataObject.BaseFieldCount + 3, record.FieldCount);
    }

    // ── Ordinal access (hot path) ──────────────────────────────────────────

    [Fact]
    public void GetSetValue_Ordinal_RoundTrips()
    {
        var record = new DataRecord(3);
        record.SetValue(0, "Alice");
        record.SetValue(1, 42);
        record.SetValue(2, 99.5m);

        Assert.Equal("Alice", record.GetValue(0));
        Assert.Equal(42, record.GetValue(1));
        Assert.Equal(99.5m, record.GetValue(2));
    }

    [Fact]
    public void GetValue_Unset_ReturnsNull()
    {
        var schema = BuildTestSchema();
        var record = new DataRecord(schema);
        // Schema fields are unset by default
        Assert.Null(record.GetValue(BaseDataObject.BaseFieldCount + 0));
        Assert.Null(record.GetValue(BaseDataObject.BaseFieldCount + 2));
    }

    [Fact]
    public void SetValue_Null_ClearsField()
    {
        var record = new DataRecord(2);
        record.SetValue(0, "hello");
        record.SetValue(0, null);

        Assert.Null(record.GetValue(0));
    }

    [Fact]
    public void SetValue_NativeTypes_PreservesClrType()
    {
        var record = new DataRecord(6);
        var now = DateTime.UtcNow;
        var today = DateOnly.FromDateTime(DateTime.Today);

        record.SetValue(0, "text");
        record.SetValue(1, 42);
        record.SetValue(2, 3.14m);
        record.SetValue(3, true);
        record.SetValue(4, now);
        record.SetValue(5, today);

        Assert.IsType<string>(record.GetValue(0));
        Assert.IsType<int>(record.GetValue(1));
        Assert.IsType<decimal>(record.GetValue(2));
        Assert.IsType<bool>(record.GetValue(3));
        Assert.IsType<DateTime>(record.GetValue(4));
        Assert.IsType<DateOnly>(record.GetValue(5));
    }

    // ── Named access (boundary path) ───────────────────────────────────────

    [Fact]
    public void GetSetField_ByName_RoundTrips()
    {
        var schema = BuildTestSchema();
        var record = schema.CreateRecord();

        record.SetField(schema, "Name", "Bob");
        record.SetField(schema, "Age", 30);
        record.SetField(schema, "Active", true);

        Assert.Equal("Bob", record.GetField(schema, "Name"));
        Assert.Equal(30, record.GetField(schema, "Age"));
        Assert.Equal(true, record.GetField(schema, "Active"));
    }

    [Fact]
    public void GetField_UnknownName_ReturnsNull()
    {
        var schema = BuildTestSchema();
        var record = schema.CreateRecord();

        Assert.Null(record.GetField(schema, "DoesNotExist"));
    }

    [Fact]
    public void SetField_UnknownName_DoesNotThrow()
    {
        var schema = BuildTestSchema();
        var record = schema.CreateRecord();

        // Should silently ignore unknown fields (boundary safety)
        record.SetField(schema, "DoesNotExist", "value");
        Assert.Null(record.GetField(schema, "DoesNotExist"));
    }

    [Fact]
    public void GetField_CaseInsensitive()
    {
        var schema = BuildTestSchema();
        var record = schema.CreateRecord();
        record.SetField(schema, "name", "Alice");

        Assert.Equal("Alice", record.GetField(schema, "NAME"));
        Assert.Equal("Alice", record.GetField(schema, "Name"));
    }

    // ── Resize ─────────────────────────────────────────────────────────────

    [Fact]
    public void Resize_PreservesExistingValues()
    {
        var record = new DataRecord(10);
        record.SetValue(0, "keep");
        record.SetValue(1, 42);
        record.SetValue(2, true);

        record.Resize(14);

        Assert.Equal(14, record.FieldCount);
        Assert.Equal("keep", record.GetValue(0));
        Assert.Equal(42, record.GetValue(1));
        Assert.Equal(true, record.GetValue(2));
        Assert.Null(record.GetValue(10));
        Assert.Null(record.GetValue(13));
    }

    [Fact]
    public void Resize_SmallerOrEqual_NoOp()
    {
        var record = new DataRecord(10);
        record.SetValue(0, "original");

        record.Resize(5); // smaller — no-op
        Assert.Equal(10, record.FieldCount);
        Assert.Equal("original", record.GetValue(0));

        record.Resize(10); // equal — no-op
        Assert.Equal(10, record.FieldCount);
    }

    // ── BaseDataObject ─────────────────────────────────────────────────────

    [Fact]
    public void InheritsBaseDataObjectProperties()
    {
        var record = new DataRecord(1);
        record.Key = 42;
        record.CreatedBy = "system";
        record.ETag = "abc123";
        record.Version = 3;

        Assert.Equal(42u, record.Key);
        Assert.Equal("system", record.CreatedBy);
        Assert.Equal("abc123", record.ETag);
        Assert.Equal(3u, record.Version);
    }

    [Fact]
    public void Touch_IncrementsVersion()
    {
        var record = new DataRecord(1);
        Assert.Equal(0u, record.Version);

        record.Touch("admin");
        Assert.Equal(1u, record.Version);
        Assert.Equal("admin", record.UpdatedBy);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static EntitySchema BuildTestSchema()
    {
        return new EntitySchema.Builder("TestEntity", "test-entities")
            .AddField("Name", FieldType.StringUtf8, typeof(string), required: true, maxLength: 100)
            .AddField("Age", FieldType.Int32, typeof(int))
            .AddField("Active", FieldType.Bool, typeof(bool))
            .Build();
    }
}
