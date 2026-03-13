using System.Buffers;
using System.Text;
using BareMetalWeb.Data;
using FieldPlan = BareMetalWeb.Data.MetadataWireSerializer.FieldPlan;
using WireFieldType = BareMetalWeb.Data.MetadataWireSerializer.WireFieldType;

namespace BareMetalWeb.Data.Tests;

public class BmwJsonWriterTests
{
    // Signing key for MetadataWireSerializer (32 bytes)
    private static readonly byte[] SigningKey = new byte[32];
    private static readonly MetadataWireSerializer Serializer = new(SigningKey);

    // ────────────── Helpers ──────────────

    /// <summary>
    /// Creates a single-field FieldPlan for testing.
    /// </summary>
    private static FieldPlan[] MakePlan(string name, WireFieldType wireType, bool isNullable = false,
        WireFieldType enumUnderlying = default)
    {
        return
        [
            new FieldPlan
            {
                Name = name,
                Ordinal = 0,
                WireType = wireType,
                IsNullable = isNullable,
                Getter = _ => null!,
                Setter = (_, _) => { },
                EnumUnderlying = enumUnderlying,
                ClrType = typeof(object),
            }
        ];
    }

    private static FieldPlan[] MakeMultiFieldPlan(params (string Name, WireFieldType Type, bool Nullable)[] fields)
    {
        var plan = new FieldPlan[fields.Length];
        for (int i = 0; i < fields.Length; i++)
        {
            var f = fields[i];
            plan[i] = new FieldPlan
            {
                Name = f.Name,
                Ordinal = i,
                WireType = f.Type,
                IsNullable = f.Nullable,
                Getter = _ => null!,
                Setter = (_, _) => { },
                ClrType = typeof(object),
            };
        }
        return plan;
    }

    /// <summary>
    /// Builds a BSO1 binary payload for a single field value using SpanWriter.
    /// </summary>
    private delegate void SpanWriterAction(ref SpanWriter writer);

    private static byte[] BuildBinary(FieldPlan[] plan, SpanWriterAction writeFields)
    {
        var buf = new ArrayBufferWriter<byte>();
        var w = new SpanWriter(buf);

        // BSO1 header (45 bytes)
        w.WriteInt32(0x314F5342); // magic
        w.WriteInt32(3);          // version
        w.WriteInt32(1);          // schema version
        w.WriteByte((byte)BinaryArchitectureMapper.Current); // arch
        for (int i = 0; i < 32; i++) w.WriteByte(0); // signature placeholder

        // Entity null indicator
        w.WriteByte(1);

        writeFields(ref w);
        w.Commit();
        return buf.WrittenSpan.ToArray();
    }

    private static string WriteEntityToString(byte[] binary, FieldPlan[] plan)
    {
        var frags = BmwJsonWriter.BuildFragments(plan);
        using var ms = new MemoryStream();
        BmwJsonWriter.WriteEntity(ms, binary, frags);
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    // ────────────── Bool ──────────────

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void WriteEntity_Bool_EmitsCorrectJson(bool value)
    {
        var plan = MakePlan("active", WireFieldType.Bool);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteBoolean(value));

        var json = WriteEntityToString(binary, plan);

        Assert.Equal(value ? "{\"active\":true}" : "{\"active\":false}", json);
    }

    // ────────────── Integer types ──────────────

    [Fact]
    public void WriteEntity_Int32_EmitsCorrectJson()
    {
        var plan = MakePlan("count", WireFieldType.Int32);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteInt32(42));

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"count\":42}", json);
    }

    [Fact]
    public void WriteEntity_Int32_Negative_EmitsCorrectJson()
    {
        var plan = MakePlan("balance", WireFieldType.Int32);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteInt32(-100));

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"balance\":-100}", json);
    }

    [Fact]
    public void WriteEntity_Int64_EmitsCorrectJson()
    {
        var plan = MakePlan("bigNum", WireFieldType.Int64);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteInt64(9_876_543_210L));

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"bigNum\":9876543210}", json);
    }

    [Fact]
    public void WriteEntity_UInt32_EmitsCorrectJson()
    {
        var plan = MakePlan("key", WireFieldType.UInt32);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteUInt32(12345u));

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"key\":12345}", json);
    }

    [Fact]
    public void WriteEntity_Byte_EmitsCorrectJson()
    {
        var plan = MakePlan("level", WireFieldType.Byte);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteByte(255));

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"level\":255}", json);
    }

    // ────────────── Floating point ──────────────

    [Fact]
    public void WriteEntity_Float32_EmitsCorrectJson()
    {
        var plan = MakePlan("rate", WireFieldType.Float32);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteSingle(3.14f));

        var json = WriteEntityToString(binary, plan);

        Assert.Contains("\"rate\":", json);
        Assert.Contains("3.14", json);
    }

    [Fact]
    public void WriteEntity_Float64_EmitsCorrectJson()
    {
        var plan = MakePlan("precise", WireFieldType.Float64);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteDouble(2.718281828));

        var json = WriteEntityToString(binary, plan);

        Assert.Contains("\"precise\":", json);
        Assert.Contains("2.718281828", json);
    }

    [Fact]
    public void WriteEntity_Decimal_EmitsCorrectJson()
    {
        var plan = MakePlan("price", WireFieldType.Decimal);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteDecimal(99.99m));

        var json = WriteEntityToString(binary, plan);

        Assert.Contains("\"price\":", json);
        Assert.Contains("99.99", json);
    }

    // ────────────── String ──────────────

    [Fact]
    public void WriteEntity_String_EmitsCorrectJson()
    {
        var plan = MakePlan("name", WireFieldType.String, isNullable: true);
        var value = "Hello, World!";
        var binary = BuildBinary(plan, (ref SpanWriter w) =>
        {
            w.WriteByte(1); // nullable: has value
            var bytes = Encoding.UTF8.GetBytes(value);
            w.WriteInt32(bytes.Length);
            w.WriteBytes(bytes);
        });

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"name\":\"Hello, World!\"}", json);
    }

    [Fact]
    public void WriteEntity_String_Null_EmitsNull()
    {
        var plan = MakePlan("name", WireFieldType.String, isNullable: true);
        var binary = BuildBinary(plan, (ref SpanWriter w) =>
        {
            w.WriteByte(0); // nullable: null
        });

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"name\":null}", json);
    }

    [Fact]
    public void WriteEntity_String_Empty_EmitsEmptyString()
    {
        var plan = MakePlan("name", WireFieldType.String, isNullable: true);
        var binary = BuildBinary(plan, (ref SpanWriter w) =>
        {
            w.WriteByte(1); // has value
            w.WriteInt32(0); // zero-length string
        });

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"name\":\"\"}", json);
    }

    [Fact]
    public void WriteEntity_String_WithEscapeChars_EscapesCorrectly()
    {
        var plan = MakePlan("msg", WireFieldType.String, isNullable: true);
        var value = "Hello \"World\"\nNew\tLine\\Backslash";
        var binary = BuildBinary(plan, (ref SpanWriter w) =>
        {
            w.WriteByte(1);
            var bytes = Encoding.UTF8.GetBytes(value);
            w.WriteInt32(bytes.Length);
            w.WriteBytes(bytes);
        });

        var json = WriteEntityToString(binary, plan);

        Assert.Contains("\\\"World\\\"", json);
        Assert.Contains("\\n", json);
        Assert.Contains("\\t", json);
        Assert.Contains("\\\\", json);
    }

    // ────────────── Guid ──────────────

    [Fact]
    public void WriteEntity_Guid_EmitsCorrectJson()
    {
        var plan = MakePlan("id", WireFieldType.Guid);
        var guid = Guid.Parse("12345678-1234-1234-1234-123456789abc");
        var binary = BuildBinary(plan, (ref SpanWriter w) =>
        {
            Span<byte> buf = stackalloc byte[16];
            guid.TryWriteBytes(buf);
            w.WriteBytes(buf);
        });

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"id\":\"12345678-1234-1234-1234-123456789abc\"}", json);
    }

    // ────────────── DateTime ──────────────

    [Fact]
    public void WriteEntity_DateTime_EmitsIso8601()
    {
        var plan = MakePlan("created", WireFieldType.DateTime);
        var dt = new DateTime(2024, 6, 15, 10, 30, 0, DateTimeKind.Utc);
        var binary = BuildBinary(plan, (ref SpanWriter w) =>
        {
            w.WriteInt64(dt.Ticks);
            w.WriteByte((byte)dt.Kind);
        });

        var json = WriteEntityToString(binary, plan);

        Assert.Contains("\"created\":\"", json);
        Assert.Contains("2024", json);
    }

    // ────────────── DateOnly ──────────────

    [Fact]
    public void WriteEntity_DateOnly_EmitsCorrectFormat()
    {
        var plan = MakePlan("birthday", WireFieldType.DateOnly);
        var d = new DateOnly(2000, 1, 15);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteInt32(d.DayNumber));

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"birthday\":\"2000-01-15\"}", json);
    }

    // ────────────── TimeOnly ──────────────

    [Fact]
    public void WriteEntity_TimeOnly_EmitsCorrectFormat()
    {
        var plan = MakePlan("startTime", WireFieldType.TimeOnly);
        var t = new TimeOnly(14, 30, 0);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteInt64(t.Ticks));

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"startTime\":\"14:30:00\"}", json);
    }

    // ────────────── TimeSpan ──────────────

    [Fact]
    public void WriteEntity_TimeSpan_EmitsCorrectFormat()
    {
        var plan = MakePlan("duration", WireFieldType.TimeSpan);
        var ts = new TimeSpan(1, 2, 3, 4);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteInt64(ts.Ticks));

        var json = WriteEntityToString(binary, plan);

        Assert.Contains("\"duration\":\"", json);
        Assert.Contains("1.02:03:04", json);
    }

    // ────────────── Enum ──────────────

    [Fact]
    public void WriteEntity_Enum_EmitsIntegerValue()
    {
        var plan = MakePlan("status", WireFieldType.Enum, enumUnderlying: WireFieldType.Int32);
        var binary = BuildBinary(plan, (ref SpanWriter w) => w.WriteInt32(3));

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"status\":3}", json);
    }

    // ────────────── Nullable non-null ──────────────

    [Fact]
    public void WriteEntity_NullableInt32_WithValue_EmitsValue()
    {
        var plan = MakePlan("score", WireFieldType.Int32, isNullable: true);
        var binary = BuildBinary(plan, (ref SpanWriter w) =>
        {
            w.WriteByte(1); // has value
            w.WriteInt32(99);
        });

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"score\":99}", json);
    }

    [Fact]
    public void WriteEntity_NullableInt32_Null_EmitsNull()
    {
        var plan = MakePlan("score", WireFieldType.Int32, isNullable: true);
        var binary = BuildBinary(plan, (ref SpanWriter w) =>
        {
            w.WriteByte(0); // null
        });

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"score\":null}", json);
    }

    // ────────────── Multi-field entity ──────────────

    [Fact]
    public void WriteEntity_MultipleFields_EmitsAllWithCommas()
    {
        var plan = MakeMultiFieldPlan(
            ("id", WireFieldType.UInt32, false),
            ("name", WireFieldType.String, true),
            ("active", WireFieldType.Bool, false)
        );

        var binary = BuildBinary(plan, (ref SpanWriter w) =>
        {
            // id
            w.WriteUInt32(42);
            // name (nullable string)
            w.WriteByte(1);
            var nameBytes = Encoding.UTF8.GetBytes("Alice");
            w.WriteInt32(nameBytes.Length);
            w.WriteBytes(nameBytes);
            // active
            w.WriteBoolean(true);
        });

        var json = WriteEntityToString(binary, plan);

        Assert.Equal("{\"id\":42,\"name\":\"Alice\",\"active\":true}", json);
    }

    // ────────────── Batch / list ──────────────

    [Fact]
    public void WriteEntityList_MultipleRows_EmitsWrappedArray()
    {
        var plan = MakePlan("value", WireFieldType.Int32);
        var frags = BmwJsonWriter.BuildFragments(plan);

        var row1 = BuildBinary(plan, (ref SpanWriter w) => w.WriteInt32(10));
        var row2 = BuildBinary(plan, (ref SpanWriter w) => w.WriteInt32(20));
        var row3 = BuildBinary(plan, (ref SpanWriter w) => w.WriteInt32(30));
        var rows = new List<ReadOnlyMemory<byte>> { row1, row2, row3 };

        using var ms = new MemoryStream();
        BmwJsonWriter.WriteEntityList(ms, rows, frags, 3);
        var json = Encoding.UTF8.GetString(ms.ToArray());

        Assert.Equal("{\"data\":[{\"value\":10},{\"value\":20},{\"value\":30}],\"count\":3}", json);
    }

    [Fact]
    public void WriteEntityList_Empty_EmitsEmptyArray()
    {
        var plan = MakePlan("x", WireFieldType.Int32);
        var frags = BmwJsonWriter.BuildFragments(plan);
        var rows = new List<ReadOnlyMemory<byte>>();

        using var ms = new MemoryStream();
        BmwJsonWriter.WriteEntityList(ms, rows, frags, 0);
        var json = Encoding.UTF8.GetString(ms.ToArray());

        Assert.Equal("{\"data\":[],\"count\":0}", json);
    }

    // ────────────── Fragment building ──────────────

    [Fact]
    public void BuildFragments_FirstFieldHasNoComma()
    {
        var plan = MakeMultiFieldPlan(("a", WireFieldType.Int32, false), ("b", WireFieldType.Int32, false));
        var frags = BmwJsonWriter.BuildFragments(plan);

        var prefix0 = Encoding.UTF8.GetString(frags[0].Prefix);
        var prefix1 = Encoding.UTF8.GetString(frags[1].Prefix);

        Assert.Equal("\"a\":", prefix0);
        Assert.Equal(",\"b\":", prefix1);
    }
}
