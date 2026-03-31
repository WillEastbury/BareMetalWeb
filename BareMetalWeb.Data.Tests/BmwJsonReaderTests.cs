using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using BareMetalWeb.Data;
using FieldPlan = BareMetalWeb.Data.BinaryObjectSerializer.FieldPlan;
using WireFieldType = BareMetalWeb.Data.BinaryObjectSerializer.WireFieldType;

namespace BareMetalWeb.Data.Tests;

public class BmwJsonReaderTests
{
    // ────────────── Helpers ──────────────

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
    /// Reads a field value from the BSO1 binary payload (after header + entity indicator).
    /// </summary>
    private static T ReadFieldFromBinary<T>(byte[] binary, FieldPlan fp, Func<SpanReader, T> readFunc)
    {
        // Skip header (45) + entity null indicator (1)
        var reader = new SpanReader(binary.AsSpan(46));
        if (fp.IsNullable)
        {
            var hasValue = reader.ReadByte();
            if (hasValue == 0) return default!;
        }
        return readFunc(reader);
    }

    private static string? ReadStringFromBinary(byte[] binary, FieldPlan fp)
    {
        var reader = new SpanReader(binary.AsSpan(46));
        if (fp.IsNullable)
        {
            var hasValue = reader.ReadByte();
            if (hasValue == 0) return null;
        }
        var len = reader.ReadInt32();
        if (len < 0) return null;
        if (len == 0) return string.Empty;
        Span<byte> buf = stackalloc byte[len];
        reader.ReadBytes(buf);
        return Encoding.UTF8.GetString(buf);
    }

    // ────────────── Bool ──────────────

    [Theory]
    [InlineData("true", true)]
    [InlineData("false", false)]
    public void ReadEntity_Bool_ParsesCorrectly(string jsonVal, bool expected)
    {
        var plan = MakePlan("active", WireFieldType.Bool);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes($"{{\"active\":{jsonVal}}}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var result = ReadFieldFromBinary(binary, plan[0], r => r.ReadBoolean());
        Assert.Equal(expected, result);
    }

    // ────────────── Integer types ──────────────

    [Theory]
    [InlineData(0)]
    [InlineData(42)]
    [InlineData(-100)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public void ReadEntity_Int32_ParsesCorrectly(int expected)
    {
        var plan = MakePlan("value", WireFieldType.Int32);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes($"{{\"value\":{expected}}}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var result = ReadFieldFromBinary(binary, plan[0], r => r.ReadInt32());
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ReadEntity_Int64_ParsesCorrectly()
    {
        var plan = MakePlan("big", WireFieldType.Int64);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"big\":9876543210}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var result = ReadFieldFromBinary(binary, plan[0], r => r.ReadInt64());
        Assert.Equal(9_876_543_210L, result);
    }

    [Fact]
    public void ReadEntity_UInt32_ParsesCorrectly()
    {
        var plan = MakePlan("key", WireFieldType.UInt32);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"key\":12345}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var result = ReadFieldFromBinary(binary, plan[0], r => r.ReadUInt32());
        Assert.Equal(12345u, result);
    }

    [Fact]
    public void ReadEntity_Byte_ParsesCorrectly()
    {
        var plan = MakePlan("level", WireFieldType.Byte);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"level\":255}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var result = ReadFieldFromBinary(binary, plan[0], r => r.ReadByte());
        Assert.Equal(255, result);
    }

    // ────────────── Floating point ──────────────

    [Fact]
    public void ReadEntity_Float64_ParsesCorrectly()
    {
        var plan = MakePlan("rate", WireFieldType.Float64);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"rate\":3.14159}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var result = ReadFieldFromBinary(binary, plan[0], r => r.ReadDouble());
        Assert.Equal(3.14159, result, 5);
    }

    [Fact]
    public void ReadEntity_Decimal_ParsesCorrectly()
    {
        var plan = MakePlan("price", WireFieldType.Decimal);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"price\":99.99}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var result = ReadFieldFromBinary(binary, plan[0], r => r.ReadDecimal());
        Assert.Equal(99.99m, result);
    }

    // ────────────── String ──────────────

    [Fact]
    public void ReadEntity_String_ParsesCorrectly()
    {
        var plan = MakePlan("name", WireFieldType.String, isNullable: true);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"name\":\"Alice\"}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var result = ReadStringFromBinary(binary, plan[0]);
        Assert.Equal("Alice", result);
    }

    [Fact]
    public void ReadEntity_String_Null_ProducesNull()
    {
        var plan = MakePlan("name", WireFieldType.String, isNullable: true);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"name\":null}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        // Nullable null indicator = 0
        var reader = new SpanReader(binary.AsSpan(46));
        Assert.Equal(0, reader.ReadByte());
    }

    [Fact]
    public void ReadEntity_String_WithEscapes_UnescapesCorrectly()
    {
        var plan = MakePlan("msg", WireFieldType.String, isNullable: true);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"msg\":\"Hello\\\"World\\\"\\n\\t\"}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var result = ReadStringFromBinary(binary, plan[0]);
        Assert.Equal("Hello\"World\"\n\t", result);
    }

    // ────────────── Guid ──────────────

    [Fact]
    public void ReadEntity_Guid_ParsesCorrectly()
    {
        var plan = MakePlan("id", WireFieldType.Guid);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var expected = Guid.Parse("12345678-1234-1234-1234-123456789abc");
        var json = Encoding.UTF8.GetBytes($"{{\"id\":\"{expected}\"}}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var reader = new SpanReader(binary.AsSpan(46));
        Span<byte> guidBuf = stackalloc byte[16];
        reader.ReadBytes(guidBuf);
        Assert.Equal(expected, new Guid(guidBuf));
    }

    // ────────────── DateTime ──────────────

    [Fact]
    public void ReadEntity_DateTime_ParsesIso8601()
    {
        var plan = MakePlan("created", WireFieldType.DateTime);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"created\":\"2024-06-15T10:30:00Z\"}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var reader = new SpanReader(binary.AsSpan(46));
        var ticks = reader.ReadInt64();
        var kind = (DateTimeKind)reader.ReadByte();
        var dt = new DateTime(ticks, kind);

        Assert.Equal(2024, dt.Year);
        Assert.Equal(6, dt.Month);
        Assert.Equal(15, dt.Day);
    }

    // ────────────── DateOnly ──────────────

    [Fact]
    public void ReadEntity_DateOnly_ParsesCorrectly()
    {
        var plan = MakePlan("birthday", WireFieldType.DateOnly);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"birthday\":\"2000-01-15\"}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var reader = new SpanReader(binary.AsSpan(46));
        var d = DateOnly.FromDayNumber(reader.ReadInt32());
        Assert.Equal(new DateOnly(2000, 1, 15), d);
    }

    // ────────────── TimeOnly ──────────────

    [Fact]
    public void ReadEntity_TimeOnly_ParsesCorrectly()
    {
        var plan = MakePlan("start", WireFieldType.TimeOnly);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"start\":\"14:30:00\"}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var reader = new SpanReader(binary.AsSpan(46));
        var t = new TimeOnly(reader.ReadInt64());
        Assert.Equal(new TimeOnly(14, 30, 0), t);
    }

    // ────────────── Enum ──────────────

    [Fact]
    public void ReadEntity_Enum_AsNumber_ParsesCorrectly()
    {
        var plan = MakePlan("status", WireFieldType.Enum, enumUnderlying: WireFieldType.Int32);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"status\":3}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var reader = new SpanReader(binary.AsSpan(46));
        Assert.Equal(3, reader.ReadInt32());
    }

    // ────────────── Nullable ──────────────

    [Fact]
    public void ReadEntity_NullableInt32_WithValue_ParsesCorrectly()
    {
        var plan = MakePlan("score", WireFieldType.Int32, isNullable: true);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"score\":99}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var reader = new SpanReader(binary.AsSpan(46));
        Assert.Equal(1, reader.ReadByte()); // has value
        Assert.Equal(99, reader.ReadInt32());
    }

    [Fact]
    public void ReadEntity_NullableInt32_Null_ProducesNullIndicator()
    {
        var plan = MakePlan("score", WireFieldType.Int32, isNullable: true);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"score\":null}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var reader = new SpanReader(binary.AsSpan(46));
        Assert.Equal(0, reader.ReadByte()); // null
    }

    // ────────────── Property reordering ──────────────

    [Fact]
    public void ReadEntity_PropertiesInDifferentOrder_ParsesCorrectly()
    {
        var plan = MakeMultiFieldPlan(
            ("alpha", WireFieldType.Int32, false),
            ("beta", WireFieldType.String, true),
            ("gamma", WireFieldType.Bool, false)
        );
        var lookup = BmwJsonReader.BuildLookup(plan);

        // JSON has properties in reverse ordinal order
        var json = Encoding.UTF8.GetBytes("{\"gamma\":true,\"alpha\":42,\"beta\":\"hello\"}");
        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        // Binary should have fields in ordinal order: alpha, beta, gamma
        var reader = new SpanReader(binary.AsSpan(46));

        // alpha (Int32)
        Assert.Equal(42, reader.ReadInt32());

        // beta (nullable String)
        Assert.Equal(1, reader.ReadByte()); // has value
        var strLen = reader.ReadInt32();
        Span<byte> strBuf = stackalloc byte[strLen];
        reader.ReadBytes(strBuf);
        Assert.Equal("hello", Encoding.UTF8.GetString(strBuf));

        // gamma (Bool)
        Assert.True(reader.ReadBoolean());
    }

    // ────────────── Unknown properties ──────────────

    [Fact]
    public void ReadEntity_UnknownProperties_AreIgnored()
    {
        var plan = MakePlan("known", WireFieldType.Int32);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"unknown\":\"skip me\",\"known\":42,\"alsoUnknown\":true}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var result = ReadFieldFromBinary(binary, plan[0], r => r.ReadInt32());
        Assert.Equal(42, result);
    }

    // ────────────── Malformed JSON ──────────────

    [Fact]
    public void ReadEntity_NotAnObject_Throws()
    {
        var plan = MakePlan("x", WireFieldType.Int32);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("[1,2,3]");

        Assert.Throws<InvalidOperationException>(() =>
            BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup));
    }

    // ────────────── Case-insensitive matching ──────────────

    [Fact]
    public void ReadEntity_CaseInsensitivePropertyNames_ParsesCorrectly()
    {
        var plan = MakePlan("Name", WireFieldType.String, isNullable: true);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"name\":\"alice\"}");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var result = ReadStringFromBinary(binary, plan[0]);
        Assert.Equal("alice", result);
    }

    // ────────────── Round-trip: Writer → Reader ──────────────

    [Fact]
    public void RoundTrip_WriterThenReader_ProducesEquivalentBinary()
    {
        var plan = MakeMultiFieldPlan(
            ("id", WireFieldType.UInt32, false),
            ("name", WireFieldType.String, true),
            ("score", WireFieldType.Int32, true),
            ("active", WireFieldType.Bool, false)
        );
        var frags = BmwJsonWriter.BuildFragments(plan);
        var lookup = BmwJsonReader.BuildLookup(plan);

        // Build original binary
        var buf = new ArrayBufferWriter<byte>();
        var w = new SpanWriter(buf);
        w.WriteInt32(0x314F5342); w.WriteInt32(3); w.WriteInt32(1);
        w.WriteByte((byte)BinaryArchitectureMapper.Current);
        for (int i = 0; i < 32; i++) w.WriteByte(0);
        w.WriteByte(1); // entity not null
        w.WriteUInt32(7);     // id
        w.WriteByte(1);       // name has value
        var nameBytes = Encoding.UTF8.GetBytes("Bob");
        w.WriteInt32(nameBytes.Length);
        w.WriteBytes(nameBytes);
        w.WriteByte(1);       // score has value
        w.WriteInt32(95);
        w.WriteBoolean(true); // active
        w.Commit();
        var originalBinary = buf.WrittenSpan.ToArray();

        // Transcode binary → JSON
        using var ms = new MemoryStream();
        BmwJsonWriter.WriteEntity(ms, originalBinary, frags);
        var json = ms.ToArray();

        // Transcode JSON → binary
        var roundTripBinary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        // Compare field values (skip header which has different signatures)
        var origReader = new SpanReader(originalBinary.AsSpan(46));
        var rtReader = new SpanReader(roundTripBinary.AsSpan(46));

        // id
        Assert.Equal(origReader.ReadUInt32(), rtReader.ReadUInt32());
        // name nullable indicator
        Assert.Equal(origReader.ReadByte(), rtReader.ReadByte());
        // name length
        var origNameLen = origReader.ReadInt32();
        var rtNameLen = rtReader.ReadInt32();
        Assert.Equal(origNameLen, rtNameLen);
        // name bytes
        Span<byte> origName = stackalloc byte[origNameLen];
        Span<byte> rtName = stackalloc byte[rtNameLen];
        origReader.ReadBytes(origName);
        rtReader.ReadBytes(rtName);
        Assert.True(origName.SequenceEqual(rtName));
        // score nullable + value
        Assert.Equal(origReader.ReadByte(), rtReader.ReadByte());
        Assert.Equal(origReader.ReadInt32(), rtReader.ReadInt32());
        // active
        Assert.Equal(origReader.ReadBoolean(), rtReader.ReadBoolean());
    }

    // ────────────── Merge (PATCH) ──────────────

    [Fact]
    public void MergeEntity_OverwritesChangedFields_RetainsOthers()
    {
        var plan = MakeMultiFieldPlan(
            ("id", WireFieldType.UInt32, false),
            ("name", WireFieldType.String, true),
            ("score", WireFieldType.Int32, false)
        );
        var lookup = BmwJsonReader.BuildLookup(plan);

        // Build original binary: id=1, name="Original", score=50
        var buf = new ArrayBufferWriter<byte>();
        var w = new SpanWriter(buf);
        w.WriteInt32(0x314F5342); w.WriteInt32(3); w.WriteInt32(1);
        w.WriteByte((byte)BinaryArchitectureMapper.Current);
        for (int i = 0; i < 32; i++) w.WriteByte(0);
        w.WriteByte(1);
        w.WriteUInt32(1);
        w.WriteByte(1);
        var origName = Encoding.UTF8.GetBytes("Original");
        w.WriteInt32(origName.Length);
        w.WriteBytes(origName);
        w.WriteInt32(50);
        w.Commit();
        var existingBinary = buf.WrittenSpan.ToArray();

        // Merge with partial JSON: only update name
        var json = Encoding.UTF8.GetBytes("{\"name\":\"Updated\"}");
        var mergedBinary = BmwJsonReader.MergeEntity(json.AsSpan(), existingBinary, plan, lookup);

        // Verify: id=1 (unchanged), name="Updated" (changed), score=50 (unchanged)
        var reader = new SpanReader(mergedBinary.AsSpan(46));

        Assert.Equal(1u, reader.ReadUInt32()); // id unchanged
        Assert.Equal(1, reader.ReadByte());    // name has value
        var nameLen = reader.ReadInt32();
        Span<byte> nameBuf = stackalloc byte[nameLen];
        reader.ReadBytes(nameBuf);
        Assert.Equal("Updated", Encoding.UTF8.GetString(nameBuf)); // name changed
        Assert.Equal(50, reader.ReadInt32()); // score unchanged
    }

    // ────────────── Stream overload ──────────────

    [Fact]
    public void ReadEntity_StreamOverload_WorksCorrectly()
    {
        var plan = MakePlan("val", WireFieldType.Int32);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("{\"val\":123}");
        using var ms = new MemoryStream(json);

        var binary = BmwJsonReader.ReadEntity(ms, plan, lookup);

        var result = ReadFieldFromBinary(binary, plan[0], r => r.ReadInt32());
        Assert.Equal(123, result);
    }

    // ────────────── Whitespace handling ──────────────

    [Fact]
    public void ReadEntity_WithWhitespace_ParsesCorrectly()
    {
        var plan = MakePlan("x", WireFieldType.Int32);
        var lookup = BmwJsonReader.BuildLookup(plan);
        var json = Encoding.UTF8.GetBytes("  {  \"x\"  :  42  }  ");

        var binary = BmwJsonReader.ReadEntity(json.AsSpan(), plan, lookup);

        var result = ReadFieldFromBinary(binary, plan[0], r => r.ReadInt32());
        Assert.Equal(42, result);
    }
}
