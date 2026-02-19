using System.Buffers;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.Tests;

public class SpanReaderWriterTests
{
    private delegate void WriteDelegate(ref SpanWriter writer);
    private delegate T ReadDelegate<T>(ref SpanReader reader);

    private static byte[] WriteToBuffer(WriteDelegate writeAction)
    {
        var bufferWriter = new ArrayBufferWriter<byte>();
        var writer = new SpanWriter(bufferWriter);
        writeAction(ref writer);
        writer.Commit();
        return bufferWriter.WrittenSpan.ToArray();
    }

    private static T RoundTrip<T>(WriteDelegate writeAction, ReadDelegate<T> readAction)
    {
        var data = WriteToBuffer(writeAction);
        var reader = new SpanReader(data);
        return readAction(ref reader);
    }

    // ─── Byte ────────────────────────────────────────────────────

    [Theory]
    [InlineData((byte)0)]
    [InlineData((byte)1)]
    [InlineData(byte.MaxValue)]
    [InlineData((byte)127)]
    public void RoundTrip_Byte(byte value)
    {
        // Act
        var result = RoundTrip<byte>(
            (ref SpanWriter w) => w.WriteByte(value),
            (ref SpanReader r) => r.ReadByte());

        // Assert
        Assert.Equal(value, result);
    }

    // ─── SByte ───────────────────────────────────────────────────

    [Theory]
    [InlineData((sbyte)0)]
    [InlineData((sbyte)-1)]
    [InlineData(sbyte.MinValue)]
    [InlineData(sbyte.MaxValue)]
    public void RoundTrip_SByte(sbyte value)
    {
        // Act
        var result = RoundTrip<sbyte>(
            (ref SpanWriter w) => w.WriteSByte(value),
            (ref SpanReader r) => r.ReadSByte());

        // Assert
        Assert.Equal(value, result);
    }

    // ─── Boolean ─────────────────────────────────────────────────

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void RoundTrip_Boolean(bool value)
    {
        // Act
        var result = RoundTrip<bool>(
            (ref SpanWriter w) => w.WriteBoolean(value),
            (ref SpanReader r) => r.ReadBoolean());

        // Assert
        Assert.Equal(value, result);
    }

    [Fact]
    public void ReadBoolean_NonZeroByte_ReturnsTrue()
    {
        // Arrange
        var data = new byte[] { 42 };
        var reader = new SpanReader(data);

        // Act
        var result = reader.ReadBoolean();

        // Assert
        Assert.True(result);
    }

    // ─── Int16 ───────────────────────────────────────────────────

    [Theory]
    [InlineData((short)0)]
    [InlineData((short)1)]
    [InlineData((short)-1)]
    [InlineData(short.MinValue)]
    [InlineData(short.MaxValue)]
    public void RoundTrip_Int16(short value)
    {
        // Act
        var result = RoundTrip<short>(
            (ref SpanWriter w) => w.WriteInt16(value),
            (ref SpanReader r) => r.ReadInt16());

        // Assert
        Assert.Equal(value, result);
    }

    // ─── UInt16 ──────────────────────────────────────────────────

    [Theory]
    [InlineData((ushort)0)]
    [InlineData((ushort)1)]
    [InlineData(ushort.MaxValue)]
    public void RoundTrip_UInt16(ushort value)
    {
        // Act
        var result = RoundTrip<ushort>(
            (ref SpanWriter w) => w.WriteUInt16(value),
            (ref SpanReader r) => r.ReadUInt16());

        // Assert
        Assert.Equal(value, result);
    }

    // ─── Int32 ───────────────────────────────────────────────────

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    [InlineData(int.MaxValue)]
    [InlineData(42)]
    public void RoundTrip_Int32(int value)
    {
        // Act
        var result = RoundTrip<int>(
            (ref SpanWriter w) => w.WriteInt32(value),
            (ref SpanReader r) => r.ReadInt32());

        // Assert
        Assert.Equal(value, result);
    }

    // ─── UInt32 ──────────────────────────────────────────────────

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(uint.MaxValue)]
    public void RoundTrip_UInt32(uint value)
    {
        // Act
        var result = RoundTrip<uint>(
            (ref SpanWriter w) => w.WriteUInt32(value),
            (ref SpanReader r) => r.ReadUInt32());

        // Assert
        Assert.Equal(value, result);
    }

    // ─── Int64 ───────────────────────────────────────────────────

    [Theory]
    [InlineData(0L)]
    [InlineData(1L)]
    [InlineData(-1L)]
    [InlineData(long.MinValue)]
    [InlineData(long.MaxValue)]
    public void RoundTrip_Int64(long value)
    {
        // Act
        var result = RoundTrip<long>(
            (ref SpanWriter w) => w.WriteInt64(value),
            (ref SpanReader r) => r.ReadInt64());

        // Assert
        Assert.Equal(value, result);
    }

    // ─── UInt64 ──────────────────────────────────────────────────

    [Theory]
    [InlineData(0uL)]
    [InlineData(1uL)]
    [InlineData(ulong.MaxValue)]
    public void RoundTrip_UInt64(ulong value)
    {
        // Act
        var result = RoundTrip<ulong>(
            (ref SpanWriter w) => w.WriteUInt64(value),
            (ref SpanReader r) => r.ReadUInt64());

        // Assert
        Assert.Equal(value, result);
    }

    // ─── Float (Single) ─────────────────────────────────────────

    [Fact]
    public void RoundTrip_Single_Zero()
    {
        var result = RoundTrip<float>(
            (ref SpanWriter w) => w.WriteSingle(0f),
            (ref SpanReader r) => r.ReadSingle());
        Assert.Equal(0f, result);
    }

    [Fact]
    public void RoundTrip_Single_Negative()
    {
        var result = RoundTrip<float>(
            (ref SpanWriter w) => w.WriteSingle(-3.14f),
            (ref SpanReader r) => r.ReadSingle());
        Assert.Equal(-3.14f, result);
    }

    [Fact]
    public void RoundTrip_Single_MaxValue()
    {
        var result = RoundTrip<float>(
            (ref SpanWriter w) => w.WriteSingle(float.MaxValue),
            (ref SpanReader r) => r.ReadSingle());
        Assert.Equal(float.MaxValue, result);
    }

    [Fact]
    public void RoundTrip_Single_MinValue()
    {
        var result = RoundTrip<float>(
            (ref SpanWriter w) => w.WriteSingle(float.MinValue),
            (ref SpanReader r) => r.ReadSingle());
        Assert.Equal(float.MinValue, result);
    }

    [Fact]
    public void RoundTrip_Single_Epsilon()
    {
        var result = RoundTrip<float>(
            (ref SpanWriter w) => w.WriteSingle(float.Epsilon),
            (ref SpanReader r) => r.ReadSingle());
        Assert.Equal(float.Epsilon, result);
    }

    [Fact]
    public void RoundTrip_Single_NaN()
    {
        var result = RoundTrip<float>(
            (ref SpanWriter w) => w.WriteSingle(float.NaN),
            (ref SpanReader r) => r.ReadSingle());
        Assert.True(float.IsNaN(result));
    }

    [Fact]
    public void RoundTrip_Single_PositiveInfinity()
    {
        var result = RoundTrip<float>(
            (ref SpanWriter w) => w.WriteSingle(float.PositiveInfinity),
            (ref SpanReader r) => r.ReadSingle());
        Assert.Equal(float.PositiveInfinity, result);
    }

    // ─── Double ──────────────────────────────────────────────────

    [Fact]
    public void RoundTrip_Double_Zero()
    {
        var result = RoundTrip<double>(
            (ref SpanWriter w) => w.WriteDouble(0.0),
            (ref SpanReader r) => r.ReadDouble());
        Assert.Equal(0.0, result);
    }

    [Fact]
    public void RoundTrip_Double_Negative()
    {
        var result = RoundTrip<double>(
            (ref SpanWriter w) => w.WriteDouble(-2.718281828459045),
            (ref SpanReader r) => r.ReadDouble());
        Assert.Equal(-2.718281828459045, result);
    }

    [Fact]
    public void RoundTrip_Double_MaxValue()
    {
        var result = RoundTrip<double>(
            (ref SpanWriter w) => w.WriteDouble(double.MaxValue),
            (ref SpanReader r) => r.ReadDouble());
        Assert.Equal(double.MaxValue, result);
    }

    [Fact]
    public void RoundTrip_Double_MinValue()
    {
        var result = RoundTrip<double>(
            (ref SpanWriter w) => w.WriteDouble(double.MinValue),
            (ref SpanReader r) => r.ReadDouble());
        Assert.Equal(double.MinValue, result);
    }

    [Fact]
    public void RoundTrip_Double_NaN()
    {
        var result = RoundTrip<double>(
            (ref SpanWriter w) => w.WriteDouble(double.NaN),
            (ref SpanReader r) => r.ReadDouble());
        Assert.True(double.IsNaN(result));
    }

    // ─── Decimal ─────────────────────────────────────────────────

    [Fact]
    public void RoundTrip_Decimal_Zero()
    {
        var result = RoundTrip<decimal>(
            (ref SpanWriter w) => w.WriteDecimal(0m),
            (ref SpanReader r) => r.ReadDecimal());
        Assert.Equal(0m, result);
    }

    [Fact]
    public void RoundTrip_Decimal_Positive()
    {
        var result = RoundTrip<decimal>(
            (ref SpanWriter w) => w.WriteDecimal(123456.789m),
            (ref SpanReader r) => r.ReadDecimal());
        Assert.Equal(123456.789m, result);
    }

    [Fact]
    public void RoundTrip_Decimal_Negative()
    {
        var result = RoundTrip<decimal>(
            (ref SpanWriter w) => w.WriteDecimal(-99999.99m),
            (ref SpanReader r) => r.ReadDecimal());
        Assert.Equal(-99999.99m, result);
    }

    [Fact]
    public void RoundTrip_Decimal_MaxValue()
    {
        var result = RoundTrip<decimal>(
            (ref SpanWriter w) => w.WriteDecimal(decimal.MaxValue),
            (ref SpanReader r) => r.ReadDecimal());
        Assert.Equal(decimal.MaxValue, result);
    }

    [Fact]
    public void RoundTrip_Decimal_MinValue()
    {
        var result = RoundTrip<decimal>(
            (ref SpanWriter w) => w.WriteDecimal(decimal.MinValue),
            (ref SpanReader r) => r.ReadDecimal());
        Assert.Equal(decimal.MinValue, result);
    }

    [Fact]
    public void RoundTrip_Decimal_One()
    {
        var result = RoundTrip<decimal>(
            (ref SpanWriter w) => w.WriteDecimal(decimal.One),
            (ref SpanReader r) => r.ReadDecimal());
        Assert.Equal(decimal.One, result);
    }

    [Fact]
    public void RoundTrip_Decimal_MinusOne()
    {
        var result = RoundTrip<decimal>(
            (ref SpanWriter w) => w.WriteDecimal(decimal.MinusOne),
            (ref SpanReader r) => r.ReadDecimal());
        Assert.Equal(decimal.MinusOne, result);
    }

    // ─── Char ────────────────────────────────────────────────────

    [Theory]
    [InlineData('A')]
    [InlineData('z')]
    [InlineData('\0')]
    [InlineData('\uFFFF')]
    [InlineData('€')]
    public void RoundTrip_Char(char value)
    {
        // Act
        var result = RoundTrip<char>(
            (ref SpanWriter w) => w.WriteChar(value),
            (ref SpanReader r) => r.ReadChar());

        // Assert
        Assert.Equal(value, result);
    }

    // ─── Bytes ───────────────────────────────────────────────────

    [Fact]
    public void RoundTrip_Bytes_NonEmpty()
    {
        // Arrange
        var original = new byte[] { 0x01, 0x02, 0x03, 0xFF, 0x00, 0xAB };

        // Act
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteBytes(original));
        var reader = new SpanReader(data);
        var result = new byte[original.Length];
        reader.ReadBytes(result);

        // Assert
        Assert.Equal(original, result);
    }

    [Fact]
    public void RoundTrip_Bytes_Empty()
    {
        // Arrange
        var original = Array.Empty<byte>();

        // Act
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteBytes(original));
        var reader = new SpanReader(data);
        var result = new byte[0];
        reader.ReadBytes(result);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void RoundTrip_Bytes_LargePayload()
    {
        // Arrange
        var original = new byte[8192];
        new Random(42).NextBytes(original);

        // Act
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteBytes(original));
        var reader = new SpanReader(data);
        var result = new byte[original.Length];
        reader.ReadBytes(result);

        // Assert
        Assert.Equal(original, result);
    }

    // ─── Multiple values in sequence ─────────────────────────────

    [Fact]
    public void RoundTrip_MultipleValues_InSequence()
    {
        // Arrange & Act
        var data = WriteToBuffer((ref SpanWriter w) =>
        {
            w.WriteInt32(42);
            w.WriteBoolean(true);
            w.WriteInt64(long.MaxValue);
            w.WriteDouble(3.14);
            w.WriteByte(0xFF);
            w.WriteChar('Z');
            w.WriteDecimal(99.99m);
        });

        var reader = new SpanReader(data);

        // Assert
        Assert.Equal(42, reader.ReadInt32());
        Assert.True(reader.ReadBoolean());
        Assert.Equal(long.MaxValue, reader.ReadInt64());
        Assert.Equal(3.14, reader.ReadDouble());
        Assert.Equal(0xFF, reader.ReadByte());
        Assert.Equal('Z', reader.ReadChar());
        Assert.Equal(99.99m, reader.ReadDecimal());
    }

    [Fact]
    public void RoundTrip_AllPrimitiveTypes_InSequence()
    {
        // Arrange
        var bytes = new byte[] { 0xDE, 0xAD };

        var data = WriteToBuffer((ref SpanWriter w) =>
        {
            w.WriteByte(0xAB);
            w.WriteSByte(-100);
            w.WriteBoolean(false);
            w.WriteInt16(-12345);
            w.WriteUInt16(54321);
            w.WriteInt32(int.MinValue);
            w.WriteUInt32(uint.MaxValue);
            w.WriteInt64(long.MinValue);
            w.WriteUInt64(ulong.MaxValue);
            w.WriteSingle(1.5f);
            w.WriteDouble(2.5);
            w.WriteDecimal(decimal.MinValue);
            w.WriteChar('€');
            w.WriteBytes(bytes);
        });

        // Act
        var reader = new SpanReader(data);

        // Assert
        Assert.Equal(0xAB, reader.ReadByte());
        Assert.Equal((sbyte)-100, reader.ReadSByte());
        Assert.False(reader.ReadBoolean());
        Assert.Equal((short)-12345, reader.ReadInt16());
        Assert.Equal((ushort)54321, reader.ReadUInt16());
        Assert.Equal(int.MinValue, reader.ReadInt32());
        Assert.Equal(uint.MaxValue, reader.ReadUInt32());
        Assert.Equal(long.MinValue, reader.ReadInt64());
        Assert.Equal(ulong.MaxValue, reader.ReadUInt64());
        Assert.Equal(1.5f, reader.ReadSingle());
        Assert.Equal(2.5, reader.ReadDouble());
        Assert.Equal(decimal.MinValue, reader.ReadDecimal());
        Assert.Equal('€', reader.ReadChar());
        var resultBytes = new byte[2];
        reader.ReadBytes(resultBytes);
        Assert.Equal(bytes, resultBytes);
    }

    // ─── Buffer overflow / EndOfStreamException ──────────────────

    [Fact]
    public void ReadByte_EmptyBuffer_ThrowsEndOfStreamException()
    {
        // Arrange
        var reader = new SpanReader(ReadOnlySpan<byte>.Empty);

        // Act & Assert
        try
        {
            reader.ReadByte();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadInt32_InsufficientBuffer_ThrowsEndOfStreamException()
    {
        // Arrange
        var data = new byte[] { 0x01, 0x02 };
        var reader = new SpanReader(data);

        // Act & Assert
        try
        {
            reader.ReadInt32();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadInt64_InsufficientBuffer_ThrowsEndOfStreamException()
    {
        // Arrange
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var reader = new SpanReader(data);

        // Act & Assert
        try
        {
            reader.ReadInt64();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadInt16_InsufficientBuffer_ThrowsEndOfStreamException()
    {
        // Arrange
        var data = new byte[] { 0x01 };
        var reader = new SpanReader(data);

        // Act & Assert
        try
        {
            reader.ReadInt16();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadDouble_InsufficientBuffer_ThrowsEndOfStreamException()
    {
        // Arrange
        var data = new byte[] { 0x01, 0x02, 0x03 };
        var reader = new SpanReader(data);

        // Act & Assert
        try
        {
            reader.ReadDouble();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadDecimal_InsufficientBuffer_ThrowsEndOfStreamException()
    {
        // Arrange — decimal needs 16 bytes (4 × int32)
        var data = new byte[12];
        var reader = new SpanReader(data);

        // Act & Assert
        try
        {
            reader.ReadDecimal();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadBytes_InsufficientBuffer_ThrowsEndOfStreamException()
    {
        // Arrange
        var data = new byte[] { 0x01, 0x02 };
        var reader = new SpanReader(data);
        var destination = new byte[5];

        // Act & Assert
        try
        {
            reader.ReadBytes(destination);
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadByte_AfterExhaustingBuffer_ThrowsEndOfStreamException()
    {
        // Arrange
        var data = new byte[] { 0x01 };
        var reader = new SpanReader(data);
        reader.ReadByte(); // consume the only byte

        // Act & Assert
        try
        {
            reader.ReadByte();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    // ─── SpanWriter Commit ───────────────────────────────────────

    [Fact]
    public void Commit_ReturnsCorrectByteCount()
    {
        // Arrange
        var bufferWriter = new ArrayBufferWriter<byte>();
        var writer = new SpanWriter(bufferWriter);

        // Act
        writer.WriteInt32(42);
        writer.WriteBoolean(true);
        writer.WriteInt64(100L);
        var totalWritten = writer.Commit();

        // Assert — 4 (int) + 1 (bool) + 8 (long) = 13
        Assert.Equal(13, totalWritten);
    }

    [Fact]
    public void Commit_CalledTwice_ReturnsSameTotal()
    {
        // Arrange
        var bufferWriter = new ArrayBufferWriter<byte>();
        var writer = new SpanWriter(bufferWriter);

        writer.WriteInt32(1);
        var first = writer.Commit();

        // Act — second commit with nothing new written
        var second = writer.Commit();

        // Assert
        Assert.Equal(4, first);
        Assert.Equal(4, second);
    }

    [Fact]
    public void Commit_NoWrites_ReturnsZero()
    {
        // Arrange
        var bufferWriter = new ArrayBufferWriter<byte>();
        var writer = new SpanWriter(bufferWriter);

        // Act
        var totalWritten = writer.Commit();

        // Assert
        Assert.Equal(0, totalWritten);
    }

    // ─── SpanWriter constructor ──────────────────────────────────

    [Fact]
    public void SpanWriter_NullBufferWriter_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => new SpanWriter(null!));
    }

    // ─── Small buffer forcing flush ──────────────────────────────

    [Fact]
    public void WriteBytes_LargerThanInitialBuffer_Succeeds()
    {
        // Arrange — use a small initial capacity to force internal flush
        var bufferWriter = new ArrayBufferWriter<byte>(initialCapacity: 16);
        var writer = new SpanWriter(bufferWriter);
        var payload = new byte[256];
        new Random(123).NextBytes(payload);

        // Act
        writer.WriteBytes(payload);
        writer.Commit();

        // Assert
        Assert.Equal(payload, bufferWriter.WrittenSpan.ToArray());
    }

    [Fact]
    public void WriteManyValues_SmallBuffer_RoundTripsCorrectly()
    {
        // Arrange — small capacity forces multiple internal flushes
        var bufferWriter = new ArrayBufferWriter<byte>(initialCapacity: 8);
        var writer = new SpanWriter(bufferWriter);

        // Act
        writer.WriteInt32(1);
        writer.WriteInt32(2);
        writer.WriteInt32(3);
        writer.WriteInt64(long.MaxValue);
        writer.WriteDouble(Math.PI);
        writer.Commit();

        var reader = new SpanReader(bufferWriter.WrittenSpan);

        // Assert
        Assert.Equal(1, reader.ReadInt32());
        Assert.Equal(2, reader.ReadInt32());
        Assert.Equal(3, reader.ReadInt32());
        Assert.Equal(long.MaxValue, reader.ReadInt64());
        Assert.Equal(Math.PI, reader.ReadDouble());
    }

    // ─── Encoding correctness (little-endian) ────────────────────

    [Fact]
    public void WriteInt32_UsesLittleEndianEncoding()
    {
        // Arrange
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteInt32(0x04030201));

        // Assert — little-endian: least significant byte first
        Assert.Equal(4, data.Length);
        Assert.Equal(0x01, data[0]);
        Assert.Equal(0x02, data[1]);
        Assert.Equal(0x03, data[2]);
        Assert.Equal(0x04, data[3]);
    }

    [Fact]
    public void WriteInt16_UsesLittleEndianEncoding()
    {
        // Arrange
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteInt16(0x0201));

        // Assert
        Assert.Equal(2, data.Length);
        Assert.Equal(0x01, data[0]);
        Assert.Equal(0x02, data[1]);
    }

    [Fact]
    public void WriteInt64_UsesLittleEndianEncoding()
    {
        // Arrange
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteInt64(0x0807060504030201));

        // Assert
        Assert.Equal(8, data.Length);
        Assert.Equal(0x01, data[0]);
        Assert.Equal(0x08, data[7]);
    }

    // ─── Written data size correctness ───────────────────────────

    [Fact]
    public void WriteByte_ProducesOneByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteByte(0xAA));
        Assert.Single(data);
    }

    [Fact]
    public void WriteBoolean_ProducesOneByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteBoolean(true));
        Assert.Single(data);
    }

    [Fact]
    public void WriteInt16_ProducesTwoByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteInt16(1));
        Assert.Equal(2, data.Length);
    }

    [Fact]
    public void WriteInt32_ProducesFourByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteInt32(1));
        Assert.Equal(4, data.Length);
    }

    [Fact]
    public void WriteInt64_ProducesEightByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteInt64(1));
        Assert.Equal(8, data.Length);
    }

    [Fact]
    public void WriteSingle_ProducesFourByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteSingle(1.0f));
        Assert.Equal(4, data.Length);
    }

    [Fact]
    public void WriteDouble_ProducesEightByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteDouble(1.0));
        Assert.Equal(8, data.Length);
    }

    [Fact]
    public void WriteDecimal_ProducesSixteenByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteDecimal(1.0m));
        Assert.Equal(16, data.Length);
    }

    [Fact]
    public void WriteChar_ProducesTwoByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteChar('A'));
        Assert.Equal(2, data.Length);
    }

    // ─── Additional buffer underflow / overflow tests ────────────

    [Fact]
    public void ReadSByte_EmptyBuffer_ThrowsEndOfStreamException()
    {
        var reader = new SpanReader(ReadOnlySpan<byte>.Empty);
        try
        {
            reader.ReadSByte();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadBoolean_EmptyBuffer_ThrowsEndOfStreamException()
    {
        var reader = new SpanReader(ReadOnlySpan<byte>.Empty);
        try
        {
            reader.ReadBoolean();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadUInt16_InsufficientBuffer_ThrowsEndOfStreamException()
    {
        var data = new byte[] { 0x01 };
        var reader = new SpanReader(data);
        try
        {
            reader.ReadUInt16();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadUInt32_InsufficientBuffer_ThrowsEndOfStreamException()
    {
        var data = new byte[] { 0x01, 0x02 };
        var reader = new SpanReader(data);
        try
        {
            reader.ReadUInt32();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadUInt64_InsufficientBuffer_ThrowsEndOfStreamException()
    {
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var reader = new SpanReader(data);
        try
        {
            reader.ReadUInt64();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadSingle_InsufficientBuffer_ThrowsEndOfStreamException()
    {
        var data = new byte[] { 0x01, 0x02 };
        var reader = new SpanReader(data);
        try
        {
            reader.ReadSingle();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadChar_InsufficientBuffer_ThrowsEndOfStreamException()
    {
        var data = new byte[] { 0x01 };
        var reader = new SpanReader(data);
        try
        {
            reader.ReadChar();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    [Fact]
    public void ReadInt32_AfterPartialRead_ThrowsEndOfStreamException()
    {
        // Arrange — 5 bytes: read 1 byte, then try to read Int32 (needs 4 but only 4 remain... 
        // use 4 bytes total: read 1, then 3 remain which is insufficient)
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var reader = new SpanReader(data);
        reader.ReadByte(); // consume 1, leaving 3

        try
        {
            reader.ReadInt32();
            Assert.Fail("Expected EndOfStreamException");
        }
        catch (EndOfStreamException) { }
    }

    // ─── Additional endianness tests ─────────────────────────────

    [Fact]
    public void WriteUInt16_UsesLittleEndianEncoding()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteUInt16(0x0201));

        Assert.Equal(2, data.Length);
        Assert.Equal(0x01, data[0]);
        Assert.Equal(0x02, data[1]);
    }

    [Fact]
    public void WriteUInt32_UsesLittleEndianEncoding()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteUInt32(0x04030201));

        Assert.Equal(4, data.Length);
        Assert.Equal(0x01, data[0]);
        Assert.Equal(0x02, data[1]);
        Assert.Equal(0x03, data[2]);
        Assert.Equal(0x04, data[3]);
    }

    [Fact]
    public void WriteUInt64_UsesLittleEndianEncoding()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteUInt64(0x0807060504030201));

        Assert.Equal(8, data.Length);
        Assert.Equal(0x01, data[0]);
        Assert.Equal(0x02, data[1]);
        Assert.Equal(0x03, data[2]);
        Assert.Equal(0x04, data[3]);
        Assert.Equal(0x05, data[4]);
        Assert.Equal(0x06, data[5]);
        Assert.Equal(0x07, data[6]);
        Assert.Equal(0x08, data[7]);
    }

    [Fact]
    public void WriteChar_UsesLittleEndianEncoding()
    {
        // 'A' is 0x0041
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteChar('A'));

        Assert.Equal(2, data.Length);
        Assert.Equal(0x41, data[0]);
        Assert.Equal(0x00, data[1]);
    }

    // ─── Additional float/double edge cases ──────────────────────

    [Fact]
    public void RoundTrip_Single_NegativeInfinity()
    {
        var result = RoundTrip<float>(
            (ref SpanWriter w) => w.WriteSingle(float.NegativeInfinity),
            (ref SpanReader r) => r.ReadSingle());
        Assert.Equal(float.NegativeInfinity, result);
    }

    [Fact]
    public void RoundTrip_Single_NegativeZero()
    {
        var result = RoundTrip<float>(
            (ref SpanWriter w) => w.WriteSingle(-0.0f),
            (ref SpanReader r) => r.ReadSingle());
        Assert.True(float.IsNegative(result) && result == 0f);
    }

    [Fact]
    public void RoundTrip_Double_NegativeInfinity()
    {
        var result = RoundTrip<double>(
            (ref SpanWriter w) => w.WriteDouble(double.NegativeInfinity),
            (ref SpanReader r) => r.ReadDouble());
        Assert.Equal(double.NegativeInfinity, result);
    }

    [Fact]
    public void RoundTrip_Double_PositiveInfinity()
    {
        var result = RoundTrip<double>(
            (ref SpanWriter w) => w.WriteDouble(double.PositiveInfinity),
            (ref SpanReader r) => r.ReadDouble());
        Assert.Equal(double.PositiveInfinity, result);
    }

    [Fact]
    public void RoundTrip_Double_Epsilon()
    {
        var result = RoundTrip<double>(
            (ref SpanWriter w) => w.WriteDouble(double.Epsilon),
            (ref SpanReader r) => r.ReadDouble());
        Assert.Equal(double.Epsilon, result);
    }

    [Fact]
    public void RoundTrip_Double_NegativeZero()
    {
        var result = RoundTrip<double>(
            (ref SpanWriter w) => w.WriteDouble(-0.0),
            (ref SpanReader r) => r.ReadDouble());
        Assert.True(double.IsNegative(result) && result == 0.0);
    }

    // ─── Additional decimal edge cases ───────────────────────────

    [Fact]
    public void RoundTrip_Decimal_HighPrecision()
    {
        var value = 1.0000000000000000000000000001m;
        var result = RoundTrip<decimal>(
            (ref SpanWriter w) => w.WriteDecimal(value),
            (ref SpanReader r) => r.ReadDecimal());
        Assert.Equal(value, result);
    }

    [Fact]
    public void RoundTrip_Decimal_SmallFraction()
    {
        var value = 0.0000001m;
        var result = RoundTrip<decimal>(
            (ref SpanWriter w) => w.WriteDecimal(value),
            (ref SpanReader r) => r.ReadDecimal());
        Assert.Equal(value, result);
    }

    // ─── Boolean raw byte encoding ───────────────────────────────

    [Fact]
    public void WriteBoolean_True_WritesOne()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteBoolean(true));
        Assert.Equal(1, data[0]);
    }

    [Fact]
    public void WriteBoolean_False_WritesZero()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteBoolean(false));
        Assert.Equal(0, data[0]);
    }

    // ─── SByte raw encoding ──────────────────────────────────────

    [Fact]
    public void WriteSByte_NegativeOne_WritesFF()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteSByte(-1));
        Assert.Equal(0xFF, data[0]);
    }

    [Fact]
    public void WriteSByte_MinValue_Writes80()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteSByte(sbyte.MinValue));
        Assert.Equal(0x80, data[0]);
    }

    // ─── Bytes edge cases ────────────────────────────────────────

    [Fact]
    public void RoundTrip_Bytes_SingleByte()
    {
        var original = new byte[] { 0x42 };

        var data = WriteToBuffer((ref SpanWriter w) => w.WriteBytes(original));
        var reader = new SpanReader(data);
        var result = new byte[1];
        reader.ReadBytes(result);

        Assert.Equal(original, result);
    }

    [Fact]
    public void RoundTrip_Bytes_AllZeros()
    {
        var original = new byte[16];

        var data = WriteToBuffer((ref SpanWriter w) => w.WriteBytes(original));
        var reader = new SpanReader(data);
        var result = new byte[16];
        reader.ReadBytes(result);

        Assert.Equal(original, result);
    }

    [Fact]
    public void RoundTrip_Bytes_AllOnes()
    {
        var original = Enumerable.Repeat((byte)0xFF, 32).ToArray();

        var data = WriteToBuffer((ref SpanWriter w) => w.WriteBytes(original));
        var reader = new SpanReader(data);
        var result = new byte[32];
        reader.ReadBytes(result);

        Assert.Equal(original, result);
    }

    // ─── Commit accumulation ─────────────────────────────────────

    [Fact]
    public void Commit_MultipleWrites_AccumulatesTotal()
    {
        var bufferWriter = new ArrayBufferWriter<byte>();
        var writer = new SpanWriter(bufferWriter);

        writer.WriteInt32(1);
        var first = writer.Commit(); // 4 bytes

        writer.WriteByte(0x01);
        writer.WriteByte(0x02);
        var second = writer.Commit(); // 4 + 2 = 6

        Assert.Equal(4, first);
        Assert.Equal(6, second);
    }

    // ─── ReadBytes after partial reads (offset correctness) ──────

    [Fact]
    public void ReadBytes_AfterReadingPrimitive_ReadsFromCorrectOffset()
    {
        var data = WriteToBuffer((ref SpanWriter w) =>
        {
            w.WriteInt32(42);
            w.WriteBytes(new byte[] { 0xAA, 0xBB, 0xCC });
        });

        var reader = new SpanReader(data);
        var intValue = reader.ReadInt32();
        var bytes = new byte[3];
        reader.ReadBytes(bytes);

        Assert.Equal(42, intValue);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, bytes);
    }

    // ─── WriteSingle/WriteDouble endianness consistency ──────────

    [Fact]
    public void WriteSingle_EndiannessConsistentWithInt32()
    {
        // Writing a float should produce same bytes as writing its Int32 bit pattern
        var value = 1.5f;
        var floatData = WriteToBuffer((ref SpanWriter w) => w.WriteSingle(value));
        var intData = WriteToBuffer((ref SpanWriter w) => w.WriteInt32(BitConverter.SingleToInt32Bits(value)));

        Assert.Equal(intData, floatData);
    }

    [Fact]
    public void WriteDouble_EndiannessConsistentWithInt64()
    {
        var value = 2.5;
        var doubleData = WriteToBuffer((ref SpanWriter w) => w.WriteDouble(value));
        var longData = WriteToBuffer((ref SpanWriter w) => w.WriteInt64(BitConverter.DoubleToInt64Bits(value)));

        Assert.Equal(longData, doubleData);
    }

    // ─── Decimal endianness consistency ──────────────────────────

    [Fact]
    public void WriteDecimal_EndiannessConsistentWithInt32Components()
    {
        var value = 12345.6789m;
        var bits = decimal.GetBits(value);
        var decimalData = WriteToBuffer((ref SpanWriter w) => w.WriteDecimal(value));
        var componentData = WriteToBuffer((ref SpanWriter w) =>
        {
            w.WriteInt32(bits[0]);
            w.WriteInt32(bits[1]);
            w.WriteInt32(bits[2]);
            w.WriteInt32(bits[3]);
        });

        Assert.Equal(componentData, decimalData);
    }

    // ─── UInt16/UInt32/UInt64 output size ────────────────────────

    [Fact]
    public void WriteUInt16_ProducesTwoByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteUInt16(1));
        Assert.Equal(2, data.Length);
    }

    [Fact]
    public void WriteUInt32_ProducesFourByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteUInt32(1));
        Assert.Equal(4, data.Length);
    }

    [Fact]
    public void WriteUInt64_ProducesEightByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteUInt64(1));
        Assert.Equal(8, data.Length);
    }

    [Fact]
    public void WriteSByte_ProducesOneByteOutput()
    {
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteSByte(1));
        Assert.Single(data);
    }

    // ─── Small buffer writer forcing Ensure flush ────────────────

    [Fact]
    public void WriteInt32_SmallBuffer_ForcesFlushAndSucceeds()
    {
        var bufferWriter = new ArrayBufferWriter<byte>(initialCapacity: 2);
        var writer = new SpanWriter(bufferWriter);

        writer.WriteInt32(42);
        writer.Commit();

        var reader = new SpanReader(bufferWriter.WrittenSpan);
        Assert.Equal(42, reader.ReadInt32());
    }

    [Fact]
    public void WriteInt64_SmallBuffer_ForcesFlushAndSucceeds()
    {
        var bufferWriter = new ArrayBufferWriter<byte>(initialCapacity: 4);
        var writer = new SpanWriter(bufferWriter);

        writer.WriteInt64(long.MinValue);
        writer.Commit();

        var reader = new SpanReader(bufferWriter.WrittenSpan);
        Assert.Equal(long.MinValue, reader.ReadInt64());
    }

    [Fact]
    public void WriteDecimal_SmallBuffer_ForcesFlushAndSucceeds()
    {
        var bufferWriter = new ArrayBufferWriter<byte>(initialCapacity: 4);
        var writer = new SpanWriter(bufferWriter);

        writer.WriteDecimal(decimal.MaxValue);
        writer.Commit();

        var reader = new SpanReader(bufferWriter.WrittenSpan);
        Assert.Equal(decimal.MaxValue, reader.ReadDecimal());
    }

    // ─── Exact buffer boundary ───────────────────────────────────

    [Fact]
    public void ReadInt32_ExactBufferSize_Succeeds()
    {
        var data = new byte[] { 0x01, 0x00, 0x00, 0x00 };
        var reader = new SpanReader(data);

        var result = reader.ReadInt32();

        Assert.Equal(1, result);
    }

    [Fact]
    public void ReadInt64_ExactBufferSize_Succeeds()
    {
        var data = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        var reader = new SpanReader(data);

        var result = reader.ReadInt64();

        Assert.Equal(1L, result);
    }

    [Fact]
    public void ReadDecimal_ExactBufferSize_Succeeds()
    {
        // Write a decimal and verify we can read it with exact-size buffer
        var data = WriteToBuffer((ref SpanWriter w) => w.WriteDecimal(1.0m));

        Assert.Equal(16, data.Length);
        var reader = new SpanReader(data);
        var result = reader.ReadDecimal();
        Assert.Equal(1.0m, result);
    }
}
