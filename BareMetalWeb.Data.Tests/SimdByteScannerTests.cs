using System;
using System.Text;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Validates that <see cref="SimdByteScanner.FindByte"/> produces correct results
/// across all buffer sizes (including those that exercise the SIMD and tail scalar paths)
/// and across all supported hardware-acceleration paths.
/// </summary>
public sealed class SimdByteScannerTests
{
    // ─── Empty / trivial inputs ───────────────────────────────────────────────

    [Fact]
    public void FindByte_EmptySpan_ReturnsMinusOne()
    {
        int result = SimdByteScanner.FindByte(ReadOnlySpan<byte>.Empty, 0x7B);
        Assert.Equal(-1, result);
    }

    [Fact]
    public void FindByte_SingleByteMatch_ReturnsZero()
    {
        ReadOnlySpan<byte> data = [(byte)'{'];
        Assert.Equal(0, SimdByteScanner.FindByte(data, (byte)'{'));
    }

    [Fact]
    public void FindByte_SingleByteNoMatch_ReturnsMinusOne()
    {
        ReadOnlySpan<byte> data = [(byte)'A'];
        Assert.Equal(-1, SimdByteScanner.FindByte(data, (byte)'{'));
    }

    // ─── Small buffers (scalar path) ──────────────────────────────────────────

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(15)]
    [InlineData(31)]
    public void FindByte_TargetAtStart_SmallBuffer_ReturnsZero(int paddingAfter)
    {
        byte[] data = new byte[1 + paddingAfter];
        data[0] = 0x7B;
        Assert.Equal(0, SimdByteScanner.FindByte(data, 0x7B));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(15)]
    [InlineData(31)]
    public void FindByte_TargetAtEnd_SmallBuffer_ReturnsLastIndex(int size)
    {
        byte[] data = new byte[size];
        data[size - 1] = 0x7B;
        Assert.Equal(size - 1, SimdByteScanner.FindByte(data, 0x7B));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(31)]
    public void FindByte_NoMatch_SmallBuffer_ReturnsMinusOne(int size)
    {
        byte[] data = new byte[size]; // all zeros
        Assert.Equal(-1, SimdByteScanner.FindByte(data, 0x7B));
    }

    // ─── Large buffers (exercises AVX2 / AdvSimd / Vector<byte> paths) ────────

    [Theory]
    [InlineData(32)]
    [InlineData(33)]
    [InlineData(64)]
    [InlineData(127)]
    [InlineData(128)]
    [InlineData(1024)]
    [InlineData(4096)]
    [InlineData(1_000_000)]
    public void FindByte_TargetAtStart_LargeBuffer_ReturnsZero(int size)
    {
        byte[] data = new byte[size];
        data[0] = 0x7B;
        Assert.Equal(0, SimdByteScanner.FindByte(data, 0x7B));
    }

    [Theory]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(100)]
    [InlineData(1024)]
    [InlineData(1_000_001)]
    public void FindByte_TargetAtEnd_LargeBuffer_ReturnsLastIndex(int size)
    {
        byte[] data = new byte[size];
        data[size - 1] = 0x7B;
        Assert.Equal(size - 1, SimdByteScanner.FindByte(data, 0x7B));
    }

    [Theory]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(1024)]
    [InlineData(1_000_000)]
    public void FindByte_NoMatch_LargeBuffer_ReturnsMinusOne(int size)
    {
        byte[] data = new byte[size]; // all zeros; target is 0x7B
        Assert.Equal(-1, SimdByteScanner.FindByte(data, 0x7B));
    }

    // ─── Position correctness across chunk boundaries ─────────────────────────

    [Theory]
    [InlineData(31)]   // last byte of first 32-byte AVX2 chunk
    [InlineData(32)]   // first byte of second AVX2 chunk
    [InlineData(63)]   // last of second chunk
    [InlineData(64)]   // first of third chunk
    [InlineData(99)]   // mid-way
    [InlineData(255)]
    public void FindByte_TargetAtSpecificPosition_ReturnsCorrectIndex(int targetPos)
    {
        int size = targetPos + 1 + 64; // ensure buffer extends well past target
        byte[] data = new byte[size];  // all zeros
        data[targetPos] = 0x7B;

        Assert.Equal(targetPos, SimdByteScanner.FindByte(data, 0x7B));
    }

    // ─── Returns FIRST occurrence when multiple matches exist ─────────────────

    [Fact]
    public void FindByte_MultipleMatches_ReturnsFirstIndex()
    {
        byte[] data = new byte[200];
        data[50]  = 0x7B;
        data[100] = 0x7B;
        data[150] = 0x7B;
        Assert.Equal(50, SimdByteScanner.FindByte(data, 0x7B));
    }

    [Fact]
    public void FindByte_AllBytesMatch_ReturnsZero()
    {
        byte[] data = new byte[128];
        Array.Fill(data, (byte)0xFF);
        Assert.Equal(0, SimdByteScanner.FindByte(data, 0xFF));
    }

    // ─── Boundary: target byte == 0x00 ───────────────────────────────────────

    [Fact]
    public void FindByte_ZeroTarget_FoundInBuffer_ReturnsCorrectIndex()
    {
        // Buffer filled with 0x01, with one 0x00 at position 40.
        byte[] data = new byte[100];
        Array.Fill(data, (byte)1);
        data[40] = 0x00;
        Assert.Equal(40, SimdByteScanner.FindByte(data, 0x00));
    }

    // ─── Tail handling: buffer sizes not divisible by vector width ────────────

    [Theory]
    [InlineData(33, 32)]  // 33-byte buffer, target in tail byte (index 32)
    [InlineData(65, 64)]  // 65-byte buffer, target in tail
    [InlineData(17, 16)]  // 17-byte buffer
    public void FindByte_TargetInTailAfterFullChunks_ReturnsCorrectIndex(int size, int targetPos)
    {
        byte[] data = new byte[size];
        data[targetPos] = 0xAB;
        Assert.Equal(targetPos, SimdByteScanner.FindByte(data, 0xAB));
    }

    // ─── Realistic use case: scanning UTF-8 for ASCII '{' (0x7B) ─────────────

    [Fact]
    public void FindByte_ScanUtf8TemplateForOpenBrace_ReturnsCorrectIndex()
    {
        // UTF-8 encode a short template with {{ tokens.
        string template = new string('A', 50) + "{{token}}" + new string('B', 50);
        byte[] utf8 = Encoding.UTF8.GetBytes(template);

        int idx = SimdByteScanner.FindByte(utf8, (byte)'{');

        Assert.Equal(50, idx); // first '{' is at position 50
    }

    [Fact]
    public void FindByte_ScanUtf8ForOpenBrace_LargeTemplate_ReturnsCorrectIndex()
    {
        // Simulate a large template page with the first token deep in the buffer.
        string prefix = new string(' ', 1024); // 1 KB of spaces before first token
        string template = prefix + "{{title}}";
        byte[] utf8 = Encoding.UTF8.GetBytes(template);

        int idx = SimdByteScanner.FindByte(utf8, (byte)'{');

        Assert.Equal(1024, idx);
    }

    // ─── DataLayerCapabilities reports the byte scanner path ──────────────────

    [Fact]
    public void DataLayerCapabilities_Describe_ContainsByteScannerLine()
    {
        string desc = DataLayerCapabilities.Describe();
        Assert.Contains("Byte scanner", desc);
    }

    [Fact]
    public void SimdByteScanner_ActivePath_IsNotNullOrEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(SimdByteScanner.ActivePath));
    }

    // ─── SpanReader integration ────────────────────────────────────────────────

    [Fact]
    public void SpanReader_IndexOfByte_FindsMarkerInRemainingBuffer()
    {
        byte[] data = [0x01, 0x02, 0x7B, 0x04, 0x05];
        var reader = new SpanReader(data);
        reader.ReadByte(); // advance past 0x01

        int idx = reader.IndexOfByte(0x7B);

        // The marker 0x7B is at absolute position 2; relative to current offset (1) it is 1.
        Assert.Equal(1, idx);
    }

    [Fact]
    public void SpanReader_IndexOfByte_NotFound_ReturnsMinusOne()
    {
        byte[] data = [0x01, 0x02, 0x03];
        var reader = new SpanReader(data);

        Assert.Equal(-1, reader.IndexOfByte(0x7B));
    }

    [Fact]
    public void SpanReader_SkipToMarker_AdvancesToCorrectPosition()
    {
        byte[] data = [0x01, 0x02, 0x7B, 0x04, 0x05];
        var reader = new SpanReader(data);
        reader.SkipToMarker(0x7B);

        // After skipping, the next byte read should be the marker itself.
        byte next = reader.ReadByte();
        Assert.Equal(0x7B, next);
    }

    [Fact]
    public void SpanReader_SkipToMarker_NotFound_AdvancesToEnd()
    {
        byte[] data = [0x01, 0x02, 0x03];
        var reader = new SpanReader(data);
        reader.SkipToMarker(0x7B);

        Assert.Equal(0, reader.Remaining);
    }
}
