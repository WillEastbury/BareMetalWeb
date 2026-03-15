using System.Text;
using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class SafeTensorsReaderTests
{
    // ── BF16 quantisation ─────────────────────────────────────────────────

    [Fact]
    public void QuantiseBf16Row_PositiveValues_ReturnsPlusOne()
    {
        // BF16 +1.0 = 0x3F80 (exp=127, mantissa=0)
        // Little-endian bytes: [0x80, 0x3F]
        var raw = new byte[] { 0x80, 0x3F, 0x80, 0x3F, 0x80, 0x3F };
        var ternary = new sbyte[3];

        SafeTensorsReader.QuantiseRow(raw, ternary, "BF16", 3);

        Assert.Equal((sbyte)1,  ternary[0]);
        Assert.Equal((sbyte)1,  ternary[1]);
        Assert.Equal((sbyte)1,  ternary[2]);
    }

    [Fact]
    public void QuantiseBf16Row_NegativeValues_ReturnsMinusOne()
    {
        // BF16 -1.0 = 0xBF80 → bytes [0x80, 0xBF]
        var raw = new byte[] { 0x80, 0xBF, 0x80, 0xBF };
        var ternary = new sbyte[2];

        SafeTensorsReader.QuantiseRow(raw, ternary, "BF16", 2);

        Assert.Equal((sbyte)-1, ternary[0]);
        Assert.Equal((sbyte)-1, ternary[1]);
    }

    [Fact]
    public void QuantiseBf16Row_ZeroValue_ReturnsZero()
    {
        // BF16 0.0 = 0x0000
        var raw = new byte[] { 0x00, 0x00, 0x00, 0x00 };
        var ternary = new sbyte[2];

        SafeTensorsReader.QuantiseRow(raw, ternary, "BF16", 2);

        Assert.Equal((sbyte)0, ternary[0]);
        Assert.Equal((sbyte)0, ternary[1]);
    }

    [Fact]
    public void QuantiseBf16Row_SubThresholdValue_ReturnsZero()
    {
        // BF16 0.25 = 0x3E80 (exp=125, which is < 126 threshold) → bytes [0x80, 0x3E]
        var raw = new byte[] { 0x80, 0x3E, 0x80, 0x3E };
        var ternary = new sbyte[2];

        SafeTensorsReader.QuantiseRow(raw, ternary, "BF16", 2);

        Assert.Equal((sbyte)0, ternary[0]);
        Assert.Equal((sbyte)0, ternary[1]);
    }

    [Fact]
    public void QuantiseF32Row_MixedValues_CorrectTernary()
    {
        // F32 values: +1.0, -1.0, 0.0
        var bytes = new byte[12];
        BitConverter.GetBytes(1.0f).CopyTo(bytes, 0);
        BitConverter.GetBytes(-1.0f).CopyTo(bytes, 4);
        BitConverter.GetBytes(0.0f).CopyTo(bytes, 8);
        var ternary = new sbyte[3];

        SafeTensorsReader.QuantiseRow(bytes, ternary, "F32", 3);

        Assert.Equal((sbyte) 1, ternary[0]);
        Assert.Equal((sbyte)-1, ternary[1]);
        Assert.Equal((sbyte) 0, ternary[2]);
    }

    [Fact]
    public void QuantiseI8Row_Values_CorrectTernary()
    {
        var raw = new byte[] { 1, 0xFF, 0 }; // +1, -1 (as sbyte), 0
        var ternary = new sbyte[3];

        SafeTensorsReader.QuantiseRow(raw, ternary, "I8", 3);

        Assert.Equal((sbyte) 1, ternary[0]);
        Assert.Equal((sbyte)-1, ternary[1]);
        Assert.Equal((sbyte) 0, ternary[2]);
    }

    // ── JSON header parsing ───────────────────────────────────────────────

    [Fact]
    public void ParseHeaderJson_MinimalTensor_ParsesCorrectly()
    {
        // Minimal valid header
        string json = """
            {
              "model.embed_tokens.weight": {
                "dtype": "BF16",
                "shape": [1000, 64],
                "data_offsets": [0, 128000]
              }
            }
            """;

        var bytes = Encoding.UTF8.GetBytes(json);
        var tensors = SafeTensorsReader.ParseHeaderJson(bytes, dataBase: 0, "test.safetensors");

        Assert.Single(tensors);
        var t = tensors[0];
        Assert.Equal("model.embed_tokens.weight", t.Name);
        Assert.Equal("BF16",   t.Dtype);
        Assert.Equal(2,        t.Shape.Length);
        Assert.Equal(1000,     t.Rows);
        Assert.Equal(64,       t.Cols);
        Assert.Equal(0L,       t.DataStart);
        Assert.Equal(128000L,  t.DataEnd);
    }

    [Fact]
    public void ParseHeaderJson_MetadataEntry_IsSkipped()
    {
        string json = """
            {
              "__metadata__": {"format": "pt"},
              "weight": {
                "dtype": "F32",
                "shape": [4, 4],
                "data_offsets": [0, 64]
              }
            }
            """;

        var bytes = Encoding.UTF8.GetBytes(json);
        var tensors = SafeTensorsReader.ParseHeaderJson(bytes, 0, string.Empty);

        Assert.Single(tensors); // __metadata__ skipped
        Assert.Equal("weight", tensors[0].Name);
    }

    [Fact]
    public void ParseHeaderJson_DataBaseOffset_IsAddedToDataOffsets()
    {
        string json = """
            {
              "t": { "dtype": "BF16", "shape": [2, 2], "data_offsets": [100, 108] }
            }
            """;

        var bytes = Encoding.UTF8.GetBytes(json);
        // dataBase = 512 → absolute offsets = 512+100=612, 512+108=620
        var tensors = SafeTensorsReader.ParseHeaderJson(bytes, dataBase: 512, string.Empty);

        Assert.Equal(612L, tensors[0].DataStart);
        Assert.Equal(620L, tensors[0].DataEnd);
    }

    [Fact]
    public void ParseHeaderJson_MultipleTensors_AllParsed()
    {
        string json = """
            {
              "a": { "dtype": "BF16", "shape": [2, 4], "data_offsets": [0, 16] },
              "b": { "dtype": "F32",  "shape": [3, 3], "data_offsets": [16, 52] }
            }
            """;

        var bytes = Encoding.UTF8.GetBytes(json);
        var tensors = SafeTensorsReader.ParseHeaderJson(bytes, 0, string.Empty);

        Assert.Equal(2, tensors.Count);
        Assert.Equal("a", tensors[0].Name);
        Assert.Equal("b", tensors[1].Name);
        Assert.Equal(4,   tensors[0].Cols);
        Assert.Equal(3,   tensors[1].Cols);
    }

    // ── TensorInfo helpers ────────────────────────────────────────────────

    [Theory]
    [InlineData("BF16", 2)]
    [InlineData("F32",  4)]
    [InlineData("F16",  2)]
    [InlineData("I8",   1)]
    [InlineData("U8",   1)]
    public void TensorInfo_ElementBytes_MatchesDtype(string dtype, int expectedBytes)
    {
        var info = new SafeTensorsReader.TensorInfo("t", dtype, [8, 4], 0, 64);
        Assert.Equal(expectedBytes, info.ElementBytes);
    }

    [Fact]
    public void TensorInfo_1dShape_ColsIsOne()
    {
        var info = new SafeTensorsReader.TensorInfo("t", "F32", [100], 0, 400);
        Assert.Equal(100, info.Rows);
        Assert.Equal(1,   info.Cols);
    }
}
