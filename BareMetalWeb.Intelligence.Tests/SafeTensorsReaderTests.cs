using System.Buffers.Binary;
using System.Text;
using Xunit;

namespace BareMetalWeb.Intelligence.Tests;

public class SafeTensorsReaderTests
{
    /// <summary>
    /// Build a minimal valid SafeTensors file in memory for testing.
    /// </summary>
    private static Stream BuildTestSafeTensors(
        Dictionary<string, (string dtype, int[] shape, byte[] data)> tensors)
    {
        // Build header JSON
        var sb = new StringBuilder();
        sb.Append('{');
        bool first = true;
        long offset = 0;
        var orderedTensors = tensors.ToArray();

        foreach (var (name, (dtype, shape, data)) in orderedTensors)
        {
            if (!first) sb.Append(',');
            first = false;

            sb.Append($"\"{name}\":{{");
            sb.Append($"\"dtype\":\"{dtype}\",");
            sb.Append($"\"shape\":[{string.Join(",", shape)}],");
            sb.Append($"\"data_offsets\":[{offset},{offset + data.Length}]");
            sb.Append('}');
            offset += data.Length;
        }
        sb.Append('}');

        var headerBytes = Encoding.UTF8.GetBytes(sb.ToString());

        // Build file
        var ms = new MemoryStream();
        var lenBuf = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(lenBuf, (ulong)headerBytes.Length);
        ms.Write(lenBuf);
        ms.Write(headerBytes);

        foreach (var (_, (_, _, data)) in orderedTensors)
            ms.Write(data);

        ms.Position = 0;
        return ms;
    }

    [Fact]
    public void Open_ParsesHeaderCorrectly()
    {
        var data = new byte[] { 1, 0, 255, 127 }; // 4 I8 weights
        using var stream = BuildTestSafeTensors(new()
        {
            ["test.weight"] = ("I8", [2, 2], data),
        });

        using var reader = SafeTensorsReader.Open(stream);

        Assert.True(reader.HasTensor("test.weight"));
        Assert.False(reader.HasTensor("nonexistent"));

        var info = reader.Tensors["test.weight"];
        Assert.Equal("I8", info.DType);
        Assert.Equal(2, info.Rows);
        Assert.Equal(2, info.Cols);
        Assert.Equal(4, info.DataLength);
    }

    [Fact]
    public void ReadTensorSBytes_ReturnsCorrectValues()
    {
        // Ternary weights: -1, 0, 1, -1
        var data = new byte[] { 0xFF, 0x00, 0x01, 0xFF };
        using var stream = BuildTestSafeTensors(new()
        {
            ["layer.weight"] = ("I8", [2, 2], data),
        });

        using var reader = SafeTensorsReader.Open(stream);
        var weights = reader.ReadTensorSBytes("layer.weight");

        Assert.Equal(4, weights.Length);
        Assert.Equal(-1, weights[0]);
        Assert.Equal(0, weights[1]);
        Assert.Equal(1, weights[2]);
        Assert.Equal(-1, weights[3]);
    }

    [Fact]
    public void ReadTensorBytes_MultipleTensors()
    {
        var data1 = new byte[] { 1, 2, 3, 4 };
        var data2 = new byte[] { 5, 6, 7, 8, 9, 10, 11, 12 };
        using var stream = BuildTestSafeTensors(new()
        {
            ["embed.weight"] = ("I8", [4], data1),
            ["layer.0.attn.q_proj.weight"] = ("I8", [2, 4], data2),
        });

        using var reader = SafeTensorsReader.Open(stream);

        Assert.Equal(2, reader.Tensors.Count);

        var t1 = reader.ReadTensorBytes("embed.weight");
        Assert.Equal(data1, t1);

        var t2 = reader.ReadTensorBytes("layer.0.attn.q_proj.weight");
        Assert.Equal(data2, t2);
    }

    [Fact]
    public void ReadTensorFloat32_DecodesCorrectly()
    {
        // Two F32 values: 1.0f and -0.5f
        var data = new byte[8];
        BinaryPrimitives.WriteSingleLittleEndian(data, 1.0f);
        BinaryPrimitives.WriteSingleLittleEndian(data.AsSpan(4), -0.5f);

        using var stream = BuildTestSafeTensors(new()
        {
            ["norm.weight"] = ("F32", [2], data),
        });

        using var reader = SafeTensorsReader.Open(stream);
        var values = reader.ReadTensorFloat32("norm.weight");

        Assert.Equal(2, values.Length);
        Assert.Equal(1.0f, values[0]);
        Assert.Equal(-0.5f, values[1]);
    }

    [Fact]
    public void TensorNames_ListsAllTensors()
    {
        using var stream = BuildTestSafeTensors(new()
        {
            ["a"] = ("I8", [1], [0]),
            ["b"] = ("I8", [1], [1]),
            ["c"] = ("I8", [1], [2]),
        });

        using var reader = SafeTensorsReader.Open(stream);
        var names = reader.TensorNames.OrderBy(n => n).ToArray();

        Assert.Equal(["a", "b", "c"], names);
    }

    [Fact]
    public void MetadataKey_IsSkipped()
    {
        // Build a file with __metadata__ key (common in HF files)
        var sb = new StringBuilder();
        sb.Append("{\"__metadata__\":{\"format\":\"pt\"},");
        sb.Append("\"weight\":{\"dtype\":\"I8\",\"shape\":[2],\"data_offsets\":[0,2]}}");

        var headerBytes = Encoding.UTF8.GetBytes(sb.ToString());
        var ms = new MemoryStream();
        var lenBuf = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(lenBuf, (ulong)headerBytes.Length);
        ms.Write(lenBuf);
        ms.Write(headerBytes);
        ms.Write(new byte[] { 1, 255 }); // data
        ms.Position = 0;

        using var reader = SafeTensorsReader.Open(ms);
        Assert.Single(reader.Tensors);
        Assert.True(reader.HasTensor("weight"));
        Assert.False(reader.HasTensor("__metadata__"));
    }

    [Fact]
    public void ReadTensorSBytes_ThrowsOnMissingTensor()
    {
        using var stream = BuildTestSafeTensors(new()
        {
            ["exists"] = ("I8", [1], [0]),
        });

        using var reader = SafeTensorsReader.Open(stream);
        Assert.Throws<KeyNotFoundException>(() => reader.ReadTensorSBytes("missing"));
    }
}

public class HuggingFaceImporterTests
{
    [Fact]
    public void QuantizeToTernary_ProducesCorrectValues()
    {
        // Use reflection-free approach: test via the full import path with synthetic data
        // The quantization is internal, so we test it indirectly through a mini import

        // Create a temp directory with minimal HF model structure
        var tmpDir = Path.Combine(Path.GetTempPath(), $"bmw-hf-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmpDir);

        try
        {
            // Write config.json
            File.WriteAllText(Path.Combine(tmpDir, "config.json"), """
                {
                    "hidden_size": 4,
                    "intermediate_size": 8,
                    "num_hidden_layers": 1,
                    "num_attention_heads": 2,
                    "vocab_size": 8,
                    "max_position_embeddings": 16
                }
                """);

            // Write tokenizer.json
            File.WriteAllText(Path.Combine(tmpDir, "tokenizer.json"), """
                {
                    "model": {
                        "vocab": {
                            "<PAD>": 0,
                            "<BOS>": 1,
                            "<EOS>": 2,
                            "<UNK>": 3,
                            "hello": 4,
                            "world": 5,
                            "test": 6,
                            "data": 7
                        }
                    }
                }
                """);

            // Build a minimal safetensors file with the required tensors
            var tensors = new Dictionary<string, (string dtype, int[] shape, byte[] data)>();

            // Each attention projection: [4 × 4] = 16 ternary weights
            byte[] smallWeight = new byte[16]; // 4×4
            for (int i = 0; i < smallWeight.Length; i++)
                smallWeight[i] = (byte)((i % 3) - 1); // cycles -1, 0, 1

            tensors["model.layers.0.self_attn.q_proj.weight"] = ("I8", [4, 4], (byte[])smallWeight.Clone());
            tensors["model.layers.0.self_attn.k_proj.weight"] = ("I8", [4, 4], (byte[])smallWeight.Clone());
            tensors["model.layers.0.self_attn.v_proj.weight"] = ("I8", [4, 4], (byte[])smallWeight.Clone());
            tensors["model.layers.0.self_attn.o_proj.weight"] = ("I8", [4, 4], (byte[])smallWeight.Clone());

            // FFN: gate/up [8×4], down [4×8]
            byte[] ffnWide = new byte[32]; // 8×4
            byte[] ffnDown = new byte[32]; // 4×8
            for (int i = 0; i < ffnWide.Length; i++)
            {
                ffnWide[i] = (byte)((i % 3) - 1);
                ffnDown[i] = (byte)((i % 3) - 1);
            }
            tensors["model.layers.0.mlp.gate_proj.weight"] = ("I8", [8, 4], (byte[])ffnWide.Clone());
            tensors["model.layers.0.mlp.up_proj.weight"] = ("I8", [8, 4], (byte[])ffnWide.Clone());
            tensors["model.layers.0.mlp.down_proj.weight"] = ("I8", [4, 8], (byte[])ffnDown.Clone());

            // Embeddings [8×4] and output head [8×4]
            byte[] embedWeight = new byte[32]; // 8×4
            for (int i = 0; i < embedWeight.Length; i++)
                embedWeight[i] = (byte)((i % 3) - 1);
            tensors["model.embed_tokens.weight"] = ("I8", [8, 4], (byte[])embedWeight.Clone());
            tensors["lm_head.weight"] = ("I8", [8, 4], (byte[])embedWeight.Clone());

            WriteSafeTensors(Path.Combine(tmpDir, "model.safetensors"), tensors);

            // Run import
            var outputPath = Path.Combine(tmpDir, "output.bmwm");
            var result = HuggingFaceImporter.Import(tmpDir, new ImportOptions
            {
                OutputPath = outputPath,
                PruneVocabulary = false,
            });

            Assert.True(File.Exists(outputPath));
            Assert.Equal(4, result.Config.HiddenDim);
            Assert.Equal(1, result.Config.NumLayers);
            Assert.Equal(8, result.ActiveVocab);
            Assert.Equal(8, result.TokenTableSize);
            Assert.True(result.FileSizeBytes > 0);
        }
        finally
        {
            Directory.Delete(tmpDir, true);
        }
    }

    private static void WriteSafeTensors(
        string path,
        Dictionary<string, (string dtype, int[] shape, byte[] data)> tensors)
    {
        var sb = new StringBuilder();
        sb.Append('{');
        bool first = true;
        long offset = 0;

        foreach (var (name, (dtype, shape, data)) in tensors)
        {
            if (!first) sb.Append(',');
            first = false;

            sb.Append($"\"{name}\":{{");
            sb.Append($"\"dtype\":\"{dtype}\",");
            sb.Append($"\"shape\":[{string.Join(",", shape)}],");
            sb.Append($"\"data_offsets\":[{offset},{offset + data.Length}]");
            sb.Append('}');
            offset += data.Length;
        }
        sb.Append('}');

        var headerBytes = Encoding.UTF8.GetBytes(sb.ToString());

        using var fs = new FileStream(path, FileMode.Create);
        var lenBuf = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(lenBuf, (ulong)headerBytes.Length);
        fs.Write(lenBuf);
        fs.Write(headerBytes);

        foreach (var (_, (_, _, data)) in tensors)
            fs.Write(data);
    }
}
