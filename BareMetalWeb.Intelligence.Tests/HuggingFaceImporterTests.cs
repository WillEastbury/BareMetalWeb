using System.Text;
using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class HuggingFaceImporterTests
{
    // ── Import validation ─────────────────────────────────────────────────

    [Fact]
    public void Import_DirectoryNotFound_Throws()
    {
        Assert.Throws<DirectoryNotFoundException>(
            () => HuggingFaceImporter.Import("/nonexistent/path", "/tmp/out.bmwm"));
    }

    [Fact]
    public void Import_EmptyDirectory_Throws()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"bmw_hf_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            // Empty dir → ReadAllHeaders returns empty map → ValidateRequiredTensors throws
            var ex = Assert.Throws<InvalidDataException>(
                () => HuggingFaceImporter.Import(dir, Path.Combine(dir, "out.bmwm")));
            Assert.Contains("model.embed_tokens.weight", ex.Message);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ── Minimal synthetic import ──────────────────────────────────────────

    [Fact]
    public void Import_MinimalSyntheticModel_ProducesValidSnapshot()
    {
        // Build a minimal 2-layer, 8-dim model as SafeTensors and import it.
        // This validates the full import → .bmwm pipeline without a real HF model.
        const int dim     = 8;
        const int layers  = 2;
        const int heads   = 2;
        const int vocab   = 16;

        var dir    = Path.Combine(Path.GetTempPath(), $"bmw_hf_minimal_{Guid.NewGuid():N}");
        var outDir = Path.Combine(Path.GetTempPath(), $"bmw_hf_out_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        Directory.CreateDirectory(outDir);

        try
        {
            // Write config.json
            File.WriteAllText(Path.Combine(dir, "config.json"),
                $$$"""
                {
                  "hidden_size": {{{dim}}},
                  "num_hidden_layers": {{{layers}}},
                  "num_attention_heads": {{{heads}}},
                  "vocab_size": {{{vocab}}},
                  "max_position_embeddings": 64
                }
                """);

            // Build SafeTensors shard: all tensors for the model
            // Tensor names must match what HuggingFaceImporter expects
            var tensors = new List<(string Name, int Rows, int Cols)>
            {
                ("model.embed_tokens.weight", vocab, dim),
                ("lm_head.weight",            vocab, dim),
            };
            for (int i = 0; i < layers; i++)
            {
                tensors.Add(($"model.layers.{i}.self_attn.q_proj.weight", dim, dim));
                tensors.Add(($"model.layers.{i}.self_attn.k_proj.weight", dim, dim));
                tensors.Add(($"model.layers.{i}.self_attn.v_proj.weight", dim, dim));
                tensors.Add(($"model.layers.{i}.self_attn.o_proj.weight", dim, dim));
                tensors.Add(($"model.layers.{i}.mlp.gate_proj.weight",    dim, dim));
                tensors.Add(($"model.layers.{i}.mlp.up_proj.weight",      dim, dim));
                tensors.Add(($"model.layers.{i}.mlp.down_proj.weight",    dim, dim));
            }

            WriteSyntheticSafeTensors(
                Path.Combine(dir, "model.safetensors"),
                tensors, dim);

            // Run the import
            string outputPath = Path.Combine(outDir, "model.bmwm");
            var progress = new List<string>();
            HuggingFaceImporter.Import(dir, outputPath, msg => progress.Add(msg));

            // Verify output snapshot was created and is loadable
            Assert.True(File.Exists(outputPath), "model.bmwm was not created");
            Assert.True(new FileInfo(outputPath).Length > 0, "model.bmwm is empty");

            // Load the snapshot into an engine
            using var engine = new BitNetEngine(new BitNetModelConfig(dim, layers, heads, vocab, 64));
            engine.LoadSnapshot(outputPath);
            Assert.True(engine.IsLoaded);
            Assert.Equal(layers, engine.ModelStats!.Value.LayerCount);

            // Progress messages should include completion
            Assert.Contains(progress, msg => msg.Contains("✓") || msg.Contains("complete") || msg.Contains("Snapshot written"));
        }
        finally
        {
            Directory.Delete(dir,    recursive: true);
            Directory.Delete(outDir, recursive: true);
        }
    }

    // ── MaxSeqLen cap ─────────────────────────────────────────────────────

    [Fact]
    public void MaxSeqLenCap_IsReasonable()
    {
        // The cap must be low enough to avoid OOM (< 1024) and high enough
        // to be useful (> 64).
        Assert.InRange(HuggingFaceImporter.MaxSeqLenCap, 64, 1023);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// <summary>
    /// Write a minimal valid .safetensors file containing random BF16 weights.
    /// All tensors are [rows, cols] BF16 with values randomly ±1.0.
    /// </summary>
    private static void WriteSyntheticSafeTensors(
        string path,
        List<(string Name, int Rows, int Cols)> tensors,
        int dim)
    {
        var rng = Random.Shared;

        // Build data section first to know offsets
        var dataChunks  = new List<(string Name, byte[] Data)>();

        foreach (var (name, rows, cols) in tensors)
        {
            int elemCount = rows * cols;
            var data      = new byte[elemCount * 2]; // BF16 = 2 bytes
            for (int i = 0; i < elemCount; i++)
            {
                // Write BF16 ±1.0 (random sign)
                ushort bits = rng.Next(2) == 0
                    ? (ushort)0x3F80  // +1.0
                    : (ushort)0xBF80; // -1.0
                data[i * 2]     = (byte)(bits & 0xFF);
                data[i * 2 + 1] = (byte)(bits >> 8);
            }
            dataChunks.Add((name, data));
        }

        // Build JSON header
        var sb = new StringBuilder(256);
        sb.Append('{');
        long offset = 0;
        for (int i = 0; i < tensors.Count; i++)
        {
            var (name, rows, cols) = tensors[i];
            var data = dataChunks[i].Data;
            if (i > 0) sb.Append(',');
            sb.Append($"\"{EscapeJson(name)}\":{{");
            sb.Append("\"dtype\":\"BF16\",");
            sb.Append($"\"shape\":[{rows},{cols}],");
            sb.Append($"\"data_offsets\":[{offset},{offset + data.Length}]");
            sb.Append('}');
            offset += data.Length;
        }
        sb.Append('}');

        byte[] headerBytes = Encoding.UTF8.GetBytes(sb.ToString());
        ulong  headerLen   = (ulong)headerBytes.Length;

        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
        using var bw = new BinaryWriter(fs);

        // Write N (8-byte LE uint64)
        bw.Write(headerLen);
        // Write header
        bw.Write(headerBytes);
        // Write data
        foreach (var (_, data) in dataChunks)
            bw.Write(data);
    }

    private static string EscapeJson(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
