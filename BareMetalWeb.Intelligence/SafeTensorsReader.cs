using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Pure C# parser for the SafeTensors binary format.
/// Streams tensors row-by-row to keep memory pressure minimal — critical for
/// large embedding tables (e.g. 128K × 2560 = 655 MB BF16 without streaming).
///
/// File layout:
///   [uint64 LE]  N  — byte length of JSON header
///   [N bytes]       — UTF-8 JSON header (tensor metadata)
///   [data bytes]    — packed tensor data (dtype-encoded, back-to-back)
///
/// Header JSON format:
///   {
///     "__metadata__": {...},           // optional, skipped
///     "tensor_name": {
///       "dtype":        "BF16|F32|I8|...",
///       "shape":        [rows, cols],
///       "data_offsets": [start, end]   // bytes from start of data section
///     }
///   }
/// </summary>
public static class SafeTensorsReader
{
    // Maximum safe header size (128 MB) — headers larger than this indicate corruption.
    private const int MaxHeaderSizeBytes = 128 * 1024 * 1024;

    // BF16 exponent threshold for |value| >= 0.5.
    // BF16 exponent is biased by 127. Value 0.5 = 2^(-1) → biased exp = 126.
    // Values with exp < 126 have |value| < 0.5 and are treated as zero.
    private const int Bf16HalfThresholdExp = 126;

    // F16 exponent threshold for |value| >= 0.5.
    // F16 exponent is biased by 15. Value 0.5 = 2^(-1) → biased exp = 14.
    // Values with exp < 14 have |value| < 0.5 and are treated as zero.
    private const int F16HalfThresholdExp = 14;
    // ── Public types ──────────────────────────────────────────────────────

    /// <summary>Metadata for a single tensor extracted from the JSON header.</summary>
    public readonly struct TensorInfo
    {
        public readonly string Name;
        public readonly string Dtype;
        public readonly int[]  Shape;
        public readonly long   DataStart; // absolute byte offset in file
        public readonly long   DataEnd;   // absolute byte offset in file (exclusive)

        public TensorInfo(string name, string dtype, int[] shape, long dataStart, long dataEnd)
        {
            Name      = name;
            Dtype     = dtype;
            Shape     = shape;
            DataStart = dataStart;
            DataEnd   = dataEnd;
        }

        /// <summary>Total data bytes (DataEnd - DataStart).</summary>
        public long DataBytes => DataEnd - DataStart;
        /// <summary>Rows (Shape[0]) or 0 if shape is empty.</summary>
        public int Rows => Shape.Length > 0 ? Shape[0] : 0;
        /// <summary>Cols (Shape[1]) or 1 for 1-D tensors.</summary>
        public int Cols => Shape.Length > 1 ? Shape[1] : 1;
        /// <summary>Bytes per element for this dtype.</summary>
        public int ElementBytes => Dtype switch
        {
            "BF16" => 2,
            "F32"  => 4,
            "F16"  => 2,
            "F64"  => 8,
            "I8"   => 1,
            "I16"  => 2,
            "I32"  => 4,
            "I64"  => 8,
            "U8"   => 1,
            "U16"  => 2,
            "U32"  => 4,
            "U64"  => 8,
            "BOOL" => 1,
            _      => 1,
        };
    }

    // ── Header parsing ────────────────────────────────────────────────────

    /// <summary>
    /// Read the tensor metadata from the SafeTensors header of a single file.
    /// Tensors are returned in header order. "__metadata__" entries are skipped.
    /// </summary>
    public static List<TensorInfo> ReadHeader(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, 65536, FileOptions.SequentialScan);
        return ReadHeader(fs);
    }

    /// <summary>
    /// Read the tensor metadata from a SafeTensors header in an already-open stream.
    /// The stream position is advanced past the JSON header on return.
    /// </summary>
    public static List<TensorInfo> ReadHeader(Stream stream)
    {
        // --- Read N (8-byte LE uint64) ---
        Span<byte> lenBuf = stackalloc byte[8];
        ReadExact(stream, lenBuf);
        long headerLen = (long)BinaryPrimitives.ReadUInt64LittleEndian(lenBuf);
        if (headerLen <= 0 || headerLen > MaxHeaderSizeBytes)
            throw new InvalidDataException($"SafeTensors header length {headerLen} is out of range.");

        // Absolute offset where the data section begins
        long dataBase = 8L + headerLen;

        // --- Read JSON header bytes ---
        var headerBytes = new byte[headerLen];
        ReadExact(stream, headerBytes);

        string name = stream is FileStream fs ? fs.Name : string.Empty;
        return ParseHeaderJson(headerBytes, dataBase, name);
    }

    // ── Shard scanning ────────────────────────────────────────────────────

    /// <summary>
    /// Collect tensor metadata from all .safetensors files in a directory.
    /// The returned map is keyed by tensor name; if a name appears in more
    /// than one shard the last shard wins.
    /// </summary>
    public static Dictionary<string, (TensorInfo Info, string FilePath)>
        ReadAllHeaders(string hfDir)
    {
        var result = new Dictionary<string, (TensorInfo, string)>(StringComparer.Ordinal);

        var files = Directory.GetFiles(hfDir, "*.safetensors", SearchOption.TopDirectoryOnly);
        Array.Sort(files, StringComparer.Ordinal); // deterministic shard order

        foreach (var file in files)
        {
            var tensors = ReadHeader(file);
            foreach (var t in tensors)
                result[t.Name] = (t, file);
        }

        return result;
    }

    // ── Tensor data streaming ─────────────────────────────────────────────

    /// <summary>
    /// Stream a BF16 or F32 tensor row-by-row, calling <paramref name="rowCallback"/>
    /// for each row with a span of quantised sbyte ternary values {-1, 0, +1}.
    /// Memory usage: one row buffer = <c>info.Cols * info.ElementBytes</c> bytes.
    /// </summary>
    /// <param name="filePath">Path to the .safetensors shard file.</param>
    /// <param name="info">Tensor descriptor from <see cref="ReadHeader"/>.</param>
    /// <param name="rowCallback">
    ///   Called for each row with (rowIndex, ternaryRow).
    ///   The span is valid only for the duration of the callback.
    /// </param>
    public static void StreamTernaryRows(
        string filePath,
        TensorInfo info,
        Action<int, ReadOnlySpan<sbyte>> rowCallback)
    {
        int rows       = info.Rows;
        int cols       = info.Cols;
        int elemBytes  = info.ElementBytes;
        int rowBytes   = cols * elemBytes;

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, Math.Max(65536, rowBytes), FileOptions.SequentialScan);

        fs.Seek(info.DataStart, SeekOrigin.Begin);

        // Single-row byte buffer (reused across all rows)
        var rawRow   = new byte[rowBytes];
        var ternRow  = new sbyte[cols];

        for (int r = 0; r < rows; r++)
        {
            ReadExact(fs, rawRow);
            QuantiseRow(rawRow, ternRow, info.Dtype, cols);
            rowCallback(r, ternRow);
        }
    }

    // ── BF16 / F32 quantisation ───────────────────────────────────────────

    /// <summary>
    /// Read the raw bytes for a tensor and convert to ternary {-1, 0, +1} in-place.
    /// Supports BF16, F16, F32, I8 (pass-through), U8.
    /// </summary>
    internal static void QuantiseRow(
        ReadOnlySpan<byte> raw,
        Span<sbyte> ternary,
        string dtype,
        int cols)
    {
        switch (dtype)
        {
            case "BF16": QuantiseBf16Row(raw, ternary, cols); break;
            case "F16":  QuantiseF16Row(raw, ternary, cols);  break;
            case "F32":  QuantiseF32Row(raw, ternary, cols);  break;
            case "I8":   QuantiseI8Row(raw, ternary, cols);   break;
            default:     QuantiseBf16Row(raw, ternary, cols); break; // best-effort
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuantiseBf16Row(ReadOnlySpan<byte> raw, Span<sbyte> ternary, int cols)
    {
        // BF16 = 16-bit: 1 sign + 8 exponent + 7 mantissa (same layout as upper 16 bits of F32)
        // Threshold: |value| >= 0.5 → quantise to ±1, otherwise 0
        // Shortcut: BF16 bytes [lo, hi] — hi byte = sign(7) + exponent(6-0)
        //   value == 0.0 when exponent==0 && mantissa==0 (i.e. hi & 0x7F == 0)
        //   sign is bit 7 of the high byte (raw[1] in little-endian)
        // For ternary: +1 when positive, -1 when negative, 0 when zero or sub-threshold
        for (int i = 0; i < cols; i++)
        {
            int offset = i * 2;
            // Reconstruct upper 16 bits as uint16 LE
            ushort bits = (ushort)(raw[offset] | (raw[offset + 1] << 8));
            // Extract exponent (bits 14-7) — biased by 127
            int exp = (bits >> 7) & 0xFF;
            // Ignore denorms and near-zero (exp < Bf16HalfThresholdExp ≈ |value| < 0.5)
            if (exp < Bf16HalfThresholdExp) { ternary[i] = 0; continue; }
            // Sign bit
            ternary[i] = (bits & 0x8000) != 0 ? (sbyte)-1 : (sbyte)1;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuantiseF16Row(ReadOnlySpan<byte> raw, Span<sbyte> ternary, int cols)
    {
        // F16: 1 sign + 5 exponent + 10 mantissa; bias=15; threshold ≈ exp >= 14
        for (int i = 0; i < cols; i++)
        {
            int offset = i * 2;
            ushort bits = (ushort)(raw[offset] | (raw[offset + 1] << 8));
            int exp = (bits >> 10) & 0x1F;
            if (exp < F16HalfThresholdExp) { ternary[i] = 0; continue; }
            ternary[i] = (bits & 0x8000) != 0 ? (sbyte)-1 : (sbyte)1;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuantiseF32Row(ReadOnlySpan<byte> raw, Span<sbyte> ternary, int cols)
    {
        for (int i = 0; i < cols; i++)
        {
            float v = BitConverter.Int32BitsToSingle(
                BinaryPrimitives.ReadInt32LittleEndian(raw.Slice(i * 4, 4)));
            ternary[i] = v > 0.5f ? (sbyte)1 : v < -0.5f ? (sbyte)-1 : (sbyte)0;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuantiseI8Row(ReadOnlySpan<byte> raw, Span<sbyte> ternary, int cols)
    {
        // I8 can directly map: positive→+1, zero→0, negative→-1
        for (int i = 0; i < cols; i++)
            ternary[i] = (sbyte)raw[i] switch { > 0 => 1, < 0 => -1, _ => 0 };
    }

    // ── Minimal JSON header parser ─────────────────────────────────────────

    /// <summary>
    /// Manual span-based JSON parser for the SafeTensors header.
    /// Avoids reflection-based deserialisation (AOT-safe).
    /// Only handles the specific structure produced by HuggingFace safetensors lib.
    /// </summary>
    internal static List<TensorInfo> ParseHeaderJson(
        ReadOnlySpan<byte> jsonBytes, long dataBase, string filePath)
    {
        var json = Encoding.UTF8.GetString(jsonBytes).AsSpan().Trim();
        var result = new List<TensorInfo>(64);

        // Top-level object: { "name": { ... }, ... }
        // Skip opening '{'
        int pos = 0;
        SkipWhitespace(json, ref pos);
        if (pos >= json.Length || json[pos] != '{') return result;
        pos++; // consume '{'

        while (pos < json.Length)
        {
            SkipWhitespace(json, ref pos);
            if (pos >= json.Length) break;
            if (json[pos] == '}') break;
            if (json[pos] == ',') { pos++; continue; }

            // Read tensor name (quoted string)
            if (json[pos] != '"') { SkipValue(json, ref pos); continue; }
            string name = ReadString(json, ref pos);

            SkipWhitespace(json, ref pos);
            if (pos >= json.Length || json[pos] != ':') continue;
            pos++; // consume ':'

            SkipWhitespace(json, ref pos);
            if (pos >= json.Length) break;

            // Skip __metadata__ entry
            if (name == "__metadata__") { SkipValue(json, ref pos); continue; }

            // Read tensor descriptor object { "dtype": ..., "shape": [...], "data_offsets": [...] }
            if (json[pos] != '{') { SkipValue(json, ref pos); continue; }
            pos++; // consume '{'

            string dtype = string.Empty;
            int[]? shape = null;
            long   offsetStart = 0, offsetEnd = 0;

            while (pos < json.Length)
            {
                SkipWhitespace(json, ref pos);
                if (pos >= json.Length) break;
                if (json[pos] == '}') { pos++; break; }
                if (json[pos] == ',') { pos++; continue; }

                if (json[pos] != '"') { SkipValue(json, ref pos); continue; }
                string key = ReadString(json, ref pos);

                SkipWhitespace(json, ref pos);
                if (pos >= json.Length || json[pos] != ':') continue;
                pos++; // consume ':'
                SkipWhitespace(json, ref pos);

                switch (key)
                {
                    case "dtype":
                        dtype = ReadString(json, ref pos);
                        break;
                    case "shape":
                        shape = ReadIntArray(json, ref pos);
                        break;
                    case "data_offsets":
                        var offsets = ReadLongArray(json, ref pos);
                        if (offsets.Length >= 2) { offsetStart = offsets[0]; offsetEnd = offsets[1]; }
                        break;
                    default:
                        SkipValue(json, ref pos);
                        break;
                }
            }

            if (!string.IsNullOrEmpty(dtype) && shape is not null)
            {
                result.Add(new TensorInfo(
                    name, dtype, shape,
                    dataStart: dataBase + offsetStart,
                    dataEnd:   dataBase + offsetEnd));
            }
        }

        return result;
    }

    // ── JSON mini-parser helpers ──────────────────────────────────────────

    private static void SkipWhitespace(ReadOnlySpan<char> s, ref int pos)
    {
        while (pos < s.Length && s[pos] is ' ' or '\t' or '\r' or '\n') pos++;
    }

    private static string ReadString(ReadOnlySpan<char> s, ref int pos)
    {
        if (pos >= s.Length || s[pos] != '"') return string.Empty;
        pos++; // consume opening '"'
        int start = pos;
        while (pos < s.Length)
        {
            if (s[pos] == '\\') { pos += 2; continue; }
            if (s[pos] == '"') break;
            pos++;
        }
        string result = s[start..pos].ToString();
        if (pos < s.Length) pos++; // consume closing '"'
        return result;
    }

    private static int[] ReadIntArray(ReadOnlySpan<char> s, ref int pos)
    {
        if (pos >= s.Length || s[pos] != '[') { SkipValue(s, ref pos); return []; }
        pos++; // consume '['
        var list = new List<int>(4);
        while (pos < s.Length)
        {
            SkipWhitespace(s, ref pos);
            if (pos >= s.Length) break;
            if (s[pos] == ']') { pos++; break; }
            if (s[pos] == ',') { pos++; continue; }
            list.Add((int)ReadLong(s, ref pos));
        }
        return [.. list];
    }

    private static long[] ReadLongArray(ReadOnlySpan<char> s, ref int pos)
    {
        if (pos >= s.Length || s[pos] != '[') { SkipValue(s, ref pos); return []; }
        pos++; // consume '['
        var list = new List<long>(2);
        while (pos < s.Length)
        {
            SkipWhitespace(s, ref pos);
            if (pos >= s.Length) break;
            if (s[pos] == ']') { pos++; break; }
            if (s[pos] == ',') { pos++; continue; }
            list.Add(ReadLong(s, ref pos));
        }
        return [.. list];
    }

    private static long ReadLong(ReadOnlySpan<char> s, ref int pos)
    {
        bool neg = pos < s.Length && s[pos] == '-';
        if (neg) pos++;
        long v = 0;
        while (pos < s.Length && s[pos] is >= '0' and <= '9')
        {
            v = v * 10 + (s[pos] - '0');
            pos++;
        }
        return neg ? -v : v;
    }

    private static void SkipValue(ReadOnlySpan<char> s, ref int pos)
    {
        if (pos >= s.Length) return;
        char c = s[pos];
        if (c == '"') { ReadString(s, ref pos); return; }
        if (c == '{' || c == '[')
        {
            char close = c == '{' ? '}' : ']';
            pos++;
            int depth = 1;
            while (pos < s.Length && depth > 0)
            {
                if (s[pos] == '"') { ReadString(s, ref pos); continue; }
                if (s[pos] == c)  depth++;
                if (s[pos] == close) depth--;
                pos++;
            }
            return;
        }
        // Number, bool, null
        while (pos < s.Length && s[pos] is not (',' or '}' or ']' or ' ' or '\t' or '\r' or '\n'))
            pos++;
    }

    // ── I/O helpers ───────────────────────────────────────────────────────

    private static void ReadExact(Stream stream, Span<byte> buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = stream.Read(buffer[total..]);
            if (read == 0)
                throw new EndOfStreamException(
                    $"Unexpected end of stream after {total} bytes (expected {buffer.Length}).");
            total += read;
        }
    }
}
