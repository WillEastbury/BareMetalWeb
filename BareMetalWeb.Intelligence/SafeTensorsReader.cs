using System.Buffers.Binary;
using System.Text;
using System.Text.Json;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Pure C# reader for the HuggingFace SafeTensors binary format.
/// No external dependencies. AOT-safe. Streaming-capable for large models.
///
/// Format:
///   [8 bytes]  u64 LE — header JSON length
///   [N bytes]  UTF-8 JSON header describing tensor metadata
///   [M bytes]  raw tensor data (contiguous, offsets from JSON)
///
/// Tensors are accessed by name; data offsets are relative to the start
/// of the data region (immediately after the header).
/// </summary>
public sealed class SafeTensorsReader : IDisposable
{
    private readonly Stream _stream;
    private readonly long _dataRegionStart;
    private readonly Dictionary<string, TensorInfo> _tensors;
    private readonly bool _ownsStream;

    public IReadOnlyDictionary<string, TensorInfo> Tensors => _tensors;

    private SafeTensorsReader(Stream stream, long dataRegionStart,
        Dictionary<string, TensorInfo> tensors, bool ownsStream)
    {
        _stream = stream;
        _dataRegionStart = dataRegionStart;
        _tensors = tensors;
        _ownsStream = ownsStream;
    }

    /// <summary>
    /// Open a SafeTensors file and parse the header.
    /// Does NOT read tensor data — call ReadTensor() to load individual tensors on demand.
    /// </summary>
    public static SafeTensorsReader Open(string path)
    {
        var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read, 65536, FileOptions.SequentialScan);
        try
        {
            return Open(fs, ownsStream: true);
        }
        catch
        {
            fs.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Open a SafeTensors stream and parse the header.
    /// </summary>
    public static SafeTensorsReader Open(Stream stream, bool ownsStream = false)
    {
        // Read 8-byte header length
        Span<byte> lenBuf = stackalloc byte[8];
        if (stream.Read(lenBuf) != 8)
            throw new InvalidDataException("SafeTensors: file too small for header length");

        long headerLen = (long)BinaryPrimitives.ReadUInt64LittleEndian(lenBuf);
        if (headerLen <= 0 || headerLen > 100_000_000) // 100MB header limit
            throw new InvalidDataException($"SafeTensors: unreasonable header length {headerLen}");

        // Read header JSON
        var headerBytes = new byte[headerLen];
        int totalRead = 0;
        while (totalRead < headerLen)
        {
            int read = stream.Read(headerBytes, totalRead, (int)(headerLen - totalRead));
            if (read == 0) throw new EndOfStreamException("SafeTensors: truncated header");
            totalRead += read;
        }

        long dataRegionStart = 8 + headerLen;

        // Parse header JSON
        var tensors = ParseHeader(headerBytes);

        return new SafeTensorsReader(stream, dataRegionStart, tensors, ownsStream);
    }

    /// <summary>
    /// Read a tensor's raw data by name. Returns the raw bytes.
    /// For ternary/I8 tensors, each byte is one weight value.
    /// </summary>
    public byte[] ReadTensorBytes(string name)
    {
        if (!_tensors.TryGetValue(name, out var info))
            throw new KeyNotFoundException($"Tensor '{name}' not found in SafeTensors file");

        long dataLen = info.DataEnd - info.DataStart;
        if (dataLen <= 0 || dataLen > int.MaxValue)
            throw new InvalidDataException($"Tensor '{name}': invalid data range [{info.DataStart}, {info.DataEnd})");

        var data = new byte[dataLen];
        _stream.Seek(_dataRegionStart + info.DataStart, SeekOrigin.Begin);
        int totalRead = 0;
        while (totalRead < dataLen)
        {
            int read = _stream.Read(data, totalRead, (int)(dataLen - totalRead));
            if (read == 0) throw new EndOfStreamException($"Tensor '{name}': truncated data");
            totalRead += read;
        }

        return data;
    }

    /// <summary>
    /// Read a tensor as sbyte[] (for I8/ternary weights).
    /// </summary>
    public sbyte[] ReadTensorSBytes(string name)
    {
        var bytes = ReadTensorBytes(name);
        // Reinterpret byte[] as sbyte[] without copy
        var result = new sbyte[bytes.Length];
        Buffer.BlockCopy(bytes, 0, result, 0, bytes.Length);
        return result;
    }

    /// <summary>
    /// Read a tensor as float[] (for F32 weights like norms).
    /// </summary>
    public float[] ReadTensorFloat32(string name)
    {
        var bytes = ReadTensorBytes(name);
        if (bytes.Length % 4 != 0)
            throw new InvalidDataException($"Tensor '{name}': F32 data length {bytes.Length} not divisible by 4");

        var result = new float[bytes.Length / 4];
        Buffer.BlockCopy(bytes, 0, result, 0, bytes.Length);
        return result;
    }

    /// <summary>
    /// Read a tensor as BFloat16 values converted to float[].
    /// </summary>
    public float[] ReadTensorBFloat16(string name)
    {
        var bytes = ReadTensorBytes(name);
        if (bytes.Length % 2 != 0)
            throw new InvalidDataException($"Tensor '{name}': BF16 data length {bytes.Length} not divisible by 2");

        int count = bytes.Length / 2;
        var result = new float[count];
        for (int i = 0; i < count; i++)
        {
            ushort raw = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(i * 2));
            // BFloat16 → Float32: just shift left by 16 bits
            uint f32Bits = (uint)raw << 16;
            result[i] = BitConverter.Int32BitsToSingle((int)f32Bits);
        }
        return result;
    }

    /// <summary>
    /// Check if a tensor exists in the file.
    /// </summary>
    public bool HasTensor(string name) => _tensors.ContainsKey(name);

    /// <summary>
    /// List all tensor names.
    /// </summary>
    public IEnumerable<string> TensorNames => _tensors.Keys;

    private static Dictionary<string, TensorInfo> ParseHeader(byte[] headerJson)
    {
        var tensors = new Dictionary<string, TensorInfo>(StringComparer.Ordinal);

        using var doc = JsonDocument.Parse(headerJson);
        foreach (var prop in doc.RootElement.EnumerateObject())
        {
            // Skip __metadata__ key
            if (prop.Name == "__metadata__") continue;

            var tensor = prop.Value;
            string dtype = tensor.GetProperty("dtype").GetString()!;
            var shape = tensor.GetProperty("shape");
            var offsets = tensor.GetProperty("data_offsets");

            var dims = new int[shape.GetArrayLength()];
            int idx = 0;
            foreach (var d in shape.EnumerateArray())
                dims[idx++] = d.GetInt32();

            long dataStart = offsets[0].GetInt64();
            long dataEnd = offsets[1].GetInt64();

            tensors[prop.Name] = new TensorInfo(dtype, dims, dataStart, dataEnd);
        }

        return tensors;
    }

    public void Dispose()
    {
        if (_ownsStream)
            _stream.Dispose();
    }
}

/// <summary>
/// Metadata for a single tensor in a SafeTensors file.
/// </summary>
public readonly record struct TensorInfo(
    string DType,
    int[] Shape,
    long DataStart,
    long DataEnd)
{
    public long DataLength => DataEnd - DataStart;
    public int Rows => Shape.Length >= 2 ? Shape[0] : 1;
    public int Cols => Shape.Length >= 2 ? Shape[1] : Shape.Length == 1 ? Shape[0] : 0;

    public override string ToString() =>
        $"{DType} [{string.Join("×", Shape)}] ({DataLength:N0} bytes)";
}
