using System.Numerics;
using System.Runtime.InteropServices;
#if NET7_0_OR_GREATER
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
#endif

namespace BareMetalWeb.Data;

/// <summary>
/// Describes which hardware-accelerated code paths are active in the data layer
/// on the current CPU. Use <see cref="Describe"/> to obtain a human-readable
/// summary suitable for startup logs and the metrics dashboard.
/// </summary>
public static class DataLayerCapabilities
{
    /// <summary>
    /// The acceleration path used by <c>SimdDistance</c> for vector distance
    /// calculations (cosine, dot-product, Euclidean).
    /// </summary>
    public static string VectorDistancePath => SimdDistance.ActivePath;

    /// <summary>
    /// The acceleration path used by <c>WalCrc32C</c> for checksum computation.
    /// </summary>
    public static string Crc32CPath
    {
        get
        {
#if NET7_0_OR_GREATER
            if (Crc32.Arm64.IsSupported) return "ARM64 CRC32C (64-bit, hardware)";
            if (Sse42.X64.IsSupported)   return "x86 SSE4.2 CRC32Q (64-bit, hardware)";
            if (Sse42.IsSupported)       return "x86 SSE4.2 CRC32D (32-bit, hardware)";
#endif
            return "Software slicing-by-4 (no hardware CRC)";
        }
    }

    /// <summary>
    /// The acceleration path used by <c>WalLatin1Key32.CompareTo</c> for
    /// 32-byte key comparison.
    /// </summary>
    public static string KeyComparisonPath =>
        "Direct ulong word comparison (4 × 64-bit, zero allocation)";

    /// <summary>
    /// The SIMD acceleration path used by <see cref="ColumnQueryExecutor"/> for
    /// batch-vectorised column scanning during full-table queries.
    /// </summary>
    public static string ColumnQueryPath
    {
        get
        {
            string tier = SimdCapabilities.Current.BestTier;
            int intWidth  = Vector<int>.Count * sizeof(int) * 8;
            int longWidth = Vector<long>.Count * sizeof(long) * 8;
            return $"Vector<T> portable SIMD ({tier}): {intWidth}-bit int lane, " +
                   $"{longWidth}-bit long lane | threshold={ColumnQueryExecutor.VectorizationThreshold} rows";
        }
    }

    /// <summary>
    /// The path used by <c>SearchIndexManager</c> for bloom filter hashing.
    /// </summary>
    public static string BloomFilterPath =>
        "OrdinalIgnoreCase hash (zero-allocation, software)";

    /// <summary>
    /// The path used for schema hash computation.
    /// </summary>
    public static string SchemaHashPath =>
        "SHA256 (managed, software)";

    /// <summary>
    /// The acceleration path used by <see cref="SimdByteScanner.FindByte"/> for
    /// scanning raw byte buffers (binary protocol parsing, template byte streams, etc.).
    /// </summary>
    public static string ByteScanPath => SimdByteScanner.ActivePath;

    /// <summary>
    /// Returns a multi-line human-readable description of all active
    /// data-layer hardware acceleration paths.
    /// </summary>
    public static string Describe()
    {
        return
            $"Portable SIMD width : {Vector<float>.Count * sizeof(float) * 8}-bit " +
            $"({Vector<float>.Count} floats/iter, Vector<float> baseline)\n" +
            $"Vector distance     : {VectorDistancePath}\n" +
            $"Column query scan   : {ColumnQueryPath}\n" +
            $"CRC-32C             : {Crc32CPath}\n" +
            $"Key comparison      : {KeyComparisonPath}\n" +
            $"Bloom filter        : {BloomFilterPath}\n" +
            $"Schema hash         : {SchemaHashPath}\n" +
            $"Byte scanner        : {ByteScanPath}";
    }
}
