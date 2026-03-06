using System.Numerics;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// Dictionary-encodes a column of repeated values into a compact dictionary + index array.
/// Reduces memory footprint and enables SIMD filtering via integer index comparison
/// instead of full value comparison.
///
/// <para>Compression tiers based on cardinality:
///   ≤ 256 unique values  → indexes stored as <c>byte[]</c>
///   ≤ 65 535              → indexes stored as <c>ushort[]</c>
///   otherwise             → indexes stored as <c>int[]</c>
/// </para>
/// </summary>
public sealed class DictionaryEncodedColumn<T> where T : notnull
{
    /// <summary>Unique values; index position is the dictionary code.</summary>
    public T[] DictionaryValues { get; }

    /// <summary>Number of unique values in the dictionary.</summary>
    public int Cardinality => DictionaryValues.Length;

    /// <summary>Number of rows encoded.</summary>
    public int RowCount { get; }

    // Exactly one of these is non-null, depending on cardinality.
    private readonly byte[]?   _byteIndexes;
    private readonly ushort[]? _ushortIndexes;
    private readonly int[]?    _intIndexes;

    /// <summary>Active compression tier for diagnostics.</summary>
    public IndexTier Tier { get; }

    public enum IndexTier : byte { Byte = 1, UShort = 2, Int = 4 }

    private DictionaryEncodedColumn(
        T[] dictionaryValues,
        int rowCount,
        byte[]? byteIndexes,
        ushort[]? ushortIndexes,
        int[]? intIndexes,
        IndexTier tier)
    {
        DictionaryValues = dictionaryValues;
        RowCount         = rowCount;
        _byteIndexes     = byteIndexes;
        _ushortIndexes   = ushortIndexes;
        _intIndexes      = intIndexes;
        Tier             = tier;
    }

    /// <summary>
    /// Encodes <paramref name="input"/> into a dictionary + compressed index array.
    /// Single-pass: builds dictionary and indexes simultaneously.
    /// </summary>
    public static DictionaryEncodedColumn<T> Encode(ReadOnlySpan<T> input)
    {
        int n = input.Length;
        if (n == 0)
            return new DictionaryEncodedColumn<T>([], 0, [], null, null, IndexTier.Byte);

        // Pre-size dictionary: heuristic cap at input length (worst case: all unique).
        var lookup = new Dictionary<T, int>(Math.Min(n, 4096));
        var tempIndexes = new int[n];
        var values = new List<T>(Math.Min(n, 256));

        for (int i = 0; i < n; i++)
        {
            T val = input[i];
            if (!lookup.TryGetValue(val, out int code))
            {
                code = values.Count;
                lookup[val] = code;
                values.Add(val);
            }
            tempIndexes[i] = code;
        }

        T[] dict = values.ToArray();
        int cardinality = dict.Length;

        // Select compression tier and copy indexes into the smallest array type.
        if (cardinality <= 256)
        {
            var indexes = new byte[n];
            for (int i = 0; i < n; i++) indexes[i] = (byte)tempIndexes[i];
            return new DictionaryEncodedColumn<T>(dict, n, indexes, null, null, IndexTier.Byte);
        }
        if (cardinality <= 65_535)
        {
            var indexes = new ushort[n];
            for (int i = 0; i < n; i++) indexes[i] = (ushort)tempIndexes[i];
            return new DictionaryEncodedColumn<T>(dict, n, null, indexes, null, IndexTier.UShort);
        }
        return new DictionaryEncodedColumn<T>(dict, n, null, null, tempIndexes, IndexTier.Int);
    }

    /// <summary>
    /// Reconstructs the original column from dictionary + indexes.
    /// </summary>
    public void Decode(Span<T> output)
    {
        if (output.Length < RowCount)
            throw new ArgumentException($"Output span too small: need {RowCount}, got {output.Length}");

        switch (Tier)
        {
            case IndexTier.Byte:
                for (int i = 0; i < RowCount; i++) output[i] = DictionaryValues[_byteIndexes![i]];
                break;
            case IndexTier.UShort:
                for (int i = 0; i < RowCount; i++) output[i] = DictionaryValues[_ushortIndexes![i]];
                break;
            case IndexTier.Int:
                for (int i = 0; i < RowCount; i++) output[i] = DictionaryValues[_intIndexes![i]];
                break;
        }
    }

    /// <summary>
    /// Copies encoded indexes into <paramref name="output"/> as <c>int[]</c>,
    /// suitable for SIMD filtering via <see cref="DictionaryColumnFilter.FilterEquals"/>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void GetEncodedIndexesAsInt(Span<int> output)
    {
        if (output.Length < RowCount)
            throw new ArgumentException($"Output span too small: need {RowCount}, got {output.Length}");

        switch (Tier)
        {
            case IndexTier.Byte:
                for (int i = 0; i < RowCount; i++) output[i] = _byteIndexes![i];
                break;
            case IndexTier.UShort:
                for (int i = 0; i < RowCount; i++) output[i] = _ushortIndexes![i];
                break;
            case IndexTier.Int:
                _intIndexes.AsSpan(0, RowCount).CopyTo(output);
                break;
        }
    }

    /// <summary>
    /// Returns a <see cref="ReadOnlySpan{Int32}"/> over the raw int indexes
    /// (only available when <see cref="Tier"/> is <see cref="IndexTier.Int"/>).
    /// For byte/ushort tiers, use <see cref="GetEncodedIndexesAsInt"/> instead.
    /// </summary>
    public ReadOnlySpan<int> RawIntIndexes =>
        Tier == IndexTier.Int ? _intIndexes.AsSpan(0, RowCount) : default;

    /// <summary>
    /// Looks up the dictionary code for <paramref name="value"/>.
    /// Returns -1 if the value is not in the dictionary.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int LookupCode(T value)
    {
        var dict = DictionaryValues;
        for (int i = 0; i < dict.Length; i++)
            if (EqualityComparer<T>.Default.Equals(dict[i], value))
                return i;
        return -1;
    }
}
