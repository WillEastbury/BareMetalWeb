using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace BareMetalWeb.Data;

/// <summary>
/// A fixed-width 32-byte Latin-1 (ISO-8859-1) encoded string key for WAL secondary indexes.
///
/// <para>
/// All secondary-index fields in the WAL store use this canonical encoding so that
/// key comparisons are byte-exact regardless of platform culture:
/// <list type="bullet">
///   <item>Characters in the Latin-1 range (U+0000–U+00FF) are stored as their byte value.</item>
///   <item>Characters outside Latin-1 are replaced with <c>0x3F</c> ('?').</item>
///   <item>The 32-byte buffer is zero-padded on the right when the string is shorter than 32 chars.</item>
///   <item>Strings longer than 32 chars are truncated at 32.</item>
/// </list>
/// </para>
///
/// <para>
/// The struct is stored as four <see cref="ulong"/> words (4 × 8 = 32 bytes) so it
/// can live on the stack without any heap allocation.
/// </para>
///
/// <para>
/// Call <see cref="ToIndexKey"/> to get an <see cref="IndexKey"/> suitable for use in
/// <see cref="ISecondaryIndex.QueryEquals"/> and <see cref="ISecondaryIndex.QueryRange"/>.
/// The conversion produces a stable FNV-1a 64-bit hash of the 32-byte canonical form.
/// </para>
/// </summary>
public readonly struct WalLatin1Key32 : IEquatable<WalLatin1Key32>, IComparable<WalLatin1Key32>
{
    // 32 bytes stored as four uint64 words
    private readonly ulong _w0;
    private readonly ulong _w1;
    private readonly ulong _w2;
    private readonly ulong _w3;

    private WalLatin1Key32(ulong w0, ulong w1, ulong w2, ulong w3)
    {
        _w0 = w0; _w1 = w1; _w2 = w2; _w3 = w3;
    }

    // ── Construction ────────────────────────────────────────────────────────

    /// <summary>
    /// Encodes <paramref name="s"/> as a 32-byte Latin-1 padded key.
    /// Null or empty maps to a zero (all-bytes-zero) key.
    /// </summary>
    public static WalLatin1Key32 FromString(string? s)
    {
        Span<byte> buf = stackalloc byte[32]; // zero-initialised
        if (s is not null)
        {
            int chars = Math.Min(s.Length, 32);
            for (int i = 0; i < chars; i++)
            {
                char c = s[i];
                buf[i] = c <= 0xFF ? (byte)c : (byte)0x3F; // '?' for non-Latin-1
            }
        }
        return FromBytes(buf);
    }

    /// <summary>Wraps an already-encoded 32-byte Latin-1 buffer.</summary>
    public static WalLatin1Key32 FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 32)
        {
            Span<byte> padded = stackalloc byte[32];
            bytes[..Math.Min(bytes.Length, 32)].CopyTo(padded);
            return FromBytes(padded);
        }

        return new WalLatin1Key32(
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(bytes[0..]),
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]),
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(bytes[16..]),
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(bytes[24..]));
    }

    // ── Conversion ───────────────────────────────────────────────────────────

    /// <summary>
    /// Writes the 32-byte Latin-1 canonical form into <paramref name="destination"/>.
    /// </summary>
    public void CopyTo(Span<byte> destination)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(destination[0..],  _w0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(destination[8..],  _w1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(destination[16..], _w2);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(destination[24..], _w3);
    }

    /// <summary>
    /// Returns an <see cref="IndexKey"/> whose <see cref="IndexKey.RawValue"/> is a stable
    /// FNV-1a 64-bit hash of the 32-byte canonical form.
    /// </summary>
    public IndexKey ToIndexKey()
    {
        Span<byte> buf = stackalloc byte[32];
        CopyTo(buf);
        ulong h = 14695981039346656037ul;
        foreach (byte b in buf) { h ^= b; h *= 1099511628211ul; }
        return IndexKey.FromUInt64(h);
    }

    /// <summary>Decodes the 32-byte Latin-1 buffer back to a <see cref="string"/>, trimming trailing NUL bytes.</summary>
    public override string ToString()
    {
        Span<byte> buf = stackalloc byte[32];
        CopyTo(buf);
        int len = buf.Length;
        while (len > 0 && buf[len - 1] == 0) len--;
        // Latin-1 is a direct char-from-byte mapping
        return string.Create(len, buf[..len].ToArray(), static (chars, bytes) =>
        {
            for (int i = 0; i < chars.Length; i++) chars[i] = (char)bytes[i];
        });
    }

    // ── Equality / Comparison ────────────────────────────────────────────────

    public bool Equals(WalLatin1Key32 other) =>
        _w0 == other._w0 && _w1 == other._w1 && _w2 == other._w2 && _w3 == other._w3;

    public override bool Equals(object? obj) => obj is WalLatin1Key32 k && Equals(k);

    public override int GetHashCode() => HashCode.Combine(_w0, _w1, _w2, _w3);

    public int CompareTo(WalLatin1Key32 other)
    {
        // Compare each 8-byte word without any stack allocation.
        // ReverseEndianness converts a little-endian word to big-endian so that
        // a plain ulong numeric comparison equals a left-to-right lexicographic
        // byte comparison of the 8 bytes that word encodes.
        ulong a0 = BinaryPrimitives.ReverseEndianness(_w0);
        ulong b0 = BinaryPrimitives.ReverseEndianness(other._w0);
        int c = a0.CompareTo(b0);
        if (c != 0) return c;

        ulong a1 = BinaryPrimitives.ReverseEndianness(_w1);
        ulong b1 = BinaryPrimitives.ReverseEndianness(other._w1);
        c = a1.CompareTo(b1);
        if (c != 0) return c;

        ulong a2 = BinaryPrimitives.ReverseEndianness(_w2);
        ulong b2 = BinaryPrimitives.ReverseEndianness(other._w2);
        c = a2.CompareTo(b2);
        if (c != 0) return c;

        ulong a3 = BinaryPrimitives.ReverseEndianness(_w3);
        ulong b3 = BinaryPrimitives.ReverseEndianness(other._w3);
        return a3.CompareTo(b3);
    }

    public static bool operator ==(WalLatin1Key32 a, WalLatin1Key32 b) => a.Equals(b);
    public static bool operator !=(WalLatin1Key32 a, WalLatin1Key32 b) => !a.Equals(b);
}
