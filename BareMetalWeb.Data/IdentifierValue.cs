using System;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace BareMetalWeb.Data;

/// <summary>
/// A compact, fixed-width human-readable identifier encoded in base-37.
/// Character set: A-Z (0-25), 0-9 (26-35), hyphen (36). Max 25 characters.
/// Stored as two ulong values (16 bytes total).
/// Accented characters are normalized to ASCII uppercase on parse.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public readonly struct IdentifierValue : IEquatable<IdentifierValue>, IComparable<IdentifierValue>
{
    public const int MaxLength = 25;
    public const int Base = 37;
    public const int ByteSize = 16;

    // A=0..Z=25, 0=26..9=35, -=36
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";

    public readonly ulong Hi;
    public readonly ulong Lo;

    public IdentifierValue(ulong hi, ulong lo)
    {
        Hi = hi;
        Lo = lo;
    }

    public static readonly IdentifierValue Empty = default;

    public bool IsEmpty => Hi == 0 && Lo == 0;

    /// <summary>
    /// Parses a human-readable identifier string into an IdentifierValue.
    /// Strips accents, uppercases, rejects invalid chars.
    /// </summary>
    public static IdentifierValue Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return Empty;

        var normalized = NormalizeToAscii(value);
        if (normalized.Length == 0)
            return Empty;
        if (normalized.Length > MaxLength)
            throw new ArgumentException($"Identifier exceeds maximum length of {MaxLength} characters.", nameof(value));

        // Encode as base-37 into 128-bit (two ulongs)
        // Process left to right: result = result * 37 + digit
        // We use 128-bit arithmetic via hi/lo pair
        ulong hi = 0, lo = 0;
        for (int i = 0; i < normalized.Length; i++)
        {
            int digit = CharToDigit(normalized[i]);
            if (digit < 0)
                throw new ArgumentException($"Invalid character '{normalized[i]}' in identifier. Allowed: A-Z, 0-9, hyphen.", nameof(value));

            // Multiply 128-bit (hi,lo) by 37 and add digit
            Multiply128By37AndAdd(ref hi, ref lo, (ulong)digit);
        }

        // Store length in top 5 bits of hi (25 fits in 5 bits)
        hi |= (ulong)normalized.Length << 59;

        return new IdentifierValue(hi, lo);
    }

    /// <summary>
    /// Tries to parse a string into an IdentifierValue. Returns false on failure.
    /// </summary>
    public static bool TryParse(string? value, out IdentifierValue result)
    {
        result = Empty;
        if (string.IsNullOrWhiteSpace(value))
            return true;

        try
        {
            result = Parse(value);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public override string ToString()
    {
        if (Hi == 0 && Lo == 0)
            return string.Empty;

        // Extract length from top 5 bits of hi
        int length = (int)(Hi >> 59) & 0x1F;
        if (length == 0 || length > MaxLength)
            return string.Empty;

        // Mask out the length bits to get the numeric value
        ulong hi = Hi & 0x07FFFFFFFFFFFFFF;
        ulong lo = Lo;

        // Decode base-37 digits right to left
        Span<char> chars = stackalloc char[length];
        for (int i = length - 1; i >= 0; i--)
        {
            Divide128By37(ref hi, ref lo, out ulong remainder);
            chars[i] = Alphabet[(int)remainder];
        }

        return new string(chars);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int CharToDigit(char c) => c switch
    {
        >= 'A' and <= 'Z' => c - 'A',
        >= '0' and <= '9' => c - '0' + 26,
        '-' => 36,
        _ => -1
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Multiply128By37AndAdd(ref ulong hi, ref ulong lo, ulong add)
    {
        // 128-bit multiply by 37: (hi:lo) * 37 + add
        // lo * 37
        ulong loProduct = lo * 37;
        ulong loCarry = Math.BigMul(lo, 37, out ulong loResult);
        // hi * 37 + carry
        ulong hiResult = hi * 37 + loCarry;
        lo = loResult + add;
        if (lo < loResult) hiResult++; // handle add overflow
        hi = hiResult;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Divide128By37(ref ulong hi, ref ulong lo, out ulong remainder)
    {
        // Divide 128-bit (hi:lo) by 37, return quotient in (hi:lo) and remainder
        ulong qHi = hi / 37;
        ulong rHi = hi % 37;

        // Combine remainder with lo: (rHi << 64) + lo
        // We need to divide (rHi * 2^64 + lo) by 37
        // rHi is at most 36, so rHi * 2^64 fits conceptually
        // Use the identity: (rHi * 2^64 + lo) / 37
        ulong combined = (rHi << 32) | (lo >> 32); // upper 64 bits of shifted value
        ulong qMid = combined / 37;
        ulong rMid = combined % 37;

        ulong lowerCombined = (rMid << 32) | (lo & 0xFFFFFFFF);
        ulong qLo = lowerCombined / 37;
        remainder = lowerCombined % 37;

        hi = qHi;
        lo = (qMid << 32) | qLo;
    }

    /// <summary>
    /// Normalizes a string: strips accents/diacritics, uppercases, keeps only A-Z, 0-9, hyphen.
    /// </summary>
    private static string NormalizeToAscii(string input)
    {
        // Normalize to decomposed form so accents become separate chars
        var decomposed = input.Normalize(NormalizationForm.FormD);
        Span<char> buffer = stackalloc char[decomposed.Length];
        int pos = 0;

        for (int i = 0; i < decomposed.Length; i++)
        {
            var category = CharUnicodeInfo.GetUnicodeCategory(decomposed[i]);
            if (category == UnicodeCategory.NonSpacingMark)
                continue; // skip accent marks

            char c = char.ToUpperInvariant(decomposed[i]);
            if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')
            {
                buffer[pos++] = c;
            }
        }

        return new string(buffer[..pos]);
    }

    // Equality & comparison
    public bool Equals(IdentifierValue other) => Hi == other.Hi && Lo == other.Lo;
    public override bool Equals(object? obj) => obj is IdentifierValue other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(Hi, Lo);
    public static bool operator ==(IdentifierValue left, IdentifierValue right) => left.Equals(right);
    public static bool operator !=(IdentifierValue left, IdentifierValue right) => !left.Equals(right);

    public int CompareTo(IdentifierValue other)
    {
        int cmp = Hi.CompareTo(other.Hi);
        return cmp != 0 ? cmp : Lo.CompareTo(other.Lo);
    }

    /// <summary>
    /// Writes the 16-byte binary representation (hi LE, lo LE) to a span.
    /// </summary>
    public void WriteTo(Span<byte> destination)
    {
        if (destination.Length < ByteSize)
            throw new ArgumentException("Destination too small.", nameof(destination));
        BitConverter.TryWriteBytes(destination, Hi);
        BitConverter.TryWriteBytes(destination[8..], Lo);
    }

    /// <summary>
    /// Reads a 16-byte binary representation from a span.
    /// </summary>
    public static IdentifierValue ReadFrom(ReadOnlySpan<byte> source)
    {
        if (source.Length < ByteSize)
            throw new ArgumentException("Source too small.", nameof(source));
        ulong hi = BitConverter.ToUInt64(source);
        ulong lo = BitConverter.ToUInt64(source[8..]);
        return new IdentifierValue(hi, lo);
    }
}
