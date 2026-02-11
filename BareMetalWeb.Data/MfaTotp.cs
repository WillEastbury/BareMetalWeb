using System;
using System.Security.Cryptography;
using System.Text;

namespace BareMetalWeb.Data;

public static class MfaTotp
{
    private const int DefaultDigits = 6;
    private const int DefaultPeriod = 30;
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string GenerateSecret(int numBytes = 20)
    {
        if (numBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(numBytes));

        var bytes = new byte[numBytes];
        RandomNumberGenerator.Fill(bytes);
        return ToBase32(bytes);
    }

    public static string GetOtpAuthUri(string issuer, string accountName, string secret)
    {
        if (string.IsNullOrWhiteSpace(issuer)) throw new ArgumentException("Issuer is required.", nameof(issuer));
        if (string.IsNullOrWhiteSpace(accountName)) throw new ArgumentException("Account name is required.", nameof(accountName));
        if (string.IsNullOrWhiteSpace(secret)) throw new ArgumentException("Secret is required.", nameof(secret));

        var escapedIssuer = Uri.EscapeDataString(issuer);
        var escapedAccount = Uri.EscapeDataString(accountName);
        return $"otpauth://totp/{escapedIssuer}:{escapedAccount}?secret={secret}&issuer={escapedIssuer}";
    }

    public static bool ValidateCode(string secretBase32, string code, out long matchedStep, int allowedDriftSteps = 1)
    {
        matchedStep = 0;
        if (string.IsNullOrWhiteSpace(secretBase32) || string.IsNullOrWhiteSpace(code))
            return false;

        if (!TryFromBase32(secretBase32, out var key))
            return false;

        var normalized = NormalizeCode(code, DefaultDigits);
        if (normalized == null)
            return false;

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var currentStep = now / DefaultPeriod;

        for (long step = currentStep - allowedDriftSteps; step <= currentStep + allowedDriftSteps; step++)
        {
            var expected = ComputeCode(key, step);
            if (FixedTimeEquals(expected, normalized))
            {
                matchedStep = step;
                return true;
            }
        }

        return false;
    }

    private static string ComputeCode(byte[] key, long step)
    {
        Span<byte> counter = stackalloc byte[8];
        for (int i = 7; i >= 0; i--)
        {
            counter[i] = (byte)(step & 0xff);
            step >>= 8;
        }

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(counter.ToArray());

        int offset = hash[^1] & 0x0f;
        int binary = ((hash[offset] & 0x7f) << 24)
                     | ((hash[offset + 1] & 0xff) << 16)
                     | ((hash[offset + 2] & 0xff) << 8)
                     | (hash[offset + 3] & 0xff);

        int otp = binary % (int)Math.Pow(10, DefaultDigits);
        return otp.ToString($"D{DefaultDigits}");
    }

    private static string? NormalizeCode(string code, int digits)
    {
        var trimmed = code.Trim();
        if (trimmed.Length != digits)
            return null;

        for (int i = 0; i < trimmed.Length; i++)
        {
            if (trimmed[i] < '0' || trimmed[i] > '9')
                return null;
        }

        return trimmed;
    }

    private static bool FixedTimeEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        if (leftBytes.Length != rightBytes.Length)
            return false;

        return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    private static string ToBase32(byte[] data)
    {
        if (data.Length == 0)
            return string.Empty;

        var output = new StringBuilder((data.Length + 4) / 5 * 8);
        int buffer = data[0];
        int next = 1;
        int bitsLeft = 8;

        while (bitsLeft > 0 || next < data.Length)
        {
            if (bitsLeft < 5)
            {
                if (next < data.Length)
                {
                    buffer <<= 8;
                    buffer |= data[next++] & 0xff;
                    bitsLeft += 8;
                }
                else
                {
                    int pad = 5 - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }

            int index = (buffer >> (bitsLeft - 5)) & 0x1f;
            bitsLeft -= 5;
            output.Append(Base32Alphabet[index]);
        }

        return output.ToString();
    }

    private static bool TryFromBase32(string input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input))
            return false;

        var normalized = input.Trim().Replace("=", string.Empty).ToUpperInvariant();
        var output = new byte[normalized.Length * 5 / 8];

        int buffer = 0;
        int bitsLeft = 0;
        int outputIndex = 0;

        foreach (var c in normalized)
        {
            int val = Base32Alphabet.IndexOf(c);
            if (val < 0)
                return false;

            buffer <<= 5;
            buffer |= val & 0x1f;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                output[outputIndex++] = (byte)((buffer >> (bitsLeft - 8)) & 0xff);
                bitsLeft -= 8;
            }
        }

        if (outputIndex == output.Length)
        {
            bytes = output;
            return true;
        }

        if (outputIndex > 0)
        {
            bytes = new byte[outputIndex];
            Array.Copy(output, bytes, outputIndex);
            return true;
        }

        return false;
    }
}
