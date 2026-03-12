using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

public static class CookieProtection
{
    // Version bytes prepended to plaintext before encryption.
    // 0x01 = uncompressed  (current format)
    // 0x02 = deflate-compressed
    // Legacy cookies with no version prefix are also handled in Unprotect.
    private const byte VersionPlain = 0x01;
    private const byte VersionDeflate = 0x02;

    private const int HmacKeySize = 32;
    private static string KeyRootFolder = AppContext.BaseDirectory;

    private static Lazy<SynchronousEncryption> Encryption = new(() =>
        SynchronousEncryption.CreateFromKeyFile(Path.Combine(KeyRootFolder, ".keys", "cookie.enc.key")));

    private static Lazy<byte[]> HmacKey = new(() =>
        LoadOrCreateKey(Path.Combine(KeyRootFolder, ".keys", "cookie.hmac.key"), HmacKeySize));

    public static void ConfigureKeyRoot(string? rootFolder)
    {
        if (string.IsNullOrWhiteSpace(rootFolder))
            throw new ArgumentException("Key root folder cannot be null or whitespace.", nameof(rootFolder));

        KeyRootFolder = rootFolder;
        // Reset lazy initializers so they pick up the new root folder
        Encryption = new(() =>
            SynchronousEncryption.CreateFromKeyFile(Path.Combine(KeyRootFolder, ".keys", "cookie.enc.key")));
        HmacKey = new(() =>
            LoadOrCreateKey(Path.Combine(KeyRootFolder, ".keys", "cookie.hmac.key"), HmacKeySize));
    }

    public static string Protect(string value)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));

        var plaintext = Encoding.UTF8.GetBytes(value);

        // Try deflate compression; use it only if it reduces size
        var compressed = DeflateCompress(plaintext);
        byte[] payload;
        if (compressed.Length < plaintext.Length)
        {
            payload = new byte[1 + compressed.Length];
            payload[0] = VersionDeflate;
            compressed.AsSpan().CopyTo(payload.AsSpan(1));
        }
        else
        {
            payload = new byte[1 + plaintext.Length];
            payload[0] = VersionPlain;
            plaintext.AsSpan().CopyTo(payload.AsSpan(1));
        }

        var encrypted = Encryption.Value.Encrypt(payload);
        var mac = ComputeHmac(encrypted);

        return $"{Base64UrlEncode(encrypted)}.{Base64UrlEncode(mac)}";
    }

    public static string? Unprotect(string? protectedValue)
    {
        if (string.IsNullOrWhiteSpace(protectedValue))
            return null;

        var span = protectedValue.AsSpan();
        int dotIdx = span.IndexOf('.');
        if (dotIdx < 0 || dotIdx == 0 || dotIdx == span.Length - 1)
            return null;

        byte[] encrypted;
        byte[] mac;
        try
        {
            encrypted = Base64UrlDecode(span[..dotIdx].ToString());
            mac = Base64UrlDecode(span[(dotIdx + 1)..].ToString());
        }
        catch (FormatException)
        {
            return null;
        }

        var expectedMac = ComputeHmac(encrypted);
        if (!FixedTimeEquals(mac, expectedMac))
            return null;

        byte[] decrypted;
        try
        {
            decrypted = Encryption.Value.Decrypt(encrypted);
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }

        // Dispatch on version byte; legacy cookies (no version byte) are decoded as-is
        if (decrypted.Length > 0 && decrypted[0] == VersionDeflate)
        {
            try
            {
                var decompressed = DeflateDecompress(decrypted, 1, decrypted.Length - 1);
                return Encoding.UTF8.GetString(decompressed);
            }
            catch
            {
                return null;
            }
        }

        if (decrypted.Length > 0 && decrypted[0] == VersionPlain)
            return Encoding.UTF8.GetString(decrypted, 1, decrypted.Length - 1);

        // Legacy format: no version prefix, entire payload is the UTF-8 string
        return Encoding.UTF8.GetString(decrypted);
    }

    private static byte[] DeflateCompress(ReadOnlySpan<byte> data)
    {
        using var output = new MemoryStream();
        using (var deflate = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
            deflate.Write(data);
        return output.ToArray();
    }

    private const int MaxDecompressedCookieBytes = 1024 * 64; // 64 KB max cookie payload

    private static byte[] DeflateDecompress(byte[] data, int offset, int count)
    {
        using var input = new MemoryStream(data, offset, count, writable: false);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream(count);
        var buffer = new byte[4096];
        int read;
        while ((read = deflate.Read(buffer, 0, buffer.Length)) > 0)
        {
            if (output.Length + read > MaxDecompressedCookieBytes)
                throw new InvalidDataException("Decompressed cookie payload exceeds maximum allowed size.");
            output.Write(buffer, 0, read);
        }
        return output.ToArray();
    }

    private static byte[] ComputeHmac(byte[] payload)
        => HMACSHA256.HashData(HmacKey.Value, payload);

    private static bool FixedTimeEquals(byte[] left, byte[] right)
    {
        if (left.Length != right.Length)
            return false;

        return CryptographicOperations.FixedTimeEquals(left, right);
    }

    private static byte[] LoadOrCreateKey(string keyFilePath, int size)
    {
        if (string.IsNullOrWhiteSpace(keyFilePath))
            throw new ArgumentException("Key file path cannot be null or whitespace.", nameof(keyFilePath));

        var directory = Path.GetDirectoryName(keyFilePath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        if (!File.Exists(keyFilePath))
        {
            var key = new byte[size];
            RandomNumberGenerator.Fill(key);
            File.WriteAllText(keyFilePath, Convert.ToBase64String(SynchronousEncryption.ProtectKeyBytes(key)));
            return key;
        }

        var base64 = File.ReadAllText(keyFilePath).Trim();
        var stored = Convert.FromBase64String(base64);
        var bytes = SynchronousEncryption.UnprotectKeyBytes(stored);
        if (bytes.Length != size)
            throw new InvalidOperationException($"Key must be {size} bytes.");

        return bytes;
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> input)
    {
        var base64 = Convert.ToBase64String(input);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private static byte[] Base64UrlDecode(string input)
    {
        int padLen = (4 - input.Length % 4) % 4;
        int totalLen = input.Length + padLen;
        Span<char> base64 = totalLen <= 256 ? stackalloc char[totalLen] : new char[totalLen];
        for (int i = 0; i < input.Length; i++)
            base64[i] = input[i] switch { '-' => '+', '_' => '/', _ => input[i] };
        for (int i = 0; i < padLen; i++)
            base64[input.Length + i] = '=';

        Span<byte> buffer = new byte[(totalLen * 3 + 3) / 4];
        if (!Convert.TryFromBase64Chars(base64, buffer, out int written))
            throw new FormatException("Invalid base64url input.");
        return buffer[..written].ToArray();
    }
}
