using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

public static class CookieProtection
{
    private const int HmacKeySize = 32;
    private static string KeyRootFolder = AppContext.BaseDirectory;

    private static readonly Lazy<SynchronousEncryption> Encryption = new(() =>
        SynchronousEncryption.CreateFromKeyFile(Path.Combine(KeyRootFolder, ".keys", "cookie.enc.key")));

    private static readonly Lazy<byte[]> HmacKey = new(() =>
        LoadOrCreateKey(Path.Combine(KeyRootFolder, ".keys", "cookie.hmac.key"), HmacKeySize));

    public static void ConfigureKeyRoot(string rootFolder)
    {
        if (string.IsNullOrWhiteSpace(rootFolder))
            throw new ArgumentException("Key root folder cannot be null or whitespace.", nameof(rootFolder));

        KeyRootFolder = rootFolder;
    }

    public static string Protect(string value)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));

        var plaintext = Encoding.UTF8.GetBytes(value);
        var encrypted = Encryption.Value.Encrypt(plaintext);
        var mac = ComputeHmac(encrypted);

        return $"{Base64UrlEncode(encrypted)}.{Base64UrlEncode(mac)}";
    }

    public static string? Unprotect(string protectedValue)
    {
        if (string.IsNullOrWhiteSpace(protectedValue))
            return null;

        var parts = protectedValue.Split('.', 2, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2)
            return null;

        byte[] encrypted;
        byte[] mac;
        try
        {
            encrypted = Base64UrlDecode(parts[0]);
            mac = Base64UrlDecode(parts[1]);
        }
        catch (FormatException)
        {
            return null;
        }

        var expectedMac = ComputeHmac(encrypted);
        if (!FixedTimeEquals(mac, expectedMac))
            return null;

        try
        {
            var plaintext = Encryption.Value.Decrypt(encrypted);
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static byte[] ComputeHmac(byte[] payload)
    {
        using var hmac = new HMACSHA256(HmacKey.Value);
        return hmac.ComputeHash(payload);
    }

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
            File.WriteAllText(keyFilePath, Convert.ToBase64String(key));
            return key;
        }

        var base64 = File.ReadAllText(keyFilePath).Trim();
        var bytes = Convert.FromBase64String(base64);
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
        var base64 = input.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2:
                base64 += "==";
                break;
            case 3:
                base64 += "=";
                break;
        }
        return Convert.FromBase64String(base64);
    }
}
