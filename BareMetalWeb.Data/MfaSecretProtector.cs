using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace BareMetalWeb.Data;

public sealed class MfaSecretProtector
{
    private const int KeySize = 32;
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const byte CurrentVersion = 1;
    private readonly byte[] _masterKey;

    private MfaSecretProtector(byte[] masterKey)
    {
        if (masterKey is null) throw new ArgumentNullException(nameof(masterKey));
        if (masterKey.Length != KeySize)
            throw new InvalidOperationException($"Master key must be {KeySize} bytes.");
        _masterKey = masterKey;
    }

    public static MfaSecretProtector CreateDefault(string rootFolder)
    {
        if (string.IsNullOrWhiteSpace(rootFolder))
            throw new ArgumentException("Root folder cannot be null or whitespace.", nameof(rootFolder));

        var keyPath = Path.Combine(rootFolder, ".keys", "mfa-master.key");
        return new MfaSecretProtector(LoadOrCreateKey(keyPath));
    }

    public string EncryptSecret(string secret, string userId)
    {
        if (string.IsNullOrWhiteSpace(secret))
            throw new ArgumentException("Secret cannot be null or empty.", nameof(secret));
        if (string.IsNullOrWhiteSpace(userId))
            throw new ArgumentException("User id is required.", nameof(userId));

        var secretBytes = Encoding.UTF8.GetBytes(secret);
        Span<byte> salt = stackalloc byte[SaltSize];
        Span<byte> nonce = stackalloc byte[NonceSize];
        RandomNumberGenerator.Fill(salt);
        RandomNumberGenerator.Fill(nonce);

        var key = DeriveKey(_masterKey, salt, userId);
        var ciphertext = new byte[secretBytes.Length];
        Span<byte> tag = stackalloc byte[TagSize];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, secretBytes, ciphertext, tag);

            var payload = new byte[1 + SaltSize + NonceSize + TagSize + ciphertext.Length];
            payload[0] = CurrentVersion;
            salt.CopyTo(payload.AsSpan(1));
            nonce.CopyTo(payload.AsSpan(1 + SaltSize));
            tag.CopyTo(payload.AsSpan(1 + SaltSize + NonceSize));
            ciphertext.CopyTo(payload.AsSpan(1 + SaltSize + NonceSize + TagSize));
            return Convert.ToBase64String(payload);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public bool TryDecryptSecret(string payloadBase64, string userId, out byte[] secretBytes)
    {
        secretBytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(payloadBase64) || string.IsNullOrWhiteSpace(userId))
            return false;

        byte[] payload;
        try
        {
            payload = Convert.FromBase64String(payloadBase64);
        }
        catch (FormatException)
        {
            return false;
        }

        if (payload.Length < 1 + SaltSize + NonceSize + TagSize)
            return false;

        if (payload[0] != CurrentVersion)
            return false;

        var salt = payload.AsSpan(1, SaltSize);
        var nonce = payload.AsSpan(1 + SaltSize, NonceSize);
        var tag = payload.AsSpan(1 + SaltSize + NonceSize, TagSize);
        var cipherLen = payload.Length - (1 + SaltSize + NonceSize + TagSize);
        var ciphertext = payload.AsSpan(1 + SaltSize + NonceSize + TagSize, cipherLen);

        var key = DeriveKey(_masterKey, salt, userId);
        var plaintext = new byte[cipherLen];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            secretBytes = plaintext;
            return true;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] DeriveKey(byte[] masterKey, ReadOnlySpan<byte> salt, string userId)
    {
        var info = Encoding.UTF8.GetBytes(userId);
        Span<byte> saltCopy = stackalloc byte[salt.Length];
        salt.CopyTo(saltCopy);
        var prk = HkdfExtract(saltCopy, masterKey);
        var okm = HkdfExpand(prk, info, KeySize);
        CryptographicOperations.ZeroMemory(prk);
        return okm;
    }

    private static byte[] HkdfExtract(ReadOnlySpan<byte> salt, byte[] ikm)
    {
        Span<byte> hash = stackalloc byte[32]; // SHA256 output
        HMACSHA256.HashData(salt, ikm, hash);
        return hash.ToArray();
    }

    private static byte[] HkdfExpand(byte[] prk, byte[] info, int length)
    {
        using var hmac = new HMACSHA256(prk);
        var output = new byte[length];
        var t = Array.Empty<byte>();
        int offset = 0;
        byte counter = 1;

        while (offset < length)
        {
            hmac.Initialize();
            hmac.TransformBlock(t, 0, t.Length, null, 0);
            hmac.TransformBlock(info, 0, info.Length, null, 0);
            hmac.TransformFinalBlock(new[] { counter }, 0, 1);
            t = hmac.Hash ?? Array.Empty<byte>();
            var toCopy = Math.Min(t.Length, length - offset);
            Buffer.BlockCopy(t, 0, output, offset, toCopy);
            offset += toCopy;
            counter++;
        }

        CryptographicOperations.ZeroMemory(t);
        return output;
    }

    private static byte[] LoadOrCreateKey(string keyFilePath)
    {
        var directory = Path.GetDirectoryName(keyFilePath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        if (File.Exists(keyFilePath))
            return File.ReadAllBytes(keyFilePath);

        var key = RandomNumberGenerator.GetBytes(KeySize);
        File.WriteAllBytes(keyFilePath, key);
        return key;
    }
}
