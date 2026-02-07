using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace BareMetalWeb.Data;

using BareMetalWeb.Interfaces;

public sealed class SynchronousEncryption : ISynchronousEncryption
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const byte FormatVersion = 1;

    private readonly byte[] _key;

    private SynchronousEncryption(byte[] key)
    {
        _key = key;
    }

    public static SynchronousEncryption CreateDefault(string rootFolder)
    {
        if (string.IsNullOrWhiteSpace(rootFolder))
            throw new ArgumentException("Root folder cannot be null or whitespace.", nameof(rootFolder));

        var keyPath = Path.Combine(rootFolder, ".keys", "encryption.key");
        return CreateFromKeyFile(keyPath);
    }

    public static SynchronousEncryption CreateFromKeyFile(string keyFilePath)
    {
        if (string.IsNullOrWhiteSpace(keyFilePath))
            throw new ArgumentException("Key file path cannot be null or whitespace.", nameof(keyFilePath));

        EnsureKeyFile(keyFilePath);
        var key = LoadKey(keyFilePath);
        return new SynchronousEncryption(key);
    }

    public static void EnsureKeyFile(string keyFilePath)
    {
        if (string.IsNullOrWhiteSpace(keyFilePath))
            throw new ArgumentException("Key file path cannot be null or whitespace.", nameof(keyFilePath));

        var directory = Path.GetDirectoryName(keyFilePath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        if (File.Exists(keyFilePath))
            return;

        var key = new byte[KeySize];
        RandomNumberGenerator.Fill(key);
        var base64 = Convert.ToBase64String(key);
        File.WriteAllText(keyFilePath, base64);
    }

    public byte[] Encrypt(byte[] plaintext, byte[]? associatedData = null)
    {
        if (plaintext is null) throw new ArgumentNullException(nameof(plaintext));

        var nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        var payload = new byte[1 + NonceSize + TagSize + ciphertext.Length];
        payload[0] = FormatVersion;
        Buffer.BlockCopy(nonce, 0, payload, 1, NonceSize);
        Buffer.BlockCopy(tag, 0, payload, 1 + NonceSize, TagSize);
        Buffer.BlockCopy(ciphertext, 0, payload, 1 + NonceSize + TagSize, ciphertext.Length);
        return payload;
    }

    public byte[] Decrypt(byte[] payload, byte[]? associatedData = null)
    {
        if (payload is null) throw new ArgumentNullException(nameof(payload));
        if (payload.Length < 1 + NonceSize + TagSize)
            throw new ArgumentException("Payload is too short.", nameof(payload));

        var version = payload[0];
        if (version != FormatVersion)
            throw new InvalidOperationException($"Unsupported payload version {version}.");

        var nonce = new byte[NonceSize];
        var tag = new byte[TagSize];
        var ciphertext = new byte[payload.Length - 1 - NonceSize - TagSize];

        Buffer.BlockCopy(payload, 1, nonce, 0, NonceSize);
        Buffer.BlockCopy(payload, 1 + NonceSize, tag, 0, TagSize);
        Buffer.BlockCopy(payload, 1 + NonceSize + TagSize, ciphertext, 0, ciphertext.Length);

        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(_key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    public string EncryptToBase64(string plaintext, byte[]? associatedData = null)
    {
        if (plaintext is null) throw new ArgumentNullException(nameof(plaintext));
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var payload = Encrypt(bytes, associatedData);
        return Convert.ToBase64String(payload);
    }

    public string DecryptFromBase64(string payloadBase64, byte[]? associatedData = null)
    {
        if (payloadBase64 is null) throw new ArgumentNullException(nameof(payloadBase64));
        var payload = Convert.FromBase64String(payloadBase64);
        var plaintext = Decrypt(payload, associatedData);
        return Encoding.UTF8.GetString(plaintext);
    }

    private static byte[] LoadKey(string keyFilePath)
    {
        var base64 = File.ReadAllText(keyFilePath).Trim();
        var key = Convert.FromBase64String(base64);
        if (key.Length != KeySize)
            throw new InvalidOperationException($"Key must be {KeySize} bytes.");
        return key;
    }
}
