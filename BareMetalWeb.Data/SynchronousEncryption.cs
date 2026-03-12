using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using BareMetalWeb.Core.Interfaces;
namespace BareMetalWeb.Data;

public sealed class SynchronousEncryption : ISynchronousEncryption
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const byte FormatVersion = 1;

    // Magic header prefix for key files protected with ProtectKeyBytes.
    internal static readonly byte[] KeyFileMagic = { 0x4B, 0x50, 0x52, 0x54 }; // "KPRT"

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
        // SECURITY: Encryption key files are stored as plaintext Base64 on disk. Any file-system
        // access (container escape, backup exposure, misconfigured permissions) results in full key
        // compromise. Ensure restrictive file permissions (chmod 600) on the .keys/ directory.
        // For production, consider OS key storage (Linux keyring, DPAPI) or KMS integration.
        // See issue #1200.
        if (string.IsNullOrWhiteSpace(keyFilePath))
            throw new ArgumentException("Key file path cannot be null or whitespace.", nameof(keyFilePath));

        var directory = Path.GetDirectoryName(keyFilePath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        if (File.Exists(keyFilePath))
            return;

        var key = new byte[KeySize];
        RandomNumberGenerator.Fill(key);
        File.WriteAllText(keyFilePath, Convert.ToBase64String(ProtectKeyBytes(key)));
    }

    public byte[] Encrypt(byte[] plaintext, byte[]? associatedData = null)
    {
        if (plaintext is null) throw new ArgumentNullException(nameof(plaintext));

        Span<byte> nonce = stackalloc byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[TagSize];

        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        int payloadSize = checked(1 + NonceSize + TagSize + ciphertext.Length);
        var payload = new byte[payloadSize];
        payload[0] = FormatVersion;
        nonce.CopyTo(payload.AsSpan(1));
        tag.CopyTo(payload.AsSpan(1 + NonceSize));
        ciphertext.AsSpan().CopyTo(payload.AsSpan(1 + NonceSize + TagSize));
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

        var span = payload.AsSpan();
        var nonce = span.Slice(1, NonceSize);
        var tag = span.Slice(1 + NonceSize, TagSize);
        var ciphertext = span.Slice(1 + NonceSize + TagSize);

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
        var stored = Convert.FromBase64String(base64);
        var key = UnprotectKeyBytes(stored);
        if (key.Length != KeySize)
            throw new InvalidOperationException($"Key must be {KeySize} bytes.");
        return key;
    }

    /// <summary>
    /// Wraps raw key bytes in an AES-256-GCM envelope keyed from machine identity.
    /// Prefixed with the "KPRT" magic header so legacy plaintext key files are
    /// handled transparently by <see cref="UnprotectKeyBytes"/>.
    /// </summary>
    internal static byte[] ProtectKeyBytes(byte[] key)
    {
        var machineKey = DeriveMachineKey();
        var nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        var ciphertext = new byte[key.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(machineKey, 16);
        aes.Encrypt(nonce, key, ciphertext, tag);
        // Layout: magic(4) + nonce(12) + tag(16) + ciphertext
        var result = new byte[KeyFileMagic.Length + nonce.Length + tag.Length + ciphertext.Length];
        int pos = 0;
        KeyFileMagic.CopyTo(result, pos); pos += KeyFileMagic.Length;
        nonce.CopyTo(result, pos); pos += nonce.Length;
        tag.CopyTo(result, pos); pos += tag.Length;
        ciphertext.CopyTo(result, pos);
        return result;
    }

    /// <summary>
    /// Unwraps a key file blob produced by <see cref="ProtectKeyBytes"/>.
    /// If the blob does not start with the "KPRT" magic header, it is assumed to be a
    /// legacy plaintext key and returned unchanged for backward compatibility.
    /// </summary>
    internal static byte[] UnprotectKeyBytes(byte[] stored)
    {
        if (stored.Length < KeyFileMagic.Length || !stored.AsSpan(0, KeyFileMagic.Length).SequenceEqual(KeyFileMagic))
            return stored; // Legacy plaintext — return as-is for backward compat
        var blob = stored[KeyFileMagic.Length..];
        var machineKey = DeriveMachineKey();
        const int nonceLen = 12, tagLen = 16;
        var nonce = blob.AsSpan(0, nonceLen);
        var tag = blob.AsSpan(nonceLen, tagLen);
        var ciphertext = blob.AsSpan(nonceLen + tagLen);
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(machineKey, tagLen);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    private static byte[] DeriveMachineKey()
    {
        string machineId = "baremetalweb-default";
        try { machineId = File.Exists("/etc/machine-id") ? File.ReadAllText("/etc/machine-id").Trim() : Environment.MachineName; } catch { }
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            Encoding.UTF8.GetBytes(machineId),
            32,
            Encoding.UTF8.GetBytes("BareMetalWeb.KeyFile.v1"),
            Encoding.UTF8.GetBytes("key-protection"));
    }
}
