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
    private const int SaltSize = 32;

    // Magic header prefix for key files protected with ProtectKeyBytes.
    internal static readonly byte[] KeyFileMagic = { 0x4B, 0x50, 0x52, 0x54 }; // "KPRT"

    private static string _keyRoot = AppContext.BaseDirectory;

    private readonly byte[] _key;

    private SynchronousEncryption(byte[] key)
    {
        _key = key;
    }

    /// <summary>
    /// Sets the root directory used for salt storage in envelope key derivation.
    /// Must be called before any key operations. Defaults to AppContext.BaseDirectory.
    /// </summary>
    public static void ConfigureKeyRoot(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Key root cannot be null or whitespace.", nameof(root));
        _keyRoot = root;
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
        // Key files are wrapped with a machine-derived envelope key (see DeriveMachineKey).
        // The envelope key is derived from an identity source (env var, pod name, or machine-id)
        // combined with a persisted random salt. The key file itself is never plaintext on disk
        // when the KPRT wrapping is active.
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
    /// Tries the current derivation first, then falls back to the legacy (v1) derivation
    /// for smooth upgrades. If the legacy path succeeds the file is NOT re-wrapped automatically
    /// — the caller may re-wrap by writing ProtectKeyBytes(result) back to the file.
    /// </summary>
    internal static byte[] UnprotectKeyBytes(byte[] stored)
    {
        if (stored.Length < KeyFileMagic.Length || !stored.AsSpan(0, KeyFileMagic.Length).SequenceEqual(KeyFileMagic))
            return stored; // Legacy plaintext — return as-is for backward compat

        var blob = stored[KeyFileMagic.Length..];

        // Try current derivation (v2 — envelope with persisted salt)
        try
        {
            return UnwrapKprt(blob, DeriveMachineKey());
        }
        catch (CryptographicException) { }

        // Fall back to legacy derivation (v1 — no salt, ATECC/machine-id only)
        try
        {
            var key = UnwrapKprt(blob, DeriveMachineKeyLegacy());
            Console.Error.WriteLine("[BMW Security] Key file unwrapped using legacy derivation — " +
                "delete .keys/ directory to regenerate with the current envelope scheme.");
            return key;
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException(
                "Cannot unwrap key file — machine key mismatch. If the deployment environment " +
                "changed, delete the .keys/ directory to regenerate keys (existing encrypted data " +
                "will be lost) or set BMW_ENCRYPTION_KEY to the original key.");
        }
    }

    private static byte[] UnwrapKprt(ReadOnlySpan<byte> blob, byte[] machineKey)
    {
        const int nonceLen = 12, tagLen = 16;
        var nonce = blob[..nonceLen];
        var tag = blob.Slice(nonceLen, tagLen);
        var ciphertext = blob[(nonceLen + tagLen)..];
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(machineKey, tagLen);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    /// <summary>
    /// Three-tier key derivation waterfall:
    /// 1. BMW_ENCRYPTION_KEY env var → direct use (production, injected by K8s/App Service)
    /// 2. KUBERNETES_SERVICE_HOST set → HOSTNAME (StatefulSet pod identity) + persisted salt → HKDF
    /// 3. Neither → /etc/machine-id or MachineName + persisted salt → HKDF
    /// The derived key never touches disk — only the random salt is persisted.
    /// </summary>
    private static byte[] DeriveMachineKey()
    {
        // Tier 1: Explicit env var (production — K8s secret / App Service config)
        var envKey = Environment.GetEnvironmentVariable("BMW_ENCRYPTION_KEY");
        if (!string.IsNullOrWhiteSpace(envKey))
        {
            byte[] keyBytes;
            try { keyBytes = Convert.FromBase64String(envKey); }
            catch (FormatException)
            {
                throw new InvalidOperationException(
                    "BMW_ENCRYPTION_KEY is not valid Base64. Provide a 32-byte key encoded as Base64.");
            }
            if (keyBytes.Length != KeySize)
                throw new InvalidOperationException(
                    $"BMW_ENCRYPTION_KEY must be exactly {KeySize} bytes ({KeySize * 8}-bit). " +
                    $"Got {keyBytes.Length} bytes.");
            return keyBytes;
        }

        // Determine identity source (never stored on disk)
        string identity;
        if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("KUBERNETES_SERVICE_HOST")))
        {
            // Tier 2: K8s StatefulSet — HOSTNAME is stable (e.g. "bmw-0")
            identity = Environment.GetEnvironmentVariable("HOSTNAME") ?? Environment.MachineName;
            Console.Error.WriteLine(
                "[BMW Security] No BMW_ENCRYPTION_KEY set — deriving from K8s pod identity. " +
                "Set BMW_ENCRYPTION_KEY via K8s Secret for production use.");
        }
        else
        {
            // Tier 3: Bare metal — machine identity
            identity = "baremetalweb-default";
            try
            {
                identity = File.Exists("/etc/machine-id")
                    ? File.ReadAllText("/etc/machine-id").Trim()
                    : Environment.MachineName;
            }
            catch { /* fall through with default */ }
            Console.Error.WriteLine(
                "[BMW Security] No BMW_ENCRYPTION_KEY set — deriving from machine identity (dev only).");
        }

        // Envelope derivation: identity (not on disk) + persisted random salt → HKDF
        var salt = EnsureSalt();
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            Encoding.UTF8.GetBytes(identity),
            KeySize,
            salt,
            Encoding.UTF8.GetBytes("BareMetalWeb.KeyFile.v2"));
    }

    /// <summary>
    /// Legacy derivation for backward compatibility with v1 key files.
    /// Uses ATECC608A → /etc/machine-id → MachineName with fixed HKDF salt/info.
    /// </summary>
    private static byte[] DeriveMachineKeyLegacy()
    {
        byte[]? ikm = null;
        if (OperatingSystem.IsLinux())
        {
            try { ikm = Atecc608a.ReadSlotKey(); } catch { }
        }

        if (ikm is null || ikm.Length != 32)
        {
            string machineId = "baremetalweb-default";
            try { machineId = File.Exists("/etc/machine-id") ? File.ReadAllText("/etc/machine-id").Trim() : Environment.MachineName; } catch { }
            ikm = Encoding.UTF8.GetBytes(machineId);
        }

        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm,
            32,
            Encoding.UTF8.GetBytes("BareMetalWeb.KeyFile.v1"),
            Encoding.UTF8.GetBytes("key-protection"));
    }

    /// <summary>
    /// Ensures a 32-byte random salt exists at {_keyRoot}/.keys/derivation.salt.
    /// The salt is generated once and persisted — it is NOT secret on its own,
    /// but combined with an identity source (HOSTNAME, machine-id) that is not on disk,
    /// it produces a key that cannot be derived from the salt file alone.
    /// </summary>
    private static byte[] EnsureSalt()
    {
        var saltPath = Path.Combine(_keyRoot, ".keys", "derivation.salt");
        var dir = Path.GetDirectoryName(saltPath);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);

        if (File.Exists(saltPath))
        {
            var existing = File.ReadAllBytes(saltPath);
            if (existing.Length == SaltSize)
                return existing;
        }

        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);
        File.WriteAllBytes(saltPath, salt);
        return salt;
    }
}
