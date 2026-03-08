using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace BareMetalWeb.Data;

/// <summary>
/// AES-256-GCM file-level encryption for data at rest. Derives a unique per-file key
/// from the WAL KEK via HKDF-SHA256 so each file uses an independent key.
///
/// Wire format (little-endian):
/// <list type="bullet">
///   <item>Magic(4): 0x454E4346 ("ENCF")</item>
///   <item>Version(2): 1</item>
///   <item>Reserved(2): 0</item>
///   <item>Nonce(12): AES-GCM nonce</item>
///   <item>PlaintextLength(4): original plaintext length (for pre-allocation)</item>
///   <item>Ciphertext(N): encrypted payload</item>
///   <item>Tag(16): AES-GCM authentication tag</item>
/// </list>
///
/// When encryption is disabled (no KEK), all methods pass data through unmodified.
/// </summary>
internal static class EncryptedFileIO
{
    private const uint Magic = 0x454E4346u; // "ENCF"
    private const ushort Version = 1;
    private const int HeaderSize = 4 + 2 + 2 + 12 + 4; // 24 bytes
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using the WAL KEK, deriving a file-specific
    /// key via HKDF with <paramref name="fileContext"/> as the info parameter.
    /// Returns the plaintext unchanged when encryption is disabled.
    /// </summary>
    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, string fileContext,
        WalEnvelopeEncryption? encryption = null)
    {
        var enc = encryption ?? GetEncryption();
        if (enc == null || !enc.IsEnabled)
            return plaintext.ToArray();

        byte[] fileKey = DeriveFileKey(enc, fileContext);
        try
        {
            return EncryptWithKey(plaintext, fileKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>
    /// Decrypts data produced by <see cref="Encrypt"/>. Returns the data unchanged
    /// if it does not start with the encryption magic (plaintext passthrough for
    /// backward compatibility with pre-encryption files).
    /// </summary>
    public static byte[] Decrypt(ReadOnlySpan<byte> data, string fileContext,
        WalEnvelopeEncryption? encryption = null)
    {
        // Not encrypted — passthrough for backward compatibility
        if (data.Length < HeaderSize + TagSize) return data.ToArray();
        if (BinaryPrimitives.ReadUInt32LittleEndian(data) != Magic) return data.ToArray();

        var enc = encryption ?? GetEncryption();
        if (enc == null || !enc.IsEnabled)
            throw new InvalidOperationException(
                "File is encrypted but no encryption key is configured (BMW_WAL_ENCRYPTION_KEY).");

        byte[] fileKey = DeriveFileKey(enc, fileContext);
        try
        {
            return DecryptWithKey(data, fileKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    /// <summary>
    /// Convenience: encrypt and write atomically (write to .tmp, rename).
    /// </summary>
    public static void WriteEncrypted(string path, ReadOnlySpan<byte> plaintext, string fileContext,
        WalEnvelopeEncryption? encryption = null)
    {
        var encrypted = Encrypt(plaintext, fileContext, encryption);
        var tmpPath = path + ".enc.tmp";
        File.WriteAllBytes(tmpPath, encrypted);
        File.Move(tmpPath, path, overwrite: true);
    }

    /// <summary>
    /// Convenience: read and decrypt. Handles both encrypted and plaintext files.
    /// </summary>
    public static byte[] ReadDecrypted(string path, string fileContext,
        WalEnvelopeEncryption? encryption = null)
    {
        var data = File.ReadAllBytes(path);
        return Decrypt(data, fileContext, encryption);
    }

    /// <summary>
    /// Returns <c>true</c> when encryption is active (KEK configured).
    /// </summary>
    public static bool IsEnabled(WalEnvelopeEncryption? encryption = null)
    {
        var enc = encryption ?? GetEncryption();
        return enc != null && enc.IsEnabled;
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    private static byte[] EncryptWithKey(ReadOnlySpan<byte> plaintext, byte[] key)
    {
        Span<byte> nonce = stackalloc byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var ciphertext = new byte[plaintext.Length];
        Span<byte> tag = stackalloc byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Assemble: Header(24) + Ciphertext(N) + Tag(16)
        int totalSize = HeaderSize + ciphertext.Length + TagSize;
        var output = new byte[totalSize];
        var s = output.AsSpan();
        int o = 0;

        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], Magic);           o += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(s[o..], Version);         o += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(s[o..], 0);               o += 2; // reserved
        nonce.CopyTo(s[o..]);                                              o += NonceSize;
        BinaryPrimitives.WriteInt32LittleEndian(s[o..], plaintext.Length); o += 4;

        ciphertext.AsSpan().CopyTo(s[o..]);                                o += ciphertext.Length;
        tag.CopyTo(s[o..]);

        return output;
    }

    private static byte[] DecryptWithKey(ReadOnlySpan<byte> data, byte[] key)
    {
        if (data.Length < HeaderSize + TagSize)
            throw new InvalidDataException("Encrypted file is too short.");

        int o = 0;
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(data[o..]);    o += 4;
        if (magic != Magic) throw new InvalidDataException("Bad encryption magic.");

        ushort ver = BinaryPrimitives.ReadUInt16LittleEndian(data[o..]);    o += 2;
        if (ver != Version) throw new InvalidDataException($"Unsupported encryption version {ver}.");

        o += 2; // reserved
        var nonce = data.Slice(o, NonceSize);                               o += NonceSize;
        int plaintextLen = BinaryPrimitives.ReadInt32LittleEndian(data[o..]); o += 4;

        int ciphertextLen = data.Length - HeaderSize - TagSize;
        if (ciphertextLen < 0 || ciphertextLen != plaintextLen)
            throw new InvalidDataException("Encrypted file ciphertext length mismatch.");

        var ciphertext = data.Slice(o, ciphertextLen);                      o += ciphertextLen;
        var tag = data.Slice(o, TagSize);

        var plaintext = new byte[plaintextLen];
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        return plaintext;
    }

    /// <summary>
    /// Derives a per-file AES-256 key from the WAL KEK using HKDF-SHA256.
    /// The <paramref name="fileContext"/> string (e.g. "snapshot", "idmap:Users")
    /// acts as the HKDF info parameter to produce independent keys per file type.
    /// </summary>
    private static byte[] DeriveFileKey(WalEnvelopeEncryption encryption, string fileContext)
    {
        // Extract the KEK bytes via a round-trip: encrypt a known plaintext, then
        // use the fileContext as HKDF info. We can't access _kek directly (it's private),
        // so we use HKDF with the KEK's identity as the input keying material.
        // Since we need the raw key, we'll derive from the env var directly.
        var envKey = Environment.GetEnvironmentVariable("BMW_WAL_ENCRYPTION_KEY");
        if (string.IsNullOrWhiteSpace(envKey))
            throw new InvalidOperationException("BMW_WAL_ENCRYPTION_KEY not set.");

        byte[] kek = Convert.FromBase64String(envKey);
        byte[] info = System.Text.Encoding.UTF8.GetBytes(fileContext);

        var derivedKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, kek, KeySize, info: info);
        return derivedKey;
    }

    private static WalEnvelopeEncryption? GetEncryption()
        => WalPayloadCodec.GetDefaultEncryption();
}
