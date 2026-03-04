using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace BareMetalWeb.Data;

/// <summary>
/// Provides AES-256-GCM envelope encryption for WAL record payloads.
/// The key encryption key (KEK) is loaded from the <c>BMW_WAL_ENCRYPTION_KEY</c>
/// environment variable (base-64 encoded, 32 bytes). When the variable is absent
/// or empty, encryption is disabled and payloads are stored in plaintext.
/// </summary>
public sealed class WalEnvelopeEncryption
{
    private const string EnvVarName = "BMW_WAL_ENCRYPTION_KEY";
    private const int KeySize = 32;   // AES-256
    private const int NonceSize = 12; // AES-GCM standard
    private const int TagSize = 16;   // AES-GCM tag

    private readonly byte[]? _kek;

    /// <summary>True when a valid KEK was loaded and encryption is active.</summary>
    public bool IsEnabled => _kek != null;

    private WalEnvelopeEncryption(byte[]? kek) => _kek = kek;

    /// <summary>
    /// Creates an instance by reading the KEK from the environment.
    /// Returns a disabled (no-op) instance when the variable is absent.
    /// </summary>
    public static WalEnvelopeEncryption FromEnvironment()
    {
        var raw = Environment.GetEnvironmentVariable(EnvVarName);
        if (string.IsNullOrWhiteSpace(raw))
            return new WalEnvelopeEncryption(null);

        byte[] kek;
        try { kek = Convert.FromBase64String(raw); }
        catch (FormatException)
        {
            throw new InvalidOperationException(
                $"{EnvVarName} is not valid base-64. Expected a 32-byte key encoded as base-64.");
        }

        if (kek.Length != KeySize)
            throw new InvalidOperationException(
                $"{EnvVarName} must be exactly {KeySize} bytes (got {kek.Length}).");

        return new WalEnvelopeEncryption(kek);
    }

    /// <summary>Creates a test instance with the supplied key (or disabled if null).</summary>
    internal static WalEnvelopeEncryption ForTesting(byte[]? kek) => new(kek);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> using a fresh random DEK wrapped with the KEK.
    /// Wire format: WrappedDEK(60) + Nonce(12) + Ciphertext(N) + Tag(16).
    /// WrappedDEK = AES-GCM(KEK, nonce=12, plaintext=DEK(32), tag=16) → 12+32+16 = 60 bytes.
    /// </summary>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        if (_kek == null) throw new InvalidOperationException("Encryption is not enabled.");

        // Generate a random DEK
        Span<byte> dek = stackalloc byte[KeySize];
        RandomNumberGenerator.Fill(dek);

        // Wrap DEK with KEK using AES-GCM
        Span<byte> wrapNonce = stackalloc byte[NonceSize];
        RandomNumberGenerator.Fill(wrapNonce);
        Span<byte> wrappedDekCipher = stackalloc byte[KeySize];
        Span<byte> wrapTag = stackalloc byte[TagSize];
        using (var wrapAes = new AesGcm(_kek, TagSize))
            wrapAes.Encrypt(wrapNonce, dek, wrappedDekCipher, wrapTag);

        // Encrypt payload with DEK
        Span<byte> payloadNonce = stackalloc byte[NonceSize];
        RandomNumberGenerator.Fill(payloadNonce);
        var ciphertext = new byte[plaintext.Length];
        Span<byte> payloadTag = stackalloc byte[TagSize];
        using (var payloadAes = new AesGcm(dek, TagSize))
            payloadAes.Encrypt(payloadNonce, plaintext, ciphertext, payloadTag);

        // Assemble envelope: WrapNonce(12) + WrappedDEK(32) + WrapTag(16) + PayloadNonce(12) + Ciphertext(N) + PayloadTag(16)
        int envelopeLen = NonceSize + KeySize + TagSize + NonceSize + ciphertext.Length + TagSize;
        var envelope = new byte[envelopeLen];
        int o = 0;
        wrapNonce.CopyTo(envelope.AsSpan(o));        o += NonceSize;
        wrappedDekCipher.CopyTo(envelope.AsSpan(o)); o += KeySize;
        wrapTag.CopyTo(envelope.AsSpan(o));          o += TagSize;
        payloadNonce.CopyTo(envelope.AsSpan(o));     o += NonceSize;
        ciphertext.CopyTo(envelope.AsSpan(o));       o += ciphertext.Length;
        payloadTag.CopyTo(envelope.AsSpan(o));

        return envelope;
    }

    /// <summary>
    /// Decrypts an envelope produced by <see cref="Encrypt"/>.
    /// </summary>
    public byte[] Decrypt(ReadOnlySpan<byte> envelope)
    {
        if (_kek == null) throw new InvalidOperationException("Encryption is not enabled.");

        const int headerSize = NonceSize + KeySize + TagSize + NonceSize; // 72
        const int minSize = headerSize + TagSize; // 88 (empty plaintext)
        if (envelope.Length < minSize)
            throw new System.IO.InvalidDataException("Encrypted WAL envelope is too short.");

        int o = 0;
        var wrapNonce        = envelope.Slice(o, NonceSize);        o += NonceSize;
        var wrappedDekCipher = envelope.Slice(o, KeySize);          o += KeySize;
        var wrapTag          = envelope.Slice(o, TagSize);          o += TagSize;
        var payloadNonce     = envelope.Slice(o, NonceSize);        o += NonceSize;
        int ciphertextLen    = envelope.Length - headerSize - TagSize;
        var ciphertext       = envelope.Slice(o, ciphertextLen);    o += ciphertextLen;
        var payloadTag       = envelope.Slice(o, TagSize);

        // Unwrap DEK
        Span<byte> dek = stackalloc byte[KeySize];
        using (var wrapAes = new AesGcm(_kek, TagSize))
            wrapAes.Decrypt(wrapNonce, wrappedDekCipher, wrapTag, dek);

        // Decrypt payload
        var plaintext = new byte[ciphertextLen];
        using (var payloadAes = new AesGcm(dek, TagSize))
            payloadAes.Decrypt(payloadNonce, ciphertext, payloadTag, plaintext);

        return plaintext;
    }
}
