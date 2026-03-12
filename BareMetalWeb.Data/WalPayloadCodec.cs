using System;
using System.Buffers;
using System.IO.Compression;

namespace BareMetalWeb.Data;

/// <summary>
/// Helpers for compressing and decompressing per-op WAL payloads using Brotli.
/// Quality 1 gives LZ4-class throughput (~2-3 GB/s) with zero external dependencies.
/// Payloads smaller than <see cref="MinCompressThreshold"/> bytes are stored as-is.
/// When encryption is enabled, payloads are compressed first, then encrypted.
/// </summary>
internal static class WalPayloadCodec
{
    /// <summary>Minimum uncompressed size (bytes) before compression is attempted.</summary>
    private const int MinCompressThreshold = 64;

    /// <summary>Hard cap on decompressed WAL record size to prevent decompression bombs.</summary>
    private const uint MaxDecompressedWalBytes = 256 * 1024 * 1024; // 256 MB

    /// <summary>Brotli quality level (0–11). 1 prioritises throughput over ratio — comparable to LZ4.</summary>
    private const int BrotliQuality = 1;

    /// <summary>Brotli window size (10–24). 22 ≈ 4 MiB, good for typical record sizes.</summary>
    private const int BrotliWindow = 22;

    /// <summary>Maximum allowed uncompressed payload size (128 MiB). Prevents decompression bomb DoS.</summary>
    internal const uint MaxUncompressedSize = 128 * 1024 * 1024;

    /// <summary>Shared encryption instance, lazily initialised from environment.</summary>
    private static WalEnvelopeEncryption? _defaultEncryption;
    private static bool _defaultEncryptionInitialised;
    private static readonly object _encLock = new();

    /// <summary>Gets the default encryption instance from environment.</summary>
    internal static WalEnvelopeEncryption GetDefaultEncryption()
    {
        if (_defaultEncryptionInitialised) return _defaultEncryption!;
        lock (_encLock)
        {
            if (!_defaultEncryptionInitialised)
            {
                _defaultEncryption = WalEnvelopeEncryption.FromEnvironment();
                _defaultEncryptionInitialised = true;
            }
        }
        return _defaultEncryption!;
    }

    /// <summary>Allows tests to override the default encryption instance.</summary>
    internal static void SetEncryptionForTesting(WalEnvelopeEncryption enc)
    {
        lock (_encLock)
        {
            _defaultEncryption = enc;
            _defaultEncryptionInitialised = true;
        }
    }

    /// <summary>Resets the default encryption instance (for test cleanup).</summary>
    internal static void ResetEncryption()
    {
        lock (_encLock)
        {
            _defaultEncryption = null;
            _defaultEncryptionInitialised = false;
        }
    }

    /// <summary>
    /// Tries to Brotli-compress <paramref name="input"/> at quality 1 (fast),
    /// then encrypts if enabled. Returns the (possibly compressed and/or encrypted)
    /// payload, setting <paramref name="codec"/> and <paramref name="uncompressedLen"/>.
    /// </summary>
    public static ReadOnlyMemory<byte> TryCompress(
        ReadOnlyMemory<byte> input,
        out ushort codec,
        out uint uncompressedLen,
        WalEnvelopeEncryption? encryption = null)
    {
        uncompressedLen = (uint)input.Length;
        var enc = encryption ?? GetDefaultEncryption();

        if (input.Length < MinCompressThreshold)
        {
            if (enc.IsEnabled)
            {
                codec = WalConstants.CodecEncryptedNone;
                return enc.Encrypt(input.Span);
            }
            codec = WalConstants.CodecNone;
            return input;
        }

        int maxSize = BrotliEncoder.GetMaxCompressedLength(input.Length);
        byte[] compressed = ArrayPool<byte>.Shared.Rent(maxSize);
        try
        {
            if (BrotliEncoder.TryCompress(input.Span, compressed, out int written,
                    quality: BrotliQuality, window: BrotliWindow)
                && written < input.Length)
            {
                var compressedSlice = compressed.AsSpan(0, written);
                if (enc.IsEnabled)
                {
                    codec = WalConstants.CodecEncryptedBrotli;
                    return enc.Encrypt(compressedSlice);
                }
                codec = WalConstants.CodecBrotli;
                return compressedSlice.ToArray();
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(compressed);
        }

        if (enc.IsEnabled)
        {
            codec = WalConstants.CodecEncryptedNone;
            return enc.Encrypt(input.Span);
        }
        codec = WalConstants.CodecNone;
        return input;
    }

    /// <summary>
    /// Decrypts (if needed) and decompresses <paramref name="payload"/> based on <paramref name="codec"/>.
    /// </summary>
    /// <exception cref="System.IO.InvalidDataException">
    /// Thrown if decompression or decryption fails, or if <paramref name="uncompressedLen"/>
    /// exceeds <see cref="MaxUncompressedSize"/>.
    /// </exception>
    public static ReadOnlyMemory<byte> Decompress(
        ReadOnlyMemory<byte> payload,
        ushort codec,
        uint uncompressedLen,
        WalEnvelopeEncryption? encryption = null)
    {
        // Guard: reject allocations that could exhaust memory (decompression bomb)
        if (uncompressedLen > MaxUncompressedSize)
            throw new System.IO.InvalidDataException(
                $"Uncompressed payload size ({uncompressedLen}) exceeds maximum ({MaxUncompressedSize}).");

        // Encrypted + Brotli: decrypt envelope → decompress Brotli
        if (codec == WalConstants.CodecEncryptedBrotli)
        {
            var enc = encryption ?? GetDefaultEncryption();
            var decrypted = enc.Decrypt(payload.Span);
            if (uncompressedLen > MaxDecompressedWalBytes)
                throw new System.IO.InvalidDataException($"WAL record claims uncompressed size {uncompressedLen} exceeds {MaxDecompressedWalBytes} byte limit.");
            byte[] result = new byte[uncompressedLen];
            bool ok = BrotliDecoder.TryDecompress(decrypted, result, out int bytesWritten);
            if (!ok || bytesWritten != (int)uncompressedLen)
                throw new System.IO.InvalidDataException(
                    $"Brotli decompression after decryption failed: ok={ok}, expected={uncompressedLen}, got={bytesWritten}.");
            return result;
        }

        // Encrypted + no compression: decrypt envelope only
        if (codec == WalConstants.CodecEncryptedNone)
        {
            var enc = encryption ?? GetDefaultEncryption();
            return enc.Decrypt(payload.Span);
        }

        // Brotli only (no encryption)
        if (codec == WalConstants.CodecBrotli)
        {
            if (uncompressedLen > MaxDecompressedWalBytes)
                throw new System.IO.InvalidDataException($"WAL record claims uncompressed size {uncompressedLen} exceeds {MaxDecompressedWalBytes} byte limit.");
            byte[] result = new byte[uncompressedLen];
            bool ok = BrotliDecoder.TryDecompress(payload.Span, result, out int bytesWritten);
            if (!ok || bytesWritten != (int)uncompressedLen)
                throw new System.IO.InvalidDataException(
                    $"Brotli decompression failed: ok={ok}, expected={uncompressedLen}, got={bytesWritten}.");
            return result;
        }

        // No compression, no encryption
        return payload;
    }
}
