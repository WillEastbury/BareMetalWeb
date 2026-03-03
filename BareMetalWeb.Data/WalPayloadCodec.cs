using System;
using System.Buffers;
using System.IO.Compression;

namespace BareMetalWeb.Data;

/// <summary>
/// Helpers for compressing and decompressing per-op WAL payloads using Brotli.
/// Payloads smaller than <see cref="MinCompressThreshold"/> bytes are stored as-is.
/// </summary>
internal static class WalPayloadCodec
{
    /// <summary>Minimum uncompressed size (bytes) before Brotli compression is attempted.</summary>
    private const int MinCompressThreshold = 64;

    /// <summary>Brotli quality level (0–11). 4 balances speed and compression ratio well.</summary>
    private const int BrotliQuality = 4;

    /// <summary>Brotli window size (10–24). 22 ≈ 4 MiB, good for typical record sizes.</summary>
    private const int BrotliWindow = 22;

    /// <summary>
    /// Tries to Brotli-compress <paramref name="input"/>.
    /// Returns the (possibly compressed) payload, setting <paramref name="codec"/> and
    /// <paramref name="uncompressedLen"/> accordingly.
    /// If the compressed output is not smaller than the input, the original bytes are
    /// returned unchanged with <see cref="WalConstants.CodecNone"/>.
    /// </summary>
    public static ReadOnlyMemory<byte> TryCompress(
        ReadOnlyMemory<byte> input,
        out ushort codec,
        out uint uncompressedLen)
    {
        uncompressedLen = (uint)input.Length;

        if (input.Length < MinCompressThreshold)
        {
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
                codec = WalConstants.CodecBrotli;
                // Copy compressed slice to a right-sized owned array so the ArrayPool
                // buffer can be returned immediately.
                return compressed.AsSpan(0, written).ToArray();
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(compressed);
        }

        codec = WalConstants.CodecNone;
        return input;
    }

    /// <summary>
    /// Decompresses <paramref name="payload"/> when <paramref name="codec"/> is
    /// <see cref="WalConstants.CodecBrotli"/>; otherwise returns the input unchanged.
    /// </summary>
    /// <exception cref="System.IO.InvalidDataException">
    /// Thrown if Brotli decompression fails or produces an unexpected number of bytes.
    /// </exception>
    public static ReadOnlyMemory<byte> Decompress(
        ReadOnlyMemory<byte> payload,
        ushort codec,
        uint uncompressedLen)
    {
        if (codec != WalConstants.CodecBrotli)
            return payload;

        byte[] result = new byte[uncompressedLen];
        bool ok = BrotliDecoder.TryDecompress(payload.Span, result, out int bytesWritten);

        if (!ok || bytesWritten != (int)uncompressedLen)
            throw new System.IO.InvalidDataException(
                $"Brotli decompression failed: ok={ok}, expected={uncompressedLen}, got={bytesWritten}.");

        return result;
    }
}
