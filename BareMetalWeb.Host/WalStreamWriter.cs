using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

/// <summary>
/// Zero-serialization WAL streaming over binary length-prefixed protocol.
///
/// <para>Wire format:</para>
/// <code>
/// [count : uint32]                    ← total record count
///
/// repeat count times:
///   [length : uint32]                 ← payload byte length
///   [wal record bytes ... ]           ← raw WAL payload (may be compressed/encrypted)
/// </code>
///
/// <para>
/// Records are shovelled directly from the WAL store's memory-mapped segments
/// to the <see cref="PipeWriter"/> with no intermediate buffering, JSON formatting,
/// or object materialisation. The only unavoidable copy is PipeWriter → socket send buffer.
/// </para>
/// </summary>
internal static class WalStreamWriter
{
    /// <summary>
    /// Streams all WAL records for a given entity type using binary length-prefixed framing.
    /// </summary>
    /// <param name="writer">The output <see cref="PipeWriter"/> (typically BmwContext.ResponseBody).</param>
    /// <param name="walProvider">The WAL data provider to read records from.</param>
    /// <param name="entityName">Entity type name to stream records for.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The number of records written.</returns>
    public static async ValueTask<int> StreamEntityAsync(
        PipeWriter writer,
        WalDataProvider walProvider,
        string entityName,
        CancellationToken ct = default)
    {
        var walStore = walProvider.WalStore;
        var payloads = walProvider.QueryBinary(entityName);
        int count = payloads.Count;

        // Write record count header (4 bytes, little-endian)
        WriteUInt32(writer, (uint)count);

        for (int i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var payload = payloads[i];

            // Write length prefix (4 bytes, little-endian)
            WriteUInt32(writer, (uint)payload.Length);

            // Write payload directly — zero intermediate buffer
            if (payload.Length > 0)
            {
                var dest = writer.GetMemory(payload.Length);
                payload.Span.CopyTo(dest.Span);
                writer.Advance(payload.Length);
            }

            // Flush periodically to maintain back-pressure (every 64 records)
            if ((i & 63) == 63)
            {
                var result = await writer.FlushAsync(ct).ConfigureAwait(false);
                if (result.IsCompleted) return i + 1;
            }
        }

        await writer.FlushAsync(ct).ConfigureAwait(false);
        return count;
    }

    /// <summary>
    /// Streams all WAL records across all entities using binary length-prefixed framing.
    /// Iterates the entire HeadMap via CopyArrays for a full database dump.
    /// </summary>
    public static async ValueTask<int> StreamAllAsync(
        PipeWriter writer,
        WalDataProvider walProvider,
        CancellationToken ct = default)
    {
        var walStore = walProvider.WalStore;

        // Extract all live key→head pairs
        walStore.HeadMap.CopyArrays(out var keys, out var heads);
        int count = keys.Length;

        // Write record count header
        WriteUInt32(writer, (uint)count);

        for (int i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();

            if (!walStore.TryReadOpPayload(heads[i], keys[i], out var payload))
            {
                // Tombstone or unreadable — write zero-length record
                WriteUInt32(writer, 0u);
            }
            else
            {
                WriteUInt32(writer, (uint)payload.Length);
                if (payload.Length > 0)
                {
                    var dest = writer.GetMemory(payload.Length);
                    payload.Span.CopyTo(dest.Span);
                    writer.Advance(payload.Length);
                }
            }

            if ((i & 63) == 63)
            {
                var result = await writer.FlushAsync(ct).ConfigureAwait(false);
                if (result.IsCompleted) return i + 1;
            }
        }

        await writer.FlushAsync(ct).ConfigureAwait(false);
        return count;
    }

    /// <summary>
    /// Writes a uint32 value in little-endian to the PipeWriter.
    /// Uses GetSpan(4) for zero-allocation inline writing.
    /// </summary>
    private static void WriteUInt32(PipeWriter writer, uint value)
    {
        var span = writer.GetSpan(4);
        BinaryPrimitives.WriteUInt32LittleEndian(span, value);
        writer.Advance(4);
    }
}
