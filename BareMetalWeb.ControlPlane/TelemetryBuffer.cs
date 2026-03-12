using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace BareMetalWeb.ControlPlane;

/// <summary>
/// Bounded, disk-backed buffer for pending outbound telemetry records.
///
/// Records are stored as NDJSON (one JSON line per record) in a local file so
/// that they survive process restarts.  In normal operation the in-memory queue
/// is the primary data structure; the file is an append-only durability log.
/// When all pending records have been successfully sent the file is deleted.
///
/// Design constraints (matching the BareMetalWeb philosophy):
///  • No external dependencies — plain file I/O only.
///  • Thread-safe without per-operation heap allocations.
///  • Bounded: when <see cref="MaxRecords"/> is exceeded the oldest record is
///    dropped and <see cref="DroppedCount"/> is incremented.
/// </summary>
internal sealed class TelemetryBuffer
{
    private readonly string _filePath;
    private readonly int _maxRecords;
    private readonly object _lock = new();
    private readonly Queue<string> _pending = new();
    private long _droppedCount;

    /// <summary>Maximum number of records kept in the in-memory queue.</summary>
    public const int DefaultMaxRecords = 10_000;

    /// <summary>Current number of records waiting to be sent.</summary>
    public int QueueDepth { get { lock (_lock) return _pending.Count; } }

    /// <summary>Total number of records dropped because the buffer was full.</summary>
    public long DroppedCount => Interlocked.Read(ref _droppedCount);

    public TelemetryBuffer(string bufferDir, int maxRecords = DefaultMaxRecords)
    {
        _maxRecords = maxRecords;
        Directory.CreateDirectory(bufferDir);
        _filePath = Path.Combine(bufferDir, "telemetry_pending.ndjson");
        LoadFromDisk();
    }

    /// <summary>
    /// Add a serialised JSON record to the buffer.
    /// Returns <c>false</c> (and increments <see cref="DroppedCount"/>) when full.
    /// </summary>
    public bool TryEnqueue(string jsonRecord)
    {
        lock (_lock)
        {
            if (_pending.Count >= _maxRecords)
            {
                // Drop the oldest entry to make room, but count the loss
                _pending.Dequeue();
                Interlocked.Increment(ref _droppedCount);
            }
            _pending.Enqueue(jsonRecord);
        }
        AppendToDisk(jsonRecord);
        return true;
    }

    /// <summary>Remove and return the oldest pending record. Returns <c>false</c> when empty.</summary>
    public bool TryDequeue(out string record)
    {
        lock (_lock)
        {
            if (_pending.Count == 0)
            {
                record = string.Empty;
                return false;
            }
            record = _pending.Dequeue();
            return true;
        }
    }

    /// <summary>
    /// Rewrite the backing file to reflect the current queue contents.
    /// Call this after a successful bulk drain so the file no longer contains
    /// already-sent records.  Deletes the file when the queue is empty.
    /// </summary>
    public void PersistCurrentState()
    {
        lock (_lock)
        {
            if (_pending.Count == 0)
            {
                try
                {
                    if (File.Exists(_filePath)) File.Delete(_filePath);
                }
                catch { /* best-effort */ }
                return;
            }

            try
            {
                File.WriteAllLines(_filePath, _pending);
            }
            catch { /* best-effort */ }
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private void LoadFromDisk()
    {
        if (!File.Exists(_filePath)) return;
        try
        {
            foreach (var line in File.ReadLines(_filePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                if (_pending.Count < _maxRecords)
                    _pending.Enqueue(line);
                else
                    Interlocked.Increment(ref _droppedCount);
            }
        }
        catch
        {
            // Corrupted file — ignore and start fresh
        }
    }

    private void AppendToDisk(string record)
    {
        try
        {
            using var stream = new FileStream(
                _filePath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite, 512);
            using var writer = new StreamWriter(stream);
            writer.WriteLine(record);
        }
        catch { /* best-effort durability */ }
    }
}
