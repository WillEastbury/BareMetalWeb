using System.Collections.Concurrent;
using System.Diagnostics;

namespace BareMetalWeb.Data;

/// <summary>
/// Internal engine telemetry for WAL, locks, commits, and compaction.
/// Thread-safe, lock-free counters using Interlocked operations.
/// All latencies are recorded in microseconds (µs).
/// </summary>
public static class EngineMetrics
{
    // ── WAL append ───────────────────────────────────────────────────────────

    private static long _walAppendCount;
    private static long _walAppendTotalUs;
    private static long _walAppendMaxUs;
    private static long _walAppendBytesTotal;

    public static void RecordWalAppend(long elapsedUs, long bytes)
    {
        Interlocked.Increment(ref _walAppendCount);
        Interlocked.Add(ref _walAppendTotalUs, elapsedUs);
        Interlocked.Add(ref _walAppendBytesTotal, bytes);
        UpdateMax(ref _walAppendMaxUs, elapsedUs);
    }

    // ── Lock acquisition ─────────────────────────────────────────────────────

    private static long _lockAcquireCount;
    private static long _lockAcquireTotalUs;
    private static long _lockAcquireMaxUs;
    private static long _lockContentions;

    public static void RecordLockAcquire(long elapsedUs, bool contended)
    {
        Interlocked.Increment(ref _lockAcquireCount);
        Interlocked.Add(ref _lockAcquireTotalUs, elapsedUs);
        UpdateMax(ref _lockAcquireMaxUs, elapsedUs);
        if (contended) Interlocked.Increment(ref _lockContentions);
    }

    // ── Commit pipeline ──────────────────────────────────────────────────────

    private static long _commitCount;
    private static long _commitSuccessCount;
    private static long _commitFailCount;
    private static long _commitTotalUs;
    private static long _commitMaxUs;
    private static long _commitRetryCount;

    public static void RecordCommit(long elapsedUs, bool success)
    {
        Interlocked.Increment(ref _commitCount);
        Interlocked.Add(ref _commitTotalUs, elapsedUs);
        UpdateMax(ref _commitMaxUs, elapsedUs);
        if (success) Interlocked.Increment(ref _commitSuccessCount);
        else Interlocked.Increment(ref _commitFailCount);
    }

    public static void RecordCommitRetry() => Interlocked.Increment(ref _commitRetryCount);

    // ── Delta sizes ──────────────────────────────────────────────────────────

    private static long _deltaSizeCount;
    private static long _deltaSizeTotal;
    private static long _deltaSizeMax;
    private static long _deltaSizeMin = long.MaxValue;

    public static void RecordDeltaSize(long bytes)
    {
        Interlocked.Increment(ref _deltaSizeCount);
        Interlocked.Add(ref _deltaSizeTotal, bytes);
        UpdateMax(ref _deltaSizeMax, bytes);
        UpdateMin(ref _deltaSizeMin, bytes);
    }

    // ── Compaction ────────────────────────────────────────────────────────────

    private static long _compactionCount;
    private static long _compactionTotalUs;
    private static long _compactionBytesReclaimed;
    private static long _lastCompactionTimestamp;

    public static void RecordCompaction(long elapsedUs, long bytesReclaimed)
    {
        Interlocked.Increment(ref _compactionCount);
        Interlocked.Add(ref _compactionTotalUs, elapsedUs);
        Interlocked.Add(ref _compactionBytesReclaimed, bytesReclaimed);
        Interlocked.Exchange(ref _lastCompactionTimestamp, Stopwatch.GetTimestamp());
    }

    // ── Replay ────────────────────────────────────────────────────────────────

    private static long _replayCount;
    private static long _replayTotalUs;
    private static long _replayOpsTotal;

    public static void RecordReplay(long elapsedUs, long opsReplayed)
    {
        Interlocked.Increment(ref _replayCount);
        Interlocked.Add(ref _replayTotalUs, elapsedUs);
        Interlocked.Add(ref _replayOpsTotal, opsReplayed);
    }

    // ── Snapshot ──────────────────────────────────────────────────────────────

    /// <summary>Capture a point-in-time snapshot of all metrics.</summary>
    public static EngineMetricsSnapshot GetSnapshot() => new(
        WalAppendCount: Volatile.Read(ref _walAppendCount),
        WalAppendTotalUs: Volatile.Read(ref _walAppendTotalUs),
        WalAppendMaxUs: Volatile.Read(ref _walAppendMaxUs),
        WalAppendBytesTotal: Volatile.Read(ref _walAppendBytesTotal),
        LockAcquireCount: Volatile.Read(ref _lockAcquireCount),
        LockAcquireTotalUs: Volatile.Read(ref _lockAcquireTotalUs),
        LockAcquireMaxUs: Volatile.Read(ref _lockAcquireMaxUs),
        LockContentions: Volatile.Read(ref _lockContentions),
        CommitCount: Volatile.Read(ref _commitCount),
        CommitSuccessCount: Volatile.Read(ref _commitSuccessCount),
        CommitFailCount: Volatile.Read(ref _commitFailCount),
        CommitTotalUs: Volatile.Read(ref _commitTotalUs),
        CommitMaxUs: Volatile.Read(ref _commitMaxUs),
        CommitRetryCount: Volatile.Read(ref _commitRetryCount),
        DeltaSizeCount: Volatile.Read(ref _deltaSizeCount),
        DeltaSizeTotal: Volatile.Read(ref _deltaSizeTotal),
        DeltaSizeMax: Volatile.Read(ref _deltaSizeMax),
        DeltaSizeMin: Volatile.Read(ref _deltaSizeMin) == long.MaxValue ? 0 : Volatile.Read(ref _deltaSizeMin),
        CompactionCount: Volatile.Read(ref _compactionCount),
        CompactionTotalUs: Volatile.Read(ref _compactionTotalUs),
        CompactionBytesReclaimed: Volatile.Read(ref _compactionBytesReclaimed),
        LastCompactionTimestamp: Volatile.Read(ref _lastCompactionTimestamp),
        ReplayCount: Volatile.Read(ref _replayCount),
        ReplayTotalUs: Volatile.Read(ref _replayTotalUs),
        ReplayOpsTotal: Volatile.Read(ref _replayOpsTotal));

    /// <summary>Reset all counters to zero.</summary>
    public static void Reset()
    {
        _walAppendCount = _walAppendTotalUs = _walAppendMaxUs = _walAppendBytesTotal = 0;
        _lockAcquireCount = _lockAcquireTotalUs = _lockAcquireMaxUs = _lockContentions = 0;
        _commitCount = _commitSuccessCount = _commitFailCount = _commitTotalUs = _commitMaxUs = _commitRetryCount = 0;
        _deltaSizeCount = _deltaSizeTotal = _deltaSizeMax = 0;
        _deltaSizeMin = long.MaxValue;
        _compactionCount = _compactionTotalUs = _compactionBytesReclaimed = _lastCompactionTimestamp = 0;
        _replayCount = _replayTotalUs = _replayOpsTotal = 0;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>Start a high-resolution stopwatch, return ticks.</summary>
    public static long StartTiming() => Stopwatch.GetTimestamp();

    /// <summary>Convert elapsed ticks to microseconds.</summary>
    public static long ElapsedUs(long startTicks)
        => (Stopwatch.GetTimestamp() - startTicks) * 1_000_000L / Stopwatch.Frequency;

    private static void UpdateMax(ref long location, long value)
    {
        long current;
        do { current = Volatile.Read(ref location); }
        while (value > current && Interlocked.CompareExchange(ref location, value, current) != current);
    }

    private static void UpdateMin(ref long location, long value)
    {
        long current;
        do { current = Volatile.Read(ref location); }
        while (value < current && Interlocked.CompareExchange(ref location, value, current) != current);
    }
}

/// <summary>Point-in-time snapshot of engine metrics (immutable).</summary>
public sealed record EngineMetricsSnapshot(
    // WAL
    long WalAppendCount, long WalAppendTotalUs, long WalAppendMaxUs, long WalAppendBytesTotal,
    // Locks
    long LockAcquireCount, long LockAcquireTotalUs, long LockAcquireMaxUs, long LockContentions,
    // Commits
    long CommitCount, long CommitSuccessCount, long CommitFailCount,
    long CommitTotalUs, long CommitMaxUs, long CommitRetryCount,
    // Delta sizes
    long DeltaSizeCount, long DeltaSizeTotal, long DeltaSizeMax, long DeltaSizeMin,
    // Compaction
    long CompactionCount, long CompactionTotalUs, long CompactionBytesReclaimed, long LastCompactionTimestamp,
    // Replay
    long ReplayCount, long ReplayTotalUs, long ReplayOpsTotal)
{
    public double WalAppendAvgUs => WalAppendCount > 0 ? (double)WalAppendTotalUs / WalAppendCount : 0;
    public double LockAcquireAvgUs => LockAcquireCount > 0 ? (double)LockAcquireTotalUs / LockAcquireCount : 0;
    public double CommitAvgUs => CommitCount > 0 ? (double)CommitTotalUs / CommitCount : 0;
    public double DeltaSizeAvg => DeltaSizeCount > 0 ? (double)DeltaSizeTotal / DeltaSizeCount : 0;
    public double CommitSuccessRate => CommitCount > 0 ? (double)CommitSuccessCount / CommitCount : 0;
    public double LockContentionRate => LockAcquireCount > 0 ? (double)LockContentions / LockAcquireCount : 0;
}
