using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;

namespace BareMetalWeb.Data;

/// <summary>
/// Deterministic WAL replay validator. Replays all WAL segments into a fresh
/// head map and validates:
/// - Record integrity (CRC32C checksums)
/// - Footer consistency (footer index vs linear scan)
/// - Head map convergence (replayed state matches live state)
/// - Non-determinism detection (multiple replays yield identical state)
/// - Performance metrics (replay cost, throughput)
///
/// Can be invoked programmatically or via CLI entry point.
/// </summary>
public sealed class WalReplayValidator
{
    private readonly string _walDirectory;
    private readonly TextWriter _output;

    public WalReplayValidator(string walDirectory, TextWriter? output = null)
    {
        _walDirectory = walDirectory ?? throw new ArgumentNullException(nameof(walDirectory));
        _output = output ?? Console.Out;
    }

    /// <summary>
    /// Run a full replay validation pass. Returns a result summary.
    /// </summary>
    public WalReplayResult Validate(bool compareWithLive = false, int replayPasses = 1)
    {
        var sw = Stopwatch.StartNew();
        var result = new WalReplayResult();

        // 1. Discover segments
        var segmentFiles = DiscoverSegments();
        result.SegmentCount = segmentFiles.Count;
        _output.WriteLine($"[WAL Replay] Found {segmentFiles.Count} segment(s) in {_walDirectory}");

        if (segmentFiles.Count == 0)
        {
            result.Success = true;
            result.ElapsedMs = sw.ElapsedMilliseconds;
            _output.WriteLine("[WAL Replay] No segments to validate.");
            return result;
        }

        // 2. Validate each segment
        foreach (var (segId, path) in segmentFiles)
        {
            var segResult = ValidateSegment(segId, path);
            result.SegmentResults.Add(segResult);
            result.TotalRecords += segResult.RecordCount;
            result.TotalOps += segResult.OpCount;
            result.TotalBytes += segResult.ByteCount;
            result.CrcErrors += segResult.CrcErrors;
            result.TruncatedRecords += segResult.TruncatedRecords;
        }

        // 3. Replay into fresh head map
        _output.WriteLine("[WAL Replay] Replaying segments into fresh head map...");
        var replayHeadMap = ReplayToHeadMap(segmentFiles);
        result.ReplayedKeys = replayHeadMap.Count;
        _output.WriteLine($"[WAL Replay] Replayed {result.ReplayedKeys} unique keys");

        // 4. Multi-pass determinism check
        if (replayPasses > 1)
        {
            _output.WriteLine($"[WAL Replay] Running {replayPasses} replay passes for determinism check...");
            bool deterministic = true;

            for (int pass = 1; pass < replayPasses; pass++)
            {
                var checkMap = ReplayToHeadMap(segmentFiles);
                if (!HeadMapsEqual(replayHeadMap, checkMap))
                {
                    deterministic = false;
                    _output.WriteLine($"[WAL Replay] ⚠ Pass {pass + 1} produced different head map!");
                    break;
                }
            }

            result.Deterministic = deterministic;
            _output.WriteLine(deterministic
                ? $"[WAL Replay] ✓ All {replayPasses} passes produced identical head maps"
                : "[WAL Replay] ✗ NON-DETERMINISM DETECTED");
        }
        else
        {
            result.Deterministic = true;
        }

        // 5. Compare with live store if requested
        if (compareWithLive)
        {
            _output.WriteLine("[WAL Replay] Comparing with live WalStore...");
            try
            {
                using var liveStore = new WalStore(_walDirectory);
                result.LiveKeyCount = liveStore.HeadMap.Count;

                int mismatches = 0;
                int missing = 0;

                liveStore.HeadMap.CopyArrays(out var liveKeys, out var liveHeads);
                for (int i = 0; i < liveKeys.Length; i++)
                {
                    if (!replayHeadMap.TryGetValue(liveKeys[i], out var replayPtr))
                    {
                        missing++;
                        continue;
                    }

                    if (replayPtr != liveHeads[i])
                        mismatches++;
                }

                // Check for keys in replay but not in live
                int extra = 0;
                foreach (var k in replayHeadMap.Keys)
                {
                    bool foundInLive = false;
                    for (int i = 0; i < liveKeys.Length; i++)
                    {
                        if (liveKeys[i] == k)
                        {
                            foundInLive = true;
                            break;
                        }
                    }
                    if (!foundInLive)
                        extra++;
                }

                result.HeadMapMismatches = mismatches;
                result.MissingFromReplay = missing;
                result.ExtraInReplay = extra;

                _output.WriteLine(mismatches == 0 && missing == 0 && extra == 0
                    ? "[WAL Replay] ✓ Head maps match perfectly"
                    : $"[WAL Replay] ✗ Mismatches: {mismatches}, Missing: {missing}, Extra: {extra}");
            }
            catch (Exception ex)
            {
                _output.WriteLine($"[WAL Replay] ⚠ Could not compare with live store: {ex.Message}");
            }
        }

        sw.Stop();
        result.ElapsedMs = sw.ElapsedMilliseconds;
        result.Success = result.CrcErrors == 0 && result.Deterministic;

        _output.WriteLine();
        _output.WriteLine("═══ WAL Replay Validation Summary ═══");
        _output.WriteLine($"  Segments:    {result.SegmentCount}");
        _output.WriteLine($"  Records:     {result.TotalRecords}");
        _output.WriteLine($"  Operations:  {result.TotalOps}");
        _output.WriteLine($"  Total bytes: {result.TotalBytes:N0}");
        _output.WriteLine($"  Unique keys: {result.ReplayedKeys}");
        _output.WriteLine($"  CRC errors:  {result.CrcErrors}");
        _output.WriteLine($"  Truncated:   {result.TruncatedRecords}");
        _output.WriteLine($"  Deterministic: {(result.Deterministic ? "✓" : "✗")}");
        _output.WriteLine($"  Elapsed:     {result.ElapsedMs} ms");
        _output.WriteLine($"  Throughput:  {(result.TotalBytes > 0 ? result.TotalBytes * 1000.0 / result.ElapsedMs / 1024 / 1024 : 0):F1} MB/s");
        _output.WriteLine($"  Result:      {(result.Success ? "PASS ✓" : "FAIL ✗")}");

        return result;
    }

    private List<(uint SegmentId, string Path)> DiscoverSegments()
    {
        var segments = new List<(uint, string)>();

        if (!Directory.Exists(_walDirectory))
            return segments;

        foreach (var file in Directory.GetFiles(_walDirectory, "wal_seg_*.log"))
        {
            var name = Path.GetFileName(file);
            if (WalConstants.TryParseSegmentId(name, out var segId))
                segments.Add((segId, file));
        }

        segments.Sort((a, b) => a.Item1.CompareTo(b.Item1));
        return segments;
    }

    private SegmentValidationResult ValidateSegment(uint segmentId, string path)
    {
        var result = new SegmentValidationResult { SegmentId = segmentId };

        try
        {
            var fileInfo = new FileInfo(path);
            result.ByteCount = fileInfo.Length;

            // Validate footer
            var footerIndex = WalSegmentReader.TryReadFooterIndex(path);
            result.HasValidFooter = footerIndex != null;

            // Linear scan (always do this for completeness)
            var scanIndex = WalSegmentReader.LinearScanIndex(path);
            result.RecordCount = scanIndex.Count;

            // Compare footer vs scan if both available
            if (footerIndex != null)
            {
                int footerMismatch = 0;
                foreach (var (key, offset) in footerIndex)
                {
                    if (!scanIndex.TryGetValue(key, out var scanOffset) || scanOffset != offset)
                        footerMismatch++;
                }
                result.FooterScanMismatches = footerMismatch;
            }

            // CRC validation by reading raw records
            result.CrcErrors = ValidateRecordCrcs(path);
            result.OpCount = CountOps(path);

            var status = result.CrcErrors == 0
                ? (result.HasValidFooter ? "✓ clean" : "✓ no footer (crash recovery)")
                : $"✗ {result.CrcErrors} CRC error(s)";

            _output.WriteLine($"  Segment {segmentId:D10}: {result.RecordCount} records, {result.OpCount} ops, {result.ByteCount:N0} bytes — {status}");
        }
        catch (Exception ex)
        {
            _output.WriteLine($"  Segment {segmentId:D10}: ERROR — {ex.Message}");
            result.Error = ex.Message;
        }

        return result;
    }

    private static int ValidateRecordCrcs(string path)
    {
        int errors = 0;

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite, 64 * 1024, FileOptions.SequentialScan);

        // Skip segment header
        if (fs.Length < WalConstants.SegmentHeaderBytes)
            return 0;

        fs.Position = WalConstants.SegmentHeaderBytes;

        var headerBuf = new byte[WalConstants.RecordHeaderBytes];

        while (fs.Position + WalConstants.RecordHeaderBytes <= fs.Length)
        {
            long recordStart = fs.Position;
            int read = fs.Read(headerBuf, 0, WalConstants.RecordHeaderBytes);
            if (read < WalConstants.RecordHeaderBytes) break;

            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(headerBuf);
            if (magic != WalConstants.RecordMagic) break;

            uint totalBytes = BinaryPrimitives.ReadUInt32LittleEndian(headerBuf.AsSpan(8));
            if (totalBytes < WalConstants.RecordHeaderBytes + WalConstants.RecordTrailerBytes)
                break;

            if (recordStart + totalBytes > fs.Length) break;

            // Read entire record for CRC check
            var recordBuf = new byte[totalBytes];
            fs.Position = recordStart;
            read = fs.Read(recordBuf, 0, (int)totalBytes);
            if (read < (int)totalBytes) break;

            // Extract stored CRC, zero CRC fields, compute
            uint storedHeaderCrc = BinaryPrimitives.ReadUInt32LittleEndian(recordBuf.AsSpan(24));

            // Zero CRC fields for computation
            BinaryPrimitives.WriteUInt32LittleEndian(recordBuf.AsSpan(24), 0);
            // Trailer CRC at totalBytes - 8
            if (totalBytes >= WalConstants.RecordTrailerBytes)
                BinaryPrimitives.WriteUInt32LittleEndian(recordBuf.AsSpan((int)totalBytes - 8), 0);

            uint computed = WalCrc32C.Compute(recordBuf);
            if (computed != storedHeaderCrc)
                errors++;
        }

        return errors;
    }

    private static int CountOps(string path)
    {
        int total = 0;

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite, 64 * 1024, FileOptions.SequentialScan);

        if (fs.Length < WalConstants.SegmentHeaderBytes)
            return 0;

        fs.Position = WalConstants.SegmentHeaderBytes;

        var headerBuf = new byte[WalConstants.RecordHeaderBytes];
        var batchHeaderBuf = new byte[16]; // TxId(8) + OpCount(4) + Flags(4)

        while (fs.Position + WalConstants.RecordHeaderBytes <= fs.Length)
        {
            long recordStart = fs.Position;
            int read = fs.Read(headerBuf, 0, WalConstants.RecordHeaderBytes);
            if (read < WalConstants.RecordHeaderBytes) break;

            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(headerBuf);
            if (magic != WalConstants.RecordMagic) break;

            uint totalBytes = BinaryPrimitives.ReadUInt32LittleEndian(headerBuf.AsSpan(8));
            if (totalBytes < WalConstants.RecordHeaderBytes + 16 + WalConstants.RecordTrailerBytes)
                break;

            // Read commit batch header
            read = fs.Read(batchHeaderBuf, 0, 16);
            if (read < 16) break;

            int opCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(batchHeaderBuf.AsSpan(8));
            total += opCount;

            // Skip to next record
            fs.Position = recordStart + totalBytes;
        }

        return total;
    }

    private Dictionary<ulong, ulong> ReplayToHeadMap(List<(uint SegmentId, string Path)> segments)
    {
        var headMap = new Dictionary<ulong, ulong>();

        foreach (var (segId, path) in segments)
        {
            // Try footer first, fall back to linear scan
            var index = WalSegmentReader.TryReadFooterIndex(path)
                        ?? WalSegmentReader.LinearScanIndex(path);

            foreach (var (key, offset32) in index)
            {
                var ptr = WalConstants.PackPtr(segId, offset32);
                headMap[key] = ptr; // latest wins (segments ordered oldest→newest)
            }
        }

        return headMap;
    }

    private static bool HeadMapsEqual(Dictionary<ulong, ulong> a, Dictionary<ulong, ulong> b)
    {
        if (a.Count != b.Count) return false;
        foreach (var (key, val) in a)
        {
            if (!b.TryGetValue(key, out var bVal) || bVal != val)
                return false;
        }
        return true;
    }

    // ── CLI Entry Point ──────────────────────────────────────────────────────

    /// <summary>
    /// CLI entry point for WAL replay validation.
    /// Usage: dotnet run -- wal-validate [path] [--passes N] [--compare]
    /// </summary>
    public static int RunCli(string[] args)
    {
        string walDir = ".";
        int passes = 2;
        bool compare = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--passes" when i + 1 < args.Length:
                    passes = int.Parse(args[++i]);
                    break;
                case "--compare":
                    compare = true;
                    break;
                default:
                    if (!args[i].StartsWith("--"))
                        walDir = args[i];
                    break;
            }
        }

        Console.WriteLine($"WAL Replay Validator — BareMetalWeb");
        Console.WriteLine($"Directory: {Path.GetFullPath(walDir)}");
        Console.WriteLine($"Passes:    {passes}");
        Console.WriteLine();

        var validator = new WalReplayValidator(walDir);
        var result = validator.Validate(compareWithLive: compare, replayPasses: passes);

        return result.Success ? 0 : 1;
    }
}

/// <summary>Overall replay validation result.</summary>
public sealed class WalReplayResult
{
    public bool Success { get; set; }
    public int SegmentCount { get; set; }
    public int TotalRecords { get; set; }
    public int TotalOps { get; set; }
    public long TotalBytes { get; set; }
    public int ReplayedKeys { get; set; }
    public int CrcErrors { get; set; }
    public int TruncatedRecords { get; set; }
    public bool Deterministic { get; set; }
    public long ElapsedMs { get; set; }
    public int? LiveKeyCount { get; set; }
    public int HeadMapMismatches { get; set; }
    public int MissingFromReplay { get; set; }
    public int ExtraInReplay { get; set; }
    public List<SegmentValidationResult> SegmentResults { get; set; } = new();
}

/// <summary>Per-segment validation result.</summary>
public sealed class SegmentValidationResult
{
    public uint SegmentId { get; set; }
    public int RecordCount { get; set; }
    public int OpCount { get; set; }
    public long ByteCount { get; set; }
    public int CrcErrors { get; set; }
    public int TruncatedRecords { get; set; }
    public bool HasValidFooter { get; set; }
    public int FooterScanMismatches { get; set; }
    public string? Error { get; set; }
}
