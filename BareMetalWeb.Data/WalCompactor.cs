using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace BareMetalWeb.Data;

/// <summary>
/// Background service that periodically compacts WAL segments.
/// Iterates all segment files except the active one, checks whether compaction
/// would be beneficial (segment has more on-disk records than live head-map
/// references), and rewrites beneficial segments via <see cref="WalStore.CompactSegment"/>.
/// </summary>
public sealed class WalCompactor
{
    /// <summary>Default interval between compaction sweeps.</summary>
    private static readonly TimeSpan SweepInterval = TimeSpan.FromMinutes(5);

    private readonly WalStore _store;

    public WalCompactor(WalStore store)
    {
        ArgumentNullException.ThrowIfNull(store);
        _store = store;
    }

    /// <summary>
    /// Compacts all eligible segments (those with more on-disk records than
    /// live head-map references).  Skips the active segment.
    /// </summary>
    public void CompactAllSegments()
    {
        var segmentIds = _store.GetSegmentIds();
        uint? activeId = _store.ActiveSegmentId;

        // Snapshot the head map once for the benefit check
        _store.HeadMap.CopyArrays(out ulong[] keys, out ulong[] heads);

        for (int s = 0; s < segmentIds.Count; s++)
        {
            uint segId = segmentIds[s];
            if (activeId.HasValue && segId == activeId.Value)
                continue;

            // Count how many live head-map entries reference this segment
            int liveCount = 0;
            for (int i = 0; i < heads.Length; i++)
            {
                var (headSeg, _) = WalConstants.UnpackPtr(heads[i]);
                if (headSeg == segId) liveCount++;
            }

            if (liveCount == 0)
            {
                // No live keys — CompactSegment will delete the file
                _store.CompactSegment(segId);
                continue;
            }

            // Check segment record count via footer/linear-scan index
            string path = System.IO.Path.Combine(
                _store.SegmentDirectory, WalConstants.SegmentFileName(segId));
            if (!System.IO.File.Exists(path)) continue;

            var index = WalSegmentReader.TryReadFooterIndex(path)
                        ?? WalSegmentReader.LinearScanIndex(path);
            int diskKeyCount = index.Count;

            // Compact if disk has more records than live references (dead data exists)
            if (diskKeyCount > liveCount)
                _store.CompactSegment(segId);
        }
    }

    /// <summary>
    /// Runs periodic compaction sweeps until cancellation is requested.
    /// </summary>
    public async Task RunAsync(CancellationToken token)
    {
        // Initial delay to let the system settle after startup
        try { await Task.Delay(SweepInterval, token).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }

        while (!token.IsCancellationRequested)
        {
            try
            {
                CompactAllSegments();
            }
            catch (ObjectDisposedException)
            {
                // Store was disposed — exit cleanly
                return;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
            {
                Debug.WriteLine($"WalCompactor: sweep failed: {ex.GetType().Name}: {ex.Message}");
            }

            try { await Task.Delay(SweepInterval, token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }
}
