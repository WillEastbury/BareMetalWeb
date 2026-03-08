using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Host;

public sealed class ClientRequestTracker : IClientRequestTracker
{
    private readonly TimeSpan _staleThreshold;
    private readonly TimeSpan _pruneInterval;
    private readonly int _maxEntries;
    private readonly int _normalRpsThreshold;
    private readonly int _suspiciousRpsThreshold;
    private readonly TimeSpan _blockDuration;
    private readonly HashSet<string> _allowList;
    private readonly HashSet<string> _denyList;
    private readonly object _throttleLock = new();
    private readonly IBufferedLogger _logger;
    private readonly ConcurrentDictionary<string, ClientRequestStats> _stats = new();

    public ClientRequestTracker(
        IBufferedLogger logger,
        int normalRpsThreshold = 60,
        int suspiciousRpsThreshold = 20,
        TimeSpan? blockDuration = null,
        IEnumerable<string>? allowList = null,
        IEnumerable<string>? denyList = null,
        TimeSpan? staleThreshold = null,
        TimeSpan? pruneInterval = null,
        int maxEntries = 10000)
    {
        _logger = logger;
        _normalRpsThreshold = normalRpsThreshold;
        _suspiciousRpsThreshold = suspiciousRpsThreshold;
        _blockDuration = blockDuration ?? TimeSpan.FromMinutes(1);
        _staleThreshold = staleThreshold ?? TimeSpan.FromSeconds(10);
        _pruneInterval = pruneInterval ?? TimeSpan.FromSeconds(2);
        _maxEntries = maxEntries;
        _allowList = allowList != null
            ? new HashSet<string>(allowList, StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _denyList = denyList != null
            ? new HashSet<string>(denyList, StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    }

    public bool ShouldThrottle(string clientIp, out string reason, out int? retryAfterSeconds)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
            clientIp = "unknown";

        var nowUtc = DateTime.UtcNow;
        retryAfterSeconds = null;

        // Always bypass throttling for loopback addresses
        if (clientIp is "127.0.0.1" or "::1")
        {
            reason = string.Empty;
            return false;
        }

        if (_allowList.Contains(clientIp))
        {
            RecordRequest(clientIp, nowUtc);
            reason = string.Empty;
            return false;
        }

        if (_denyList.Contains(clientIp))
        {
            RecordRequest(clientIp, nowUtc);
            reason = "deny-list";
            return true;
        }

        // Use ConcurrentDictionary.AddOrUpdate for lock-free read-modify-write
        var nowLocal = nowUtc; // capture for closure
        var updated = _stats.AddOrUpdate(clientIp,
            _ => new ClientRequestStats(1, nowLocal, nowLocal, 1, DateTime.MinValue, false),
            (_, stats) =>
            {
                stats = stats with { Count = stats.Count + 1, LastSeenUtc = nowLocal };
                if (stats.BlockedUntilUtc != DateTime.MinValue && stats.BlockedUntilUtc <= nowLocal)
                    stats = stats with { BlockedUntilUtc = DateTime.MinValue, IsSuspicious = true };
                if (nowLocal - stats.WindowStartUtc >= TimeSpan.FromSeconds(1))
                    stats = stats with { WindowStartUtc = nowLocal, WindowCount = 1 };
                else
                    stats = stats with { WindowCount = stats.WindowCount + 1 };
                var threshold = stats.IsSuspicious ? _suspiciousRpsThreshold : _normalRpsThreshold;
                if (threshold > 0 && stats.WindowCount > threshold)
                    stats = stats with { BlockedUntilUtc = nowLocal + _blockDuration };
                return stats;
            });

        if (updated.BlockedUntilUtc > nowUtc)
        {
            reason = updated.IsSuspicious ? "blocked-suspicious" : "blocked";
            retryAfterSeconds = Math.Max(1, (int)Math.Ceiling((updated.BlockedUntilUtc - nowUtc).TotalSeconds));
            return true;
        }

        reason = string.Empty;
        return false;
    }

    public void RecordRequest(string clientIp)
    {
        if (string.IsNullOrWhiteSpace(clientIp))
            clientIp = "unknown";

        RecordRequest(clientIp, DateTime.UtcNow);
    }

    private void RecordRequest(string clientIp, DateTime nowUtc)
    {
        _stats.AddOrUpdate(
            clientIp,
            _ => new ClientRequestStats(1, nowUtc, nowUtc, 1, DateTime.MinValue, false),
            (_, existing) => existing with
            {
                Count = existing.Count + 1,
                LastSeenUtc = nowUtc
            });
    }

    public IReadOnlyDictionary<string, ClientRequestStats> Snapshot()
    {
        return new Dictionary<string, ClientRequestStats>(_stats);
    }

    public IReadOnlyList<KeyValuePair<string, ClientRequestStats>> GetTopClients(int count)
    {
        var list = new List<KeyValuePair<string, ClientRequestStats>>(_stats);
        list.Sort((a, b) =>
        {
            int cmp = b.Value.Count.CompareTo(a.Value.Count);
            if (cmp != 0) return cmp;
            return b.Value.LastSeenUtc.CompareTo(a.Value.LastSeenUtc);
        });
        if (list.Count > count)
            list.RemoveRange(count, list.Count - count);
        return list;
    }

    public void GetTopClientsTable(int count, out string[] tableColumns, out string[][] tableRows)
    {
        var top = GetTopClients(count);
        tableColumns = new[] { "IP Address", "Requests", "Last Seen (UTC)" };
        if (top.Count == 0)
        {
            tableRows = new[] { new[] { "No requests recorded.", "", "" } };
        }
        else
        {
            tableRows = new string[top.Count][];
            for (int i = 0; i < top.Count; i++)
            {
                tableRows[i] = new[]
                {
                    top[i].Key,
                    top[i].Value.Count.ToString(),
                    top[i].Value.LastSeenUtc.ToString("O")
                };
            }
        }
    }

    public IReadOnlyList<KeyValuePair<string, ClientRequestStats>> GetSuspiciousClients(int count)
    {
        var nowUtc = DateTime.UtcNow;
        var filtered = new List<KeyValuePair<string, ClientRequestStats>>();
        foreach (var kvp in _stats)
        {
            if (kvp.Value.IsSuspicious || kvp.Value.BlockedUntilUtc > nowUtc)
                filtered.Add(kvp);
        }
        filtered.Sort((a, b) =>
        {
            int cmp = b.Value.Count.CompareTo(a.Value.Count);
            if (cmp != 0) return cmp;
            return b.Value.LastSeenUtc.CompareTo(a.Value.LastSeenUtc);
        });
        if (filtered.Count > count)
            filtered.RemoveRange(count, filtered.Count - count);
        return filtered;
    }

    public void GetSuspiciousClientsTable(int count, out string[] tableColumns, out string[][] tableRows)
    {
        var suspicious = GetSuspiciousClients(count);
        tableColumns = new[] { "IP Address", "Requests", "Last Seen (UTC)" };
        if (suspicious.Count == 0)
        {
            tableRows = new[] { new[] { "No suspicious IPs recorded.", "", "" } };
        }
        else
        {
            tableRows = new string[suspicious.Count][];
            for (int i = 0; i < suspicious.Count; i++)
            {
                tableRows[i] = new[]
                {
                    suspicious[i].Key,
                    suspicious[i].Value.Count.ToString(),
                    suspicious[i].Value.LastSeenUtc.ToString("O")
                };
            }
        }
    }

    public async Task RunPruningAsync(CancellationToken token)
    {
        _logger.LogInfo("ClientRequestTracker pruning loop starting.");

        while (!token.IsCancellationRequested)
        {
            try
            {
                var pruned = PruneIfNeeded();
                if (pruned > 0)
                    _logger.LogInfo($"ClientRequestTracker pruned {pruned} records.");
            }
            catch (Exception ex)
            {
                _logger.LogError("ClientRequestTracker pruning error.", ex);
            }
            try
            {
                await Task.Delay(_pruneInterval, token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInfo("ClientRequestTracker pruning loop stopped.");
    }

    private int PruneIfNeeded()
    {
        var pruned = RemoveStaleEntries();
        if (_stats.Count <= _maxEntries)
            return pruned;

        var overflow = _stats.Count - _maxEntries;
        if (overflow <= 0)
            return pruned;

        var list = new List<KeyValuePair<string, ClientRequestStats>>(_stats);
        list.Sort((a, b) => a.Value.LastSeenUtc.CompareTo(b.Value.LastSeenUtc));
        int removeCount = Math.Min(overflow, list.Count);
        for (int i = 0; i < removeCount; i++)
        {
            if (_stats.TryRemove(list[i].Key, out _))
                pruned++;
        }

        return pruned;
    }

    private int RemoveStaleEntries()
    {
        var pruned = 0;
        var nowUtc = DateTime.UtcNow;
        var cutoff = nowUtc - _staleThreshold;
        foreach (var kvp in _stats)
        {
            if (kvp.Value.BlockedUntilUtc > nowUtc)
                continue;

            if (kvp.Value.LastSeenUtc < cutoff)
            {
                if (_stats.TryRemove(kvp.Key, out _))
                    pruned++;
            }
        }

        return pruned;
    }
    
}

public readonly record struct ClientRequestStats(
    long Count,
    DateTime LastSeenUtc,
    DateTime WindowStartUtc,
    int WindowCount,
    DateTime BlockedUntilUtc,
    bool IsSuspicious
);
