using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.WebServer;

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

        lock (_throttleLock)
        {
            var stats = _stats.TryGetValue(clientIp, out var existing)
                ? existing
                : new ClientRequestStats(0, nowUtc, nowUtc, 0, DateTime.MinValue, false);

            stats = stats with
            {
                Count = stats.Count + 1,
                LastSeenUtc = nowUtc
            };

            if (stats.BlockedUntilUtc > nowUtc)
            {
                _stats[clientIp] = stats;
                reason = "blocked";
                retryAfterSeconds = Math.Max(1, (int)Math.Ceiling((stats.BlockedUntilUtc - nowUtc).TotalSeconds));
                return true;
            }

            if (stats.BlockedUntilUtc != DateTime.MinValue && stats.BlockedUntilUtc <= nowUtc)
            {
                stats = stats with
                {
                    BlockedUntilUtc = DateTime.MinValue,
                    IsSuspicious = true
                };
            }

            if (nowUtc - stats.WindowStartUtc >= TimeSpan.FromSeconds(1))
            {
                stats = stats with
                {
                    WindowStartUtc = nowUtc,
                    WindowCount = 1
                };
            }
            else
            {
                stats = stats with
                {
                    WindowCount = stats.WindowCount + 1
                };
            }

            var threshold = stats.IsSuspicious ? _suspiciousRpsThreshold : _normalRpsThreshold;
            if (threshold > 0 && stats.WindowCount > threshold)
            {
                stats = stats with
                {
                    BlockedUntilUtc = nowUtc + _blockDuration
                };
                _stats[clientIp] = stats;
                reason = stats.IsSuspicious ? "blocked-suspicious" : "blocked";
                retryAfterSeconds = Math.Max(1, (int)Math.Ceiling((stats.BlockedUntilUtc - nowUtc).TotalSeconds));
                return true;
            }

            _stats[clientIp] = stats;
            reason = string.Empty;
            return false;
        }
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
        return _stats
            .OrderByDescending(kvp => kvp.Value.Count)
            .ThenByDescending(kvp => kvp.Value.LastSeenUtc)
            .Take(count)
            .ToList();
    }

    public void GetTopClientsTable(int count, out string[] tableColumns, out string[][] tableRows)
    {
        var top = GetTopClients(count);
        tableColumns = new[] { "IP Address", "Requests", "Last Seen (UTC)" };
        tableRows = top.Count == 0
            ? new[] { new[] { "No requests recorded.", "", "" } }
            : top.Select(kvp => new[]
            {
                kvp.Key,
                kvp.Value.Count.ToString(),
                kvp.Value.LastSeenUtc.ToString("O")
            }).ToArray();
    }

    public IReadOnlyList<KeyValuePair<string, ClientRequestStats>> GetSuspiciousClients(int count)
    {
        var nowUtc = DateTime.UtcNow;
        return _stats
            .Where(kvp => kvp.Value.IsSuspicious || kvp.Value.BlockedUntilUtc > nowUtc)
            .OrderByDescending(kvp => kvp.Value.Count)
            .ThenByDescending(kvp => kvp.Value.LastSeenUtc)
            .Take(count)
            .ToList();
    }

    public void GetSuspiciousClientsTable(int count, out string[] tableColumns, out string[][] tableRows)
    {
        var suspicious = GetSuspiciousClients(count);
        tableColumns = new[] { "IP Address", "Requests", "Last Seen (UTC)" };
        tableRows = suspicious.Count == 0
            ? new[] { new[] { "No suspicious IPs recorded.", "", "" } }
            : suspicious.Select(kvp => new[]
            {
                kvp.Key,
                kvp.Value.Count.ToString(),
                kvp.Value.LastSeenUtc.ToString("O")
            }).ToArray();
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

        foreach (var kvp in _stats.OrderBy(k => k.Value.LastSeenUtc).Take(overflow))
        {
            if (_stats.TryRemove(kvp.Key, out _))
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
