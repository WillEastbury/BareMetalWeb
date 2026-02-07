using System;
using System.Collections.Generic;

namespace BareMetalWeb.WebServer;

public sealed class ProxyRoutingOptions
{
    public List<ProxyRouteConfig> Routes { get; set; } = new();
}

public sealed class ProxyRouteConfig
{
    public string Route { get; set; } = "/proxy";
    public string Verb { get; set; } = "ALL";
    public string MatchMode { get; set; } = "Equals"; // Equals | StartsWith | Regex
    public string? TargetBaseUrl { get; set; }
    public List<string> Targets { get; set; } = new();
    public List<ProxyTargetConfig> TargetConfigs { get; set; } = new();

    public string LoadBalance { get; set; } = "RoundRobin"; // RoundRobin | Failover

    public Dictionary<string, string> AddHeaders { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> RemoveHeaders { get; set; } = new();

    public bool StickySessionsEnabled { get; set; } = false;
    public string StickySessionMode { get; set; } = "Cookie"; // Cookie | IpHash
    public string StickySessionKeyName { get; set; } = "X-Proxy-Session";
    public int StickySessionTtlSeconds { get; set; } = 3600;

    public string? PathPrefixToStrip { get; set; }
    public string? PathPrefixToAdd { get; set; }
    public string? RewritePath { get; set; }
    public bool IncludeQuery { get; set; } = true;

    public bool RetryIdempotentRequests { get; set; } = true;
    public string RetryAllMethodsHeader { get; set; } = "X-Proxy-Retry-All";
    public int MaxRetries { get; set; } = 1;
    public int MaxRetryBodyBytes { get; set; } = 1048576;
    public int RetryBaseDelayMs { get; set; } = 100;
    public int RetryMaxDelayMs { get; set; } = 2000;
    public bool RetryUseJitter { get; set; } = true;
    public bool UseStatus499ForClientAbort { get; set; } = true;
    public string TraceIdHeader { get; set; } = "X-Trace-ID";
    public bool EnableVerboseLog { get; set; } = false;

    public int FailureWindowSeconds { get; set; } = 60;
    public double FailurePercentageThreshold { get; set; } = 50;
    public int MinimumRequestsInWindow { get; set; } = 10;
    public int OfflineSeconds { get; set; } = 60;
}

public sealed class ProxyTargetState
{
    public Uri BaseUri { get; }
    public int Weight { get; }
    private readonly object _sync = new();
    private int _windowTotal;
    private int _windowFailed;
    private DateTimeOffset _windowStart;
    private DateTimeOffset _offlineUntil;
    private long _totalSuccess;
    private long _totalFailure;

    public ProxyTargetState(Uri baseUri, int weight)
    {
        BaseUri = baseUri;
        Weight = Math.Max(1, weight);
        _windowStart = DateTimeOffset.UtcNow;
    }

    public bool IsOffline(DateTimeOffset now)
    {
        lock (_sync)
        {
            return now < _offlineUntil;
        }
    }

    public void RecordSuccess(DateTimeOffset now, int windowSeconds)
    {
        lock (_sync)
        {
            EnsureWindow(now, windowSeconds);
            _windowTotal++;
            _totalSuccess++;
        }
    }

    public void RecordFailure(DateTimeOffset now, int windowSeconds)
    {
        lock (_sync)
        {
            EnsureWindow(now, windowSeconds);
            _windowTotal++;
            _windowFailed++;
            _totalFailure++;
        }
    }

    public bool ShouldTrip(double failurePercentageThreshold, int minimumRequests)
    {
        if (_windowTotal < minimumRequests)
            return false;

        if (_windowTotal == 0)
            return false;

        var failureRate = (double)_windowFailed / _windowTotal * 100.0;
        return failureRate >= failurePercentageThreshold;
    }

    public void TakeOffline(DateTimeOffset now, TimeSpan duration)
    {
        lock (_sync)
        {
            _offlineUntil = now.Add(duration);
            _windowTotal = 0;
            _windowFailed = 0;
            _windowStart = now;
        }
    }

    public ProxyTargetStatus Snapshot(DateTimeOffset now)
    {
        lock (_sync)
        {
            var online = now >= _offlineUntil;
            return new ProxyTargetStatus
            {
                Uri = BaseUri.ToString(),
                Weight = Weight,
                Online = online,
                OfflineUntil = online ? null : _offlineUntil,
                Successes = _totalSuccess,
                Failures = _totalFailure,
                WindowTotal = _windowTotal,
                WindowFailures = _windowFailed,
                WindowSuccesses = _windowTotal - _windowFailed
            };
        }
    }

    private void EnsureWindow(DateTimeOffset now, int windowSeconds)
    {
        if ((now - _windowStart).TotalSeconds <= windowSeconds)
            return;

        _windowStart = now;
        _windowTotal = 0;
        _windowFailed = 0;
    }
}

public sealed class ProxyRouteStatus
{
    public string Route { get; set; } = string.Empty;
    public string MatchMode { get; set; } = string.Empty;
    public string LoadBalance { get; set; } = string.Empty;
    public ProxyTargetStatus[] Targets { get; set; } = Array.Empty<ProxyTargetStatus>();
}

public sealed class ProxyTargetStatus
{
    public string Uri { get; set; } = string.Empty;
    public int Weight { get; set; }
    public bool Online { get; set; }
    public DateTimeOffset? OfflineUntil { get; set; }
    public long Successes { get; set; }
    public long Failures { get; set; }
    public int WindowTotal { get; set; }
    public int WindowFailures { get; set; }
    public int WindowSuccesses { get; set; }
}

public sealed class ProxyTargetConfig
{
    public string Uri { get; set; } = string.Empty;
    public int Weight { get; set; } = 1;
}
