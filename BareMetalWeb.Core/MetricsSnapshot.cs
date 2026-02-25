namespace BareMetalWeb.Host;

public readonly record struct MetricsSnapshot(
    long TotalRequests,
    long ErrorRequests,
    TimeSpan AverageResponseTime,
    TimeSpan RecentMinimumResponseTime,
    TimeSpan RecentMaximumResponseTime,
    TimeSpan RecentAverageResponseTime,
    TimeSpan RecentP95ResponseTime,
    TimeSpan RecentP99ResponseTime,
    TimeSpan Recent10sAverageResponseTime,
    long Requests2xx,
    long Requests4xx,
    long Requests5xx,
    long RequestsOther,
    long ThrottledRequests,
    int ProcessId,
    long WorkingSet64,
    long VirtualMemorySize64
);
