namespace BareMetalWeb.Data;

/// <summary>
/// In-memory circular buffer that stores the most recent query plan entries.
/// Thread-safe; retains at most <see cref="MaxEntries"/> entries.
/// </summary>
public static class QueryPlanHistory
{
    /// <summary>Maximum number of plan entries retained in memory.</summary>
    public const int MaxEntries = 100;

    private static readonly object _lock = new();
    private static readonly Queue<QueryPlanEntry> _entries = new(MaxEntries + 1);

    /// <summary>Records a completed plan execution.</summary>
    public static void Record(QueryPlanEntry entry)
    {
        lock (_lock)
        {
            _entries.Enqueue(entry);
            if (_entries.Count > MaxEntries)
                _entries.Dequeue();
        }
    }

    /// <summary>Returns a snapshot of all recorded entries, newest first.</summary>
    public static IReadOnlyList<QueryPlanEntry> GetSnapshot()
    {
        lock (_lock)
        {
            var copy = _entries.ToArray();
            Array.Reverse(copy);
            return copy;
        }
    }

    /// <summary>Removes all recorded entries.</summary>
    public static void Clear()
    {
        lock (_lock) { _entries.Clear(); }
    }
}

/// <summary>A single recorded query execution with its plan and timing.</summary>
public sealed class QueryPlanEntry
{
    /// <summary>UTC timestamp when the query was executed.</summary>
    public DateTimeOffset ExecutedAt { get; init; }

    /// <summary>Root entity slug queried.</summary>
    public string RootEntity { get; init; } = string.Empty;

    /// <summary>Number of entities joined in the query.</summary>
    public int JoinCount { get; init; }

    /// <summary>Number of result rows returned.</summary>
    public int ResultRowCount { get; init; }

    /// <summary>Wall-clock execution time in milliseconds.</summary>
    public double ElapsedMs { get; init; }

    /// <summary>The optimised execution plan produced for this query.</summary>
    public QueryPlan Plan { get; init; } = null!;
}
