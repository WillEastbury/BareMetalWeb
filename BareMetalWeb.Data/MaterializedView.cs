using System.Collections.Concurrent;
using System.Threading;

namespace BareMetalWeb.Data;

/// <summary>
/// Materialised-view cache that stores the pre-computed <see cref="ReportResult"/>
/// for a set of <see cref="ViewDefinition"/> objects and refreshes them incrementally
/// when relevant entity changes are reported.
///
/// <para>
/// Registration model:
/// <list type="number">
///   <item>Call <see cref="Register"/> to add a view definition that should be materialised.</item>
///   <item>On first access (or after invalidation) <see cref="GetOrRefreshAsync"/> computes
///         the result and caches it.</item>
///   <item>Call <see cref="NotifyEntityChanged"/> after any save/delete on an entity to
///         automatically invalidate all materialised views that depend on that entity.</item>
/// </list>
/// </para>
///
/// <para>
/// Incremental WAL integration: register this cache with the WAL data provider's
/// <c>AfterEntitySaved</c> / <c>AfterEntityDeleted</c> hooks (or any similar mechanism)
/// so that invalidation happens automatically after every committed write:
/// <code>
/// MaterializedViewCache.Instance.NotifyEntityChanged("orders");
/// </code>
/// </para>
/// </summary>
public sealed class MaterializedViewCache
{
    private static readonly MaterializedViewCache _instance = new();
    /// <summary>Global singleton instance.</summary>
    public static MaterializedViewCache Instance => _instance;

    // viewName → entry
    private readonly ConcurrentDictionary<string, CacheEntry> _entries =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly ViewEngine _engine = new();

    private MaterializedViewCache() { }

    // ── Registration ──────────────────────────────────────────────────────────

    /// <summary>
    /// Registers a <see cref="ViewDefinition"/> for materialisation.
    /// The result is computed lazily on first call to <see cref="GetOrRefreshAsync"/>.
    /// </summary>
    public void Register(ViewDefinition def)
    {
        ArgumentNullException.ThrowIfNull(def);
        _entries[def.ViewName] = new CacheEntry(def);
    }

    /// <summary>Unregisters and drops the cached result for a view by name.</summary>
    public void Unregister(string viewName)
        => _entries.TryRemove(viewName, out _);

    // ── Access ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the cached <see cref="ReportResult"/> for <paramref name="viewName"/>,
    /// computing it if the cache is cold or has been invalidated.
    /// Returns null when no view with that name is registered.
    /// </summary>
    public ValueTask<ReportResult?> GetOrRefreshAsync(
        string viewName,
        CancellationToken cancellationToken = default)
    {
        if (!_entries.TryGetValue(viewName, out var entry))
            return ValueTask.FromResult<ReportResult?>(null);

        return entry.GetOrRefreshAsync(_engine, cancellationToken);
    }

    // ── Invalidation ──────────────────────────────────────────────────────────

    /// <summary>
    /// Notifies the cache that data for <paramref name="entitySlug"/> has changed.
    /// All materialised views that depend on this entity are invalidated and will be
    /// recomputed on next access.
    ///
    /// <para>
    /// This is the primary hook for WAL-driven incremental refresh.  Call after every
    /// committed save or delete:
    /// <code>
    /// MaterializedViewCache.Instance.NotifyEntityChanged(entitySlug);
    /// </code>
    /// </para>
    /// </summary>
    public void NotifyEntityChanged(string entitySlug)
    {
        foreach (var (_, entry) in _entries)
        {
            if (entry.DependsOn(entitySlug))
                entry.Invalidate();
        }
    }

    /// <summary>Invalidates the cache for a specific view by name.</summary>
    public void InvalidateView(string viewName)
    {
        if (_entries.TryGetValue(viewName, out var entry))
            entry.Invalidate();
    }

    /// <summary>Invalidates all cached view results.</summary>
    public void InvalidateAll()
    {
        foreach (var (_, entry) in _entries)
            entry.Invalidate();
    }

    // ── Internal entry ────────────────────────────────────────────────────────

    private sealed class CacheEntry
    {
        private readonly ViewDefinition _def;
        private readonly HashSet<string> _entityDeps;
        private volatile ReportResult? _cached;
        private long _invalidated = 1; // starts invalidated → computed on first access
        private readonly SemaphoreSlim _refreshLock = new(1, 1);

        internal CacheEntry(ViewDefinition def)
        {
            _def        = def;
            _entityDeps = BuildDeps(def);
        }

        internal bool DependsOn(string entitySlug)
            => _entityDeps.Contains(entitySlug);

        internal void Invalidate()
        {
            Interlocked.Exchange(ref _invalidated, 1);
            ViewEngine.InvalidatePlan(BuildCacheKey(_def));
        }

        internal async ValueTask<ReportResult?> GetOrRefreshAsync(
            ViewEngine engine,
            CancellationToken cancellationToken)
        {
            // Fast path: not invalidated
            if (Interlocked.Read(ref _invalidated) == 0 && _cached != null)
                return _cached;

            // Only one refresh at a time per entry
            await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (Interlocked.Read(ref _invalidated) == 0 && _cached != null)
                    return _cached; // double-checked

                _cached = await engine.ExecuteAsync(_def, cancellationToken).ConfigureAwait(false);
                Interlocked.Exchange(ref _invalidated, 0);
                return _cached;
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        private static HashSet<string> BuildDeps(ViewDefinition def)
        {
            var deps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrWhiteSpace(def.RootEntity))
                deps.Add(def.RootEntity);
            foreach (var j in def.Joins)
            {
                if (!string.IsNullOrWhiteSpace(j.SourceEntity)) deps.Add(j.SourceEntity);
                if (!string.IsNullOrWhiteSpace(j.TargetEntity)) deps.Add(j.TargetEntity);
            }
            return deps;
        }

        private static string BuildCacheKey(ViewDefinition def)
            => $"{def.Key}:{def.ViewName}:{def.RootEntity}";
    }
}
