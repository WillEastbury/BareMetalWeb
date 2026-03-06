using System;
using System.Threading;

namespace BareMetalWeb.Data;

/// <summary>
/// Immutable compiled snapshot of all entity/field/route metadata,
/// optimised for cache-friendly array-indexed reads on hot paths.
/// Rebuilt and atomically swapped when metadata changes.
/// </summary>
public sealed class RuntimeSnapshot
{
    private static volatile RuntimeSnapshot? _current;

    /// <summary>
    /// The currently active snapshot. Null until first compilation.
    /// Reads are lock-free (volatile reference swap).
    /// </summary>
    public static RuntimeSnapshot? Current
    {
        get => _current;
        private set => _current = value;
    }

    public readonly EntityTable Entities;
    public readonly FieldTable Fields;
    public readonly RouteTable Routes;
    public readonly long CompiledAtTicks;

    public RuntimeSnapshot(EntityTable entities, FieldTable fields, RouteTable routes)
    {
        Entities = entities;
        Fields = fields;
        Routes = routes;
        CompiledAtTicks = DateTime.UtcNow.Ticks;
    }

    /// <summary>
    /// Atomically replaces the current snapshot. Returns the previous snapshot (for diagnostics).
    /// </summary>
    public static RuntimeSnapshot? Swap(RuntimeSnapshot newSnapshot)
    {
        return Interlocked.Exchange(ref _current, newSnapshot);
    }
}
