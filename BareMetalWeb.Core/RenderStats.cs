using System.Runtime.CompilerServices;

namespace BareMetalWeb.Core;

/// <summary>Per-render statistics collected during a single page render cycle.</summary>
public struct RenderStats
{
    public int WriteCount;
    public int BytesWritten;
    public int FlushCount;
    public int TokenCount;
    public int FragmentCount;

    public override readonly string ToString() =>
        $"writes={WriteCount} bytes={BytesWritten} flushes={FlushCount} tokens={TokenCount} fragments={FragmentCount}";
}

/// <summary>
/// Thread-local render stats provider. Moved to Core so RenderPlan (also in Core)
/// can collect stats without a circular dependency on BareMetalWeb.Rendering.
/// </summary>
public static class RenderStatsProvider
{
    [ThreadStatic] private static RenderStats t_stats;

    /// <summary>Returns a ref to the thread-local render stats for the current render cycle.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ref RenderStats GetStats() => ref t_stats;

    /// <summary>Resets the thread-local stats to zero. Called at the start of each render.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Reset() => t_stats = default;
}
