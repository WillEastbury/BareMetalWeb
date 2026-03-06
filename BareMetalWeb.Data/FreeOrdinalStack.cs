using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// A pool of freed column-array ordinals.
/// <para>
/// Deleted rows push their ordinal here; new inserts pop from here before
/// allocating a fresh high-water-mark slot.  This keeps column arrays dense
/// and avoids unbounded array growth under steady-state churn.
/// </para>
/// <para>Not thread-safe — callers are responsible for external synchronisation.</para>
/// </summary>
internal sealed class FreeOrdinalStack
{
    private uint[] _buf;
    private int _top;

    public FreeOrdinalStack(int initialCapacity = 16)
    {
        _buf = new uint[Math.Max(initialCapacity, 16)];
    }

    /// <summary>Number of ordinals currently on the stack.</summary>
    public int Count => _top;

    /// <summary>Pushes a freed ordinal onto the stack for later reuse.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Push(uint ordinal)
    {
        if (_top == _buf.Length)
            Array.Resize(ref _buf, _buf.Length * 2);
        _buf[_top++] = ordinal;
    }

    /// <summary>
    /// Pops the most-recently-freed ordinal.
    /// Returns <c>false</c> (and <paramref name="ordinal"/> = 0) when the stack is empty.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryPop(out uint ordinal)
    {
        if (_top == 0) { ordinal = 0; return false; }
        ordinal = _buf[--_top];
        return true;
    }

    /// <summary>Removes all entries from the stack without releasing the backing array.</summary>
    public void Clear() => _top = 0;

    /// <summary>Read-only view of the stack contents (index 0 = bottom, top-1 = top).</summary>
    public ReadOnlySpan<uint> AsSpan() => _buf.AsSpan(0, _top);
}
