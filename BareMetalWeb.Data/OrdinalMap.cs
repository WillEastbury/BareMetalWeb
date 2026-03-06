using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// Stable <c>uint</c> id → <c>uint</c> ordinal mapping backed by a <see cref="FreeOrdinalStack"/>.
/// <para>
/// Each live row has a unique ordinal in <c>[0, HighWater)</c>.  When a row is deleted
/// its ordinal is pushed onto the <see cref="FreeOrdinalStack"/>; the next insert pops
/// that ordinal rather than allocating a new one, keeping column arrays dense.
/// </para>
/// <para>
/// Indexes always reference IDs; ordinals are a private layout detail of
/// <see cref="ColumnarStore"/>.
/// </para>
/// <para>Not thread-safe — callers are responsible for external synchronisation.</para>
/// </summary>
internal sealed class OrdinalMap
{
    private readonly Dictionary<uint, uint> _idToOrdinal;
    private uint[] _ordinalToId;
    private uint _highWater;
    private readonly FreeOrdinalStack _free;

    /// <summary>Number of live (non-deleted) rows.</summary>
    public int Count => _idToOrdinal.Count;

    /// <summary>
    /// One past the highest ordinal ever assigned.
    /// Column arrays must be at least this long; scan loops run over <c>[0, HighWater)</c>.
    /// </summary>
    public uint HighWater => _highWater;

    /// <summary>Number of ordinals available for reuse without growing the arrays.</summary>
    public int FreeCount => _free.Count;

    /// <summary>Exposes the underlying free stack (e.g. for testing or diagnostics).</summary>
    public FreeOrdinalStack FreeStack => _free;

    public OrdinalMap(int initialCapacity = 64)
    {
        _idToOrdinal    = new Dictionary<uint, uint>(initialCapacity);
        _ordinalToId    = new uint[Math.Max(initialCapacity, 64)];
        _free           = new FreeOrdinalStack();
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns <c>true</c> and the existing ordinal when <paramref name="id"/> is live.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryGetOrdinal(uint id, out uint ordinal)
        => _idToOrdinal.TryGetValue(id, out ordinal);

    /// <summary>
    /// Returns the id stored at <paramref name="ordinal"/>,
    /// or <c>0</c> if the slot is free or out of range.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint GetId(uint ordinal)
        => ordinal < _highWater ? _ordinalToId[ordinal] : 0u;

    /// <summary>Enumerates all live (id, ordinal) pairs.</summary>
    public IEnumerable<KeyValuePair<uint, uint>> Pairs => _idToOrdinal;

    // ── Mutation ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Assigns (or returns the existing) ordinal for <paramref name="id"/>.
    /// <list type="bullet">
    ///   <item><description>
    ///     If <paramref name="id"/> already has an ordinal: returns <c>(existing, false)</c>.
    ///   </description></item>
    ///   <item><description>
    ///     Otherwise a freed ordinal is popped from the <see cref="FreeOrdinalStack"/> (if any)
    ///     or the high-water mark is incremented: returns <c>(new_ordinal, true)</c>.
    ///   </description></item>
    /// </list>
    /// </summary>
    public (uint Ordinal, bool IsNew) Upsert(uint id)
    {
        if (_idToOrdinal.TryGetValue(id, out var existing))
            return (existing, false);

        // Reuse a freed ordinal, or allocate the next high-water slot.
        uint ordinal = _free.TryPop(out var freed) ? freed : _highWater++;

        EnsureCapacity(ordinal + 1);
        _idToOrdinal[id]   = ordinal;
        _ordinalToId[ordinal] = id;
        return (ordinal, true);
    }

    /// <summary>
    /// Removes the id → ordinal mapping and pushes the freed ordinal onto the
    /// <see cref="FreeOrdinalStack"/> for reuse.
    /// Returns <c>false</c> when <paramref name="id"/> was not found.
    /// </summary>
    public bool Remove(uint id, out uint ordinal)
    {
        if (!_idToOrdinal.Remove(id, out ordinal))
            return false;

        _ordinalToId[ordinal] = 0; // tombstone: GetId will return 0 for freed slots
        _free.Push(ordinal);
        return true;
    }

    /// <summary>Resets the map to an empty state, preserving the backing arrays.</summary>
    public void Clear()
    {
        _idToOrdinal.Clear();
        if (_highWater > 0)
            Array.Clear(_ordinalToId, 0, (int)_highWater);
        _highWater = 0;
        _free.Clear();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void EnsureCapacity(uint needed)
    {
        if (needed > (uint)_ordinalToId.Length)
        {
            var newLen = (int)Math.Max(needed, (uint)_ordinalToId.Length * 2u);
            Array.Resize(ref _ordinalToId, newLen);
        }
    }
}
