using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// Tracks the active row indices in a batch of up to <see cref="BatchSize"/> rows.
///
/// <para>
/// Selection vectors are the core mechanism of vectorised execution in the BMW View Engine.
/// Rather than copying matching rows into a new collection, predicates modify the selection
/// vector in place — only the <em>indices</em> of passing rows are tracked. This keeps the
/// filter, join, and projection pipelines allocation-free in the hot path.
/// </para>
///
/// <para>
/// Typical pipeline (per 1024-row batch):
/// <list type="number">
///   <item>Initialise: fill all <see cref="BatchSize"/> indices 0..N-1 → <see cref="Count"/> = N.</item>
///   <item>Filter: iterate <see cref="Count"/> indices; keep only rows that pass → update <see cref="Count"/>.</item>
///   <item>Join: for each active row, look up the joined row; mask out non-matches for INNER joins.</item>
///   <item>Project: iterate <see cref="Count"/> indices; extract fields into output span.</item>
/// </list>
/// </para>
/// </summary>
public struct SelectionVector
{
    /// <summary>Maximum number of rows per batch.</summary>
    public const int BatchSize = 1024;

    /// <summary>Row indices of active rows in the current batch.</summary>
    public int[] RowIndices;

    /// <summary>Number of active (selected) rows. Always ≤ <see cref="BatchSize"/>.</summary>
    public int Count;

    // ── Construction ──────────────────────────────────────────────────────────

    /// <summary>Allocates a new selection vector with the given capacity (typically <see cref="BatchSize"/>).</summary>
    public SelectionVector(int capacity)
    {
        RowIndices = new int[capacity];
        Count      = 0;
    }

    // ── Initialisation ────────────────────────────────────────────────────────

    /// <summary>
    /// Fills the selection vector with indices [<paramref name="baseRow"/> .. <paramref name="baseRow"/> + <paramref name="count"/> − 1].
    /// Called once per batch at the start of the root scan.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void InitRange(int baseRow, int count)
    {
        Count = count;
        for (int i = 0; i < count; i++)
            RowIndices[i] = baseRow + i;
    }

    // ── Filtering ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Removes rows that fail <paramref name="predicate"/> from the active set.
    /// Operates in-place on <see cref="RowIndices"/>[0..<see cref="Count"/>].
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ApplyPredicate<TRow>(TRow[] rows, Func<TRow, bool> predicate)
    {
        int write = 0;
        for (int i = 0; i < Count; i++)
        {
            int idx = RowIndices[i];
            if (idx < rows.Length && predicate(rows[idx]))
                RowIndices[write++] = idx;
        }
        Count = write;
    }

    // ── Reset ─────────────────────────────────────────────────────────────────

    /// <summary>Clears all selections without reallocating.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Reset() => Count = 0;
}
