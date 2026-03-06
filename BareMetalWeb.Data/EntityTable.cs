using System;
using System.Runtime.CompilerServices;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Dense struct-of-arrays table for entity metadata, indexed by contiguous EntityId (0..Count-1).
/// Immutable after construction — safe for concurrent reads without locking.
/// </summary>
public sealed class EntityTable
{
    public readonly int Count;
    public readonly string[] Names;
    public readonly string[] Slugs;
    public readonly int[] FieldStart;   // first global FieldId for this entity
    public readonly int[] FieldCount;   // number of fields for this entity
    public readonly bool[] ShowOnNav;
    public readonly int[] NavOrder;
    public readonly AutoIdStrategy[] IdStrategies;
    public readonly DataEntityHandlers[] Handlers;
    /// <summary>Original DataEntityMetadata references indexed by EntityId, for handlers that need full metadata.</summary>
    public readonly DataEntityMetadata[] Metadata;

    // slug → EntityId resolver (sorted slugs + binary search)
    private readonly string[] _sortedSlugs;
    private readonly int[] _sortedEntityIds;

    public EntityTable(
        string[] names,
        string[] slugs,
        int[] fieldStart,
        int[] fieldCount,
        bool[] showOnNav,
        int[] navOrder,
        AutoIdStrategy[] idStrategies,
        DataEntityHandlers[] handlers,
        string[] sortedSlugs,
        int[] sortedEntityIds,
        DataEntityMetadata[] metadata)
    {
        Count = names.Length;
        Names = names;
        Slugs = slugs;
        FieldStart = fieldStart;
        FieldCount = fieldCount;
        ShowOnNav = showOnNav;
        NavOrder = navOrder;
        IdStrategies = idStrategies;
        Handlers = handlers;
        _sortedSlugs = sortedSlugs;
        _sortedEntityIds = sortedEntityIds;
        Metadata = metadata;
    }

    /// <summary>
    /// Resolves an entity slug to its EntityId. Returns -1 if not found.
    /// O(log N) via binary search on sorted slug array.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int ResolveSlug(string slug)
    {
        int idx = Array.BinarySearch(_sortedSlugs, slug, StringComparer.OrdinalIgnoreCase);
        return idx >= 0 ? _sortedEntityIds[idx] : -1;
    }

    /// <summary>
    /// Resolves an entity slug to its EntityId. Returns false if not found.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryResolveSlug(string slug, out int entityId)
    {
        entityId = ResolveSlug(slug);
        return entityId >= 0;
    }
}
