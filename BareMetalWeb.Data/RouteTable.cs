using System;
using System.Runtime.CompilerServices;
using BareMetalWeb.Core.Delegates;

namespace BareMetalWeb.Data;

/// <summary>
/// Verb/action ordinals for entity API routes.
/// Combined with EntityId to form a flat dispatch index: (entityId &lt;&lt; VerbBits) | verb.
/// </summary>
public enum ApiVerb : byte
{
    List           = 0,
    Create         = 1,
    Import         = 2,
    Get            = 3,
    Update         = 4,
    Patch          = 5,
    Delete         = 6,
    FileGet        = 7,
    Command        = 8,
    AttachList     = 9,
    AttachAdd      = 10,
    CommentList    = 11,
    CommentAdd     = 12,
    RelatedChain   = 13,
    GlobalSearch   = 14,
    // room for 1 more before hitting 16 (4 bits)
}

/// <summary>
/// Flat dispatch table for entity API routes.
/// Indexed by (entityId &lt;&lt; VerbBits) | verbOrdinal for O(1) handler lookup.
/// Immutable after construction — safe for concurrent reads without locking.
/// </summary>
public sealed class RouteTable
{
    public const int VerbBits = 4;
    public const int VerbCount = 1 << VerbBits; // 16

    private readonly RouteHandlerDelegate?[] _handlers;
    public readonly int EntityCount;

    public RouteTable(int entityCount)
    {
        EntityCount = entityCount;
        _handlers = new RouteHandlerDelegate?[entityCount * VerbCount];
    }

    /// <summary>
    /// Sets a handler for a specific entity + verb combination.
    /// Called during compilation only (before the table is published).
    /// </summary>
    public void Set(int entityId, ApiVerb verb, RouteHandlerDelegate handler)
    {
        _handlers[(entityId << VerbBits) | (int)verb] = handler;
    }

    /// <summary>
    /// Resolves a handler for a specific entity + verb combination.
    /// Returns null if no handler is registered.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public RouteHandlerDelegate? Resolve(int entityId, ApiVerb verb)
    {
        int index = (entityId << VerbBits) | (int)verb;
        return (uint)index < (uint)_handlers.Length ? _handlers[index] : null;
    }
}
