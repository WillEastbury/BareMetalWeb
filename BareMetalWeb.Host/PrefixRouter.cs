using System.Runtime.CompilerServices;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Delegates;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Host;

/// <summary>
/// Classifies an API entity route into a dense integer for array-indexed dispatch.
/// </summary>
internal enum ApiRouteKind : byte
{
    List,               // GET    /api/{type}
    Create,             // POST   /api/{type}
    Import,             // POST   /api/{type}/import
    Get,                // GET    /api/{type}/{id}
    Update,             // PUT    /api/{type}/{id}
    Patch,              // PATCH  /api/{type}/{id}
    Delete,             // DELETE /api/{type}/{id}
    FileGet,            // GET    /api/{type}/{id}/files/{field}
    Command,            // POST   /api/{type}/{id}/_command/{command}
    ListAttachments,    // GET    /api/{type}/{id}/_attachments
    AddAttachment,      // POST   /api/{type}/{id}/_attachments
    ListComments,       // GET    /api/{type}/{id}/_comments
    AddComment,         // POST   /api/{type}/{id}/_comments
    RelatedChain,       // GET    /api/{type}/{id}/_related-chain
    _Count              // sentinel — must be last
}

/// <summary>
/// High-performance three-stage router for <c>/api/{entity}</c> routes.
/// <list type="number">
///   <item>Prefix classify — <c>path.StartsWith("/api/")</c></item>
///   <item>Entity resolve — slice slug, hash-probe <see cref="EntityRouteTable"/></item>
///   <item>Verb+suffix dispatch — classify remaining path → handler array index</item>
/// </list>
/// </summary>
/// <remarks>
/// <para>
/// The hot path is allocation-free: entity slug resolved to a pre-interned string,
/// route parameters set as direct fields on <see cref="BmwContext"/>,
/// handler invoked via array indexing.
/// </para>
/// <para>
/// Only matches routes for entities registered in <see cref="DataScaffold.Entities"/>.
/// System prefixes (<c>_binary</c>, <c>_lookup</c>, <c>metadata</c>) are not in the
/// entity table and fall through to the jump table / pattern matching.
/// </para>
/// </remarks>
public sealed class PrefixRouter
{
    private readonly EntityRouteTable _entityTable = new();
    private readonly RouteHandlerData[] _handlers = new RouteHandlerData[(int)ApiRouteKind._Count];
    private PageInfo _apiPageInfo = null!;
    private int _version;

    /// <summary>Current build version (incremented on each <see cref="Build"/>).</summary>
    public int Version => _version;

    /// <summary>Number of entities in the route table.</summary>
    public int EntityCount => _entityTable.Count;

    /// <summary>
    /// Build the prefix router from the registered routes and entity metadata.
    /// Call after all routes are registered and entities are scaffolded.
    /// </summary>
    public void Build(Dictionary<string, RouteHandlerData> routes, IBufferedLogger? logger = null)
    {
        // Collect entity slugs from DataScaffold
        var entities = DataScaffold.Entities;
        var slugs = new List<string>(entities.Count);
        foreach (var meta in entities)
        {
            if (!string.IsNullOrEmpty(meta.Slug))
                slugs.Add(meta.Slug);
        }

        _entityTable.Build(slugs);

        // Extract handler delegates from known route patterns
        TryExtract(routes, "GET /api/{type}", ApiRouteKind.List);
        TryExtract(routes, "POST /api/{type}", ApiRouteKind.Create);
        TryExtract(routes, "POST /api/{type}/import", ApiRouteKind.Import);
        TryExtract(routes, "GET /api/{type}/{id}", ApiRouteKind.Get);
        TryExtract(routes, "PUT /api/{type}/{id}", ApiRouteKind.Update);
        TryExtract(routes, "PATCH /api/{type}/{id}", ApiRouteKind.Patch);
        TryExtract(routes, "DELETE /api/{type}/{id}", ApiRouteKind.Delete);
        TryExtract(routes, "GET /api/{type}/{id}/files/{field}", ApiRouteKind.FileGet);
        TryExtract(routes, "POST /api/{type}/{id}/_command/{command}", ApiRouteKind.Command);
        TryExtract(routes, "GET /api/{type}/{id}/_attachments", ApiRouteKind.ListAttachments);
        TryExtract(routes, "POST /api/{type}/{id}/_attachments", ApiRouteKind.AddAttachment);
        TryExtract(routes, "GET /api/{type}/{id}/_comments", ApiRouteKind.ListComments);
        TryExtract(routes, "POST /api/{type}/{id}/_comments", ApiRouteKind.AddComment);
        TryExtract(routes, "GET /api/{type}/{id}/_related-chain", ApiRouteKind.RelatedChain);

        // Build a shared PageInfo for auth checks (all API entity routes use "Authenticated")
        if (routes.TryGetValue("GET /api/{type}", out var sample) && sample.PageInfo != null)
        {
            _apiPageInfo = sample.PageInfo;
        }
        else
        {
            // Fallback: build a minimal PageInfo
            _apiPageInfo = new PageInfo(
                new PageMetaData(null!, 200, "Authenticated", false, 0),
                new PageContext(Array.Empty<string>(), Array.Empty<string>()));
        }

        _version++;

        logger?.LogInfo($"PrefixRouter built: {slugs.Count} entities, " +
                        $"{_handlers.Count(h => h.Handler != null)} route kinds");
    }

    /// <summary>
    /// Attempt to match and dispatch a request via the three-stage pipeline.
    /// Returns true if the route was matched (caller should execute the handler).
    /// Sets <see cref="BmwContext.EntitySlug"/>, <see cref="BmwContext.EntityId"/>,
    /// and <see cref="BmwContext.PageInfo"/> on successful match.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryMatch(BmwContext context, out RouteHandlerData data)
    {
        var path = context.Request.Path.AsSpan();

        // Stage 1: Prefix classify
        if (path.StartsWith("/api/".AsSpan(), StringComparison.Ordinal))
        {
            return TryMatchApi(context, path.Slice(5), context.Request.Method, out data);
        }

        data = default;
        return false;
    }

    /// <summary>
    /// Dispatch an <c>/api/...</c> route. <paramref name="remainder"/> is the
    /// path after <c>/api/</c> (e.g. <c>users/42/_attachments</c>).
    /// </summary>
    private bool TryMatchApi(BmwContext context, ReadOnlySpan<char> remainder,
                             string method, out RouteHandlerData data)
    {
        data = default;

        // Stage 2: Extract entity slug (first segment after /api/)
        int slash = remainder.IndexOf('/');
        ReadOnlySpan<char> entitySlug;
        ReadOnlySpan<char> rest;

        if (slash < 0)
        {
            entitySlug = remainder;
            rest = ReadOnlySpan<char>.Empty;
        }
        else
        {
            entitySlug = remainder[..slash];
            rest = remainder[(slash + 1)..];
        }

        if (entitySlug.IsEmpty) return false;

        // Resolve entity via hash table
        if (!_entityTable.TryResolve(entitySlug, out var resolvedSlug, out var entityOrdinal))
            return false;

        // Stage 3: Classify verb + remaining path suffix
        var kind = ClassifyRoute(method, rest,
                                 out var idSpan, out var extraSpan, out var extraKey);
        if (kind < 0) return false;

        ref var handler = ref _handlers[kind];
        if (handler.Handler == null) return false;

        // Set fast-path fields on BmwContext (zero allocation for entity slug)
        context.EntitySlug = resolvedSlug;
        context.EntityOrdinal = entityOrdinal;
        if (!idSpan.IsEmpty)
            context.EntityId = idSpan.ToString();
        if (!extraSpan.IsEmpty)
        {
            context.RouteExtra = extraSpan.ToString();
            context.RouteExtraKey = extraKey;
        }

        // Set PageInfo for auth check
        context.PageInfo = _apiPageInfo;
        context.SetPageInfo(_apiPageInfo);

        data = handler;
        return true;
    }

    /// <summary>
    /// Classify an API route's remaining path (after <c>/api/{entity}/</c>) and
    /// HTTP method into an <see cref="ApiRouteKind"/> ordinal.
    /// Returns -1 for unknown combinations (fall through to pattern matching).
    /// </summary>
    internal static int ClassifyRoute(string method, ReadOnlySpan<char> remainder,
        out ReadOnlySpan<char> id, out ReadOnlySpan<char> extra, out string? extraKey)
    {
        id = default;
        extra = default;
        extraKey = null;

        // /api/{entity} — no id segment
        if (remainder.IsEmpty)
        {
            if (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.List;
            if (string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.Create;
            return -1;
        }

        // /api/{entity}/import
        if (remainder.Equals("import".AsSpan(), StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.Import;
            return -1;
        }

        // Extract {id} segment
        int slash = remainder.IndexOf('/');
        if (slash < 0)
        {
            // /api/{entity}/{id} — just id, no suffix
            id = remainder;
            if (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.Get;
            if (string.Equals(method, "PUT", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.Update;
            if (string.Equals(method, "PATCH", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.Patch;
            if (string.Equals(method, "DELETE", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.Delete;
            return -1;
        }

        id = remainder[..slash];
        var suffix = remainder[(slash + 1)..];

        // Known suffixes (underscore-prefixed system routes)
        if (suffix.Equals("_attachments".AsSpan(), StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.ListAttachments;
            if (string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.AddAttachment;
            return -1;
        }

        if (suffix.Equals("_comments".AsSpan(), StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.ListComments;
            if (string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.AddComment;
            return -1;
        }

        if (suffix.Equals("_related-chain".AsSpan(), StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.RelatedChain;
            return -1;
        }

        // /api/{entity}/{id}/files/{field}
        if (suffix.StartsWith("files/".AsSpan(), StringComparison.OrdinalIgnoreCase) && suffix.Length > 6)
        {
            extra = suffix.Slice(6);
            extraKey = "field";
            if (string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.FileGet;
            return -1;
        }

        // /api/{entity}/{id}/_command/{command}
        if (suffix.StartsWith("_command/".AsSpan(), StringComparison.OrdinalIgnoreCase) && suffix.Length > 9)
        {
            extra = suffix.Slice(9);
            extraKey = "command";
            if (string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase))
                return (int)ApiRouteKind.Command;
            return -1;
        }

        return -1; // Unknown suffix — fall through to pattern matching
    }

    private void TryExtract(Dictionary<string, RouteHandlerData> routes,
                            string routeKey, ApiRouteKind kind)
    {
        if (routes.TryGetValue(routeKey, out var data))
            _handlers[(int)kind] = data;
    }
}
