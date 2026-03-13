using BareMetalWeb.Core;
using System.Text.Json;
using BareMetalWeb.Data;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// REST API for vector index operations:
/// POST /api/vector/upsert — upsert an embedding
/// POST /api/vector/search — ANN search
/// POST /api/vector/delete — remove a vector
/// GET  /api/vector/indexes — list registered indexes
/// POST /api/vector/register — register a new index definition
/// </summary>
public static class VectorApiHandlers
{
    private static readonly Dictionary<string, DistanceMetric> DistanceMetricLookup = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Cosine"] = DistanceMetric.Cosine,
        ["DotProduct"] = DistanceMetric.DotProduct,
        ["Euclidean"] = DistanceMetric.Euclidean,
    };

    private static VectorIndexManager? _manager;

    /// <summary>Initialize with the vector index manager.</summary>
    public static void Initialize(VectorIndexManager manager) => _manager = manager;

    /// <summary>POST /api/vector/search</summary>
    public static async ValueTask SearchHandler(BmwContext context)
    {
        if (_manager == null)
        {
            context.Response.StatusCode = 503;
            await context.Response.WriteAsync("{\"error\":\"vector index not initialized\"}");
            return;
        }

        using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body);
        var root = doc.RootElement;

        var entity = root.GetProperty("entity").GetString() ?? "";
        var field = root.GetProperty("field").GetString() ?? "";

        if (!await HasEntityPermissionAsync(context, entity, context.RequestAborted))
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsync("{\"error\":\"Access denied.\"}");
            return;
        }
        var top = root.TryGetProperty("top", out var topEl) ? topEl.GetInt32() : 10;

        float[] vector;
        if (root.TryGetProperty("vector", out var vecEl) && vecEl.ValueKind == JsonValueKind.Array)
        {
            vector = new float[vecEl.GetArrayLength()];
            int i = 0;
            foreach (var v in vecEl.EnumerateArray())
                vector[i++] = v.GetSingle();
        }
        else
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("{\"error\":\"vector array required\"}");
            return;
        }

        var results = _manager.Search(entity, field, vector, top);

        var projectedResults = new List<Dictionary<string, object?>>(results.Count);
        foreach (var r in results)
            projectedResults.Add(new Dictionary<string, object?> { ["id"] = r.Id, ["distance"] = r.Distance });
        await JsonWriterHelper.WriteResponseAsync(context.Response, new Dictionary<string, object?>
        {
            ["entity"] = entity,
            ["field"] = field,
            ["count"] = results.Count,
            ["results"] = projectedResults,
        });
    }

    /// <summary>POST /api/vector/upsert</summary>
    public static async ValueTask UpsertHandler(BmwContext context)
    {
        if (_manager == null) { context.Response.StatusCode = 503; return; }

        using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body);
        var root = doc.RootElement;

        var entity = root.GetProperty("entity").GetString() ?? "";
        var field = root.GetProperty("field").GetString() ?? "";
        var objectId = root.GetProperty("objectId").GetUInt32();

        if (!await HasEntityPermissionAsync(context, entity, context.RequestAborted))
        {
            context.Response.StatusCode = 403;
            return;
        }

        float[] embedding;
        if (root.TryGetProperty("embedding", out var embEl) && embEl.ValueKind == JsonValueKind.Array)
        {
            embedding = new float[embEl.GetArrayLength()];
            int i = 0;
            foreach (var v in embEl.EnumerateArray())
                embedding[i++] = v.GetSingle();
        }
        else
        {
            context.Response.StatusCode = 400;
            return;
        }

        _manager.Upsert(entity, field, objectId, embedding);
        context.Response.StatusCode = 204;
    }

    /// <summary>POST /api/vector/delete</summary>
    public static async ValueTask DeleteHandler(BmwContext context)
    {
        if (_manager == null) { context.Response.StatusCode = 503; return; }

        using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body);
        var root = doc.RootElement;

        var entity = root.GetProperty("entity").GetString() ?? "";
        var field = root.GetProperty("field").GetString() ?? "";
        var objectId = root.GetProperty("objectId").GetUInt32();

        if (!await HasEntityPermissionAsync(context, entity, context.RequestAborted))
        {
            context.Response.StatusCode = 403;
            return;
        }

        _manager.Delete(entity, field, objectId);
        context.Response.StatusCode = 204;
    }

    /// <summary>GET /api/vector/indexes</summary>
    public static async ValueTask ListIndexesHandler(BmwContext context)
    {
        if (_manager == null) { context.Response.StatusCode = 503; return; }

        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted);
        if (user == null)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("{\"error\":\"Authentication required.\"}");
            return;
        }

        var rawDefs = _manager.GetDefinitions();
        var defs = new List<Dictionary<string, object?>>();
        foreach (var d in rawDefs)
        {
            defs.Add(new Dictionary<string, object?>
            {
                ["entity"] = d.EntityType,
                ["field"] = d.Field,
                ["dimension"] = d.Def.Dimension,
                ["metric"] = d.Def.Metric.ToString(),
                ["maxDegree"] = d.Def.MaxDegree,
                ["count"] = _manager.Count(d.EntityType, d.Field),
            });
        }

        await JsonWriterHelper.WriteResponseAsync(context.Response, defs);
    }

    private static async ValueTask<bool> HasEntityPermissionAsync(BmwContext context, string entitySlug, CancellationToken ct)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta))
            return true;

        var permissionsNeeded = meta.Permissions?.Trim();
        if (string.IsNullOrWhiteSpace(permissionsNeeded) ||
            string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
            return true;

        var user = await UserAuth.GetRequestUserAsync(context, ct);
        if (user == null)
            return string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase);

        if (string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase))
            return false;

        var userPerms = new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase);
        var altLookup = userPerms.GetAlternateLookup<ReadOnlySpan<char>>();
        var remaining = permissionsNeeded.AsSpan();
        while (remaining.Length > 0)
        {
            int idx = remaining.IndexOf(',');
            ReadOnlySpan<char> segment;
            if (idx < 0) { segment = remaining; remaining = default; }
            else { segment = remaining[..idx]; remaining = remaining[(idx + 1)..]; }
            var trimmed = segment.Trim();
            if (trimmed.IsEmpty) continue;
            if (!altLookup.Contains(trimmed))
                return false;
        }
        return true;
    }

    /// <summary>POST /api/vector/register — register a new vector index.</summary>
    public static async ValueTask RegisterHandler(BmwContext context)
    {
        if (_manager == null) { context.Response.StatusCode = 503; return; }

        using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body);
        var root = doc.RootElement;

        var entity = root.GetProperty("entity").GetString() ?? "";
        var field = root.GetProperty("field").GetString() ?? "";
        var dimension = root.GetProperty("dimension").GetUInt16();
        var metric = root.TryGetProperty("metric", out var mEl) && mEl.GetString() is { } ms
            && DistanceMetricLookup.TryGetValue(ms, out var m) ? m : DistanceMetric.Cosine;
        var maxDegree = root.TryGetProperty("maxDegree", out var mdEl) ? mdEl.GetInt32() : 32;

        var def = new VectorIndexDefinition
        {
            Dimension = dimension,
            Metric = metric,
            MaxDegree = maxDegree,
        };

        _manager.RegisterIndex(entity, field, def);
        context.Response.StatusCode = 201;
    }
}
