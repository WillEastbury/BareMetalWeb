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
    private static VectorIndexManager? _manager;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };

    /// <summary>Initialize with the vector index manager.</summary>
    public static void Initialize(VectorIndexManager manager) => _manager = manager;

    /// <summary>POST /api/vector/search</summary>
    public static async ValueTask SearchHandler(HttpContext context)
    {
        if (_manager == null)
        {
            context.Response.StatusCode = 503;
            await context.Response.WriteAsync("{\"error\":\"vector index not initialized\"}");
            return;
        }

        using var doc = await JsonDocument.ParseAsync(context.Request.Body);
        var root = doc.RootElement;

        var entity = root.GetProperty("entity").GetString() ?? "";
        var field = root.GetProperty("field").GetString() ?? "";
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

        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body, new
        {
            entity,
            field,
            count = results.Count,
            results = results.Select(r => new { id = r.Id, distance = r.Distance }),
        }, JsonOpts);
    }

    /// <summary>POST /api/vector/upsert</summary>
    public static async ValueTask UpsertHandler(HttpContext context)
    {
        if (_manager == null) { context.Response.StatusCode = 503; return; }

        using var doc = await JsonDocument.ParseAsync(context.Request.Body);
        var root = doc.RootElement;

        var entity = root.GetProperty("entity").GetString() ?? "";
        var field = root.GetProperty("field").GetString() ?? "";
        var objectId = root.GetProperty("objectId").GetUInt32();

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
    public static async ValueTask DeleteHandler(HttpContext context)
    {
        if (_manager == null) { context.Response.StatusCode = 503; return; }

        using var doc = await JsonDocument.ParseAsync(context.Request.Body);
        var root = doc.RootElement;

        var entity = root.GetProperty("entity").GetString() ?? "";
        var field = root.GetProperty("field").GetString() ?? "";
        var objectId = root.GetProperty("objectId").GetUInt32();

        _manager.Delete(entity, field, objectId);
        context.Response.StatusCode = 204;
    }

    /// <summary>GET /api/vector/indexes</summary>
    public static async ValueTask ListIndexesHandler(HttpContext context)
    {
        if (_manager == null) { context.Response.StatusCode = 503; return; }

        var defs = _manager.GetDefinitions().Select(d => new
        {
            entity = d.EntityType,
            field = d.Field,
            dimension = d.Def.Dimension,
            metric = d.Def.Metric.ToString(),
            maxDegree = d.Def.MaxDegree,
            count = _manager.Count(d.EntityType, d.Field),
        });

        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body, defs, JsonOpts);
    }

    /// <summary>POST /api/vector/register — register a new vector index.</summary>
    public static async ValueTask RegisterHandler(HttpContext context)
    {
        if (_manager == null) { context.Response.StatusCode = 503; return; }

        using var doc = await JsonDocument.ParseAsync(context.Request.Body);
        var root = doc.RootElement;

        var entity = root.GetProperty("entity").GetString() ?? "";
        var field = root.GetProperty("field").GetString() ?? "";
        var dimension = root.GetProperty("dimension").GetUInt16();
        var metric = root.TryGetProperty("metric", out var mEl)
            ? Enum.TryParse<DistanceMetric>(mEl.GetString(), true, out var m) ? m : DistanceMetric.Cosine
            : DistanceMetric.Cosine;
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
