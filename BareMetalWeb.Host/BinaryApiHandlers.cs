using System.Buffers;
using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

/// <summary>
/// Binary wire-format API handlers.
/// Serve entities as BSO1 binary payloads — metadata-driven, zero-reflection at request time.
/// JSON fallback at /api/_lookup/ remains for service-to-service callers.
/// </summary>
public static class BinaryApiHandlers
{
    private static MetadataWireSerializer? _serializer;

    /// <summary>Get the serializer instance for use by related handlers.</summary>
    internal static MetadataWireSerializer? GetSerializer() => _serializer;
    private static byte[]? _signingKeyRaw;
    private static IBufferedLogger? _logger;
    private static readonly ConcurrentDictionary<string, MetadataWireSerializer.FieldPlan[]> _plans = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, MetadataWireSerializer.WireSchemaDescriptor> _schemas = new(StringComparer.OrdinalIgnoreCase);

    private const string BinaryContentType = "application/x-bmw-binary";

    /// <summary>
    /// Initialise the binary API subsystem with the shared signing key.
    /// Call once at startup after data store creation.
    /// </summary>
    public static void Initialize(byte[] signingKey, IBufferedLogger? logger = null)
    {
        _signingKeyRaw = (byte[])signingKey.Clone();
        _serializer = new MetadataWireSerializer(signingKey);
        _logger = logger;
    }

    // ────────────── Helpers ──────────────

    private static MetadataWireSerializer.FieldPlan[] GetOrBuildPlan(DataEntityMetadata meta)
    {
        return _plans.GetOrAdd(meta.Slug, _ => BuildPlanFromMetadata(meta));
    }

    /// <summary>Public accessor for GetOrBuildPlan, used by DeltaApiHandlers.</summary>
    internal static MetadataWireSerializer.FieldPlan[] GetOrBuildPlanPublic(DataEntityMetadata meta)
        => GetOrBuildPlan(meta);

    private static MetadataWireSerializer.FieldPlan[] BuildPlanFromMetadata(DataEntityMetadata meta)
    {
        // Build a lookup from metadata fields for getter/setter reuse
        var metaFieldsByName = new Dictionary<string, DataFieldMetadata>(StringComparer.Ordinal);
        foreach (var f in meta.Fields)
            metaFieldsByName[f.Name] = f;

        // Collect ALL public properties on the CLR type — same set the BinaryObjectSerializer uses.
        // Sort by name (Ordinal compare) to match binary serializer member ordering.
        var unsortedProps = meta.Type.GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
        var propsList = new List<System.Reflection.PropertyInfo>(unsortedProps);
        propsList.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));
        var props = propsList.ToArray();

        var descriptors = new List<MetadataWireSerializer.FieldPlanDescriptor>(props.Length);
        foreach (var prop in props)
        {
            if (!prop.CanRead || !prop.CanWrite) continue;

            var (wireType, isNullable, enumUnderlying) = MetadataWireSerializer.ResolveWireType(prop.PropertyType);
            var effectiveType = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType;

            // Reuse pre-compiled delegates from metadata when available
            Func<object, object?> getter;
            Action<object, object?> setter;
            if (metaFieldsByName.TryGetValue(prop.Name, out var fieldMeta))
            {
                getter = fieldMeta.GetValueFn;
                setter = fieldMeta.SetValueFn;
            }
            else
            {
                getter = PropertyAccessorFactory.BuildGetter(prop);
                setter = PropertyAccessorFactory.BuildSetter(prop);
            }

            descriptors.Add(new MetadataWireSerializer.FieldPlanDescriptor
            {
                Name = prop.Name,
                WireType = wireType,
                IsNullable = isNullable,
                Getter = getter,
                Setter = setter,
                ClrType = effectiveType,
                EnumUnderlying = enumUnderlying,
            });
        }

        return MetadataWireSerializer.BuildPlan(meta.Type, descriptors);
    }

    private static MetadataWireSerializer.WireSchemaDescriptor GetOrBuildSchema(DataEntityMetadata meta)
    {
        return _schemas.GetOrAdd(meta.Slug, _ =>
        {
            var plan = GetOrBuildPlan(meta);
            return MetadataWireSerializer.BuildSchemaDescriptor(meta.Slug, 1, plan);
        });
    }

    // ────────────── Route handlers ──────────────

    /// <summary>
    /// GET /api/_binary/_key
    /// Returns the HMAC signing key (base64) for authenticated users.
    /// The client needs this to sign/verify binary payloads.
    /// </summary>
    public static async ValueTask KeyHandler(BmwContext context)
    {
        // Require authentication — only logged-in users get the signing key
        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted);
        if (user == null)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        if (_signingKeyRaw == null)
        {
            await WriteError(context, (500, "Binary API not initialized."));
            return;
        }

        context.Response.ContentType = "text/plain";
        await context.Response.WriteAsync(Convert.ToBase64String(_signingKeyRaw), context.RequestAborted);
    }

    /// <summary>
    /// GET /api/_binary/{type}/_schema
    /// Returns JSON schema descriptor so the JS client can build its own field plan.
    /// </summary>
    public static async ValueTask SchemaHandler(BmwContext context)
    {
        var (meta, _, error) = await ValidateAsync(context);
        if (meta == null) { await WriteError(context, error!.Value); return; }

        var schema = GetOrBuildSchema(meta);
        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body, schema, JsonOpts, context.RequestAborted);
    }

    /// <summary>
    /// GET /api/_binary/{type}
    /// Returns entity list in binary or JSON based on Accept header.
    /// </summary>
    public static async ValueTask ListHandler(BmwContext context)
    {
        var (meta, _, error) = await ValidateAsync(context);
        if (meta == null) { await WriteError(context, error!.Value); return; }
        if (_serializer == null) { await WriteError(context, (500, "Binary API not initialized.")); return; }

        try
        {
            var queryDef = LookupApiHandlers.BuildQueryFromRequest(context, meta);
            var entities = await meta.Handlers.QueryAsync(queryDef, context.RequestAborted);
            var list = new List<object>();
            foreach (var e in entities)
                list.Add((object)e);
            var plan = GetOrBuildPlan(meta);
            await WriteListResponse(context, list, plan);
        }
        catch (Exception ex)
        {
            _logger?.LogError("BinaryAPI|list", ex);
            await WriteError(context, (500, "Error querying entities."));
        }
    }

    /// <summary>
    /// GET /api/_binary/{type}/_raw
    /// Returns Brotli-compressed ordinal array data — no JSON serialization.
    /// Client decompresses with DecompressionStream, then reads field values by ordinal.
    /// Format: [uint32 rowCount][uint16 fieldCount][rows: [field0_len][field0_bytes]...]
    /// </summary>
    public static async ValueTask RawListHandler(BmwContext context)
    {
        var (meta, _, error) = await ValidateAsync(context);
        if (meta == null) { await WriteError(context, error!.Value); return; }

        try
        {
            var queryDef = LookupApiHandlers.BuildQueryFromRequest(context, meta);
            var entities = await meta.Handlers.QueryAsync(queryDef, context.RequestAborted);
            var list = new List<object>();
            foreach (var e in entities)
                list.Add((object)e);
            var plan = GetOrBuildPlan(meta);

            // Build raw ordinal array: each row is field values in plan order
            using var ms = new System.IO.MemoryStream();
            using (var bw = new System.IO.BinaryWriter(ms, System.Text.Encoding.UTF8, leaveOpen: true))
            {
                bw.Write((uint)list.Count);
                bw.Write((ushort)plan.Length);

                foreach (var entity in list)
                {
                    foreach (var field in plan)
                    {
                        var val = field.Getter(entity)?.ToString() ?? string.Empty;
                        var bytes = System.Text.Encoding.UTF8.GetBytes(val);
                        bw.Write((ushort)bytes.Length);
                        bw.Write(bytes);
                    }
                }
            }

            // Brotli compress the ordinal data — read from internal buffer to avoid ToArray copy
            var rawBuf = ms.GetBuffer().AsSpan(0, (int)ms.Length);
            using var compressedMs = new System.IO.MemoryStream();
            using (var brotli = new System.IO.Compression.BrotliStream(
                compressedMs, System.IO.Compression.CompressionLevel.Fastest, leaveOpen: true))
            {
                brotli.Write(rawBuf);
            }

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/x-bmw-raw";
            context.Response.Headers["Content-Encoding"] = "br";
            var fieldNamesSb = new System.Text.StringBuilder();
            for (int i = 0; i < plan.Length; i++)
            {
                if (i > 0) fieldNamesSb.Append(',');
                fieldNamesSb.Append(plan[i].Name);
            }
            context.Response.Headers["X-BMW-Fields"] = fieldNamesSb.ToString();
            var compressedLen = (int)compressedMs.Length;
            context.Response.ContentLength = compressedLen;
            await context.Response.Body.WriteAsync(
                compressedMs.GetBuffer().AsMemory(0, compressedLen), context.RequestAborted);
        }
        catch (Exception ex)
        {
            _logger?.LogError("BinaryAPI|raw-list", ex);
            await WriteError(context, (500, "Error querying entities."));
        }
    }

    /// <summary>
    /// GET /api/_binary/{type}/_aggregations
    /// Returns list of AggregationDefinition records for this entity type.
    /// </summary>
    public static async ValueTask AggregationDefsHandler(BmwContext context)
    {
        var (meta, typeSlug, error) = await ValidateAsync(context);
        if (meta == null) { await WriteError(context, error!.Value); return; }

        try
        {
            // Find aggregation definitions where EntityId matches
            var entityDefs = await DataStoreProvider.Current
                .QueryAsync<BareMetalWeb.Runtime.EntityDefinition>(null, context.RequestAborted);
            BareMetalWeb.Runtime.EntityDefinition? entityDef = null;
            foreach (var e in entityDefs)
            {
                if (string.Equals(e.Slug, typeSlug, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(e.Name?.Replace(' ', '-').ToLowerInvariant(), typeSlug, StringComparison.OrdinalIgnoreCase))
                {
                    entityDef = e;
                    break;
                }
            }

            if (entityDef == null)
            {
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("[]", context.RequestAborted);
                return;
            }

            var aggQuery = new QueryDefinition
            {
                Clauses = { new QueryClause { Field = "EntityId", Operator = QueryOperator.Equals, Value = entityDef.EntityId } }
            };
            var aggs = new List<BareMetalWeb.Runtime.AggregationDefinition>();
            foreach (var a in await DataStoreProvider.Current
                .QueryAsync<BareMetalWeb.Runtime.AggregationDefinition>(aggQuery, context.RequestAborted))
                aggs.Add(a);

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await using var writer = new System.Text.Json.Utf8JsonWriter(context.Response.Body);
            writer.WriteStartArray();
            foreach (var agg in aggs)
            {
                writer.WriteStartObject();
                writer.WriteString("name", agg.Name);
                writer.WriteString("groupByFields", agg.GroupByFields);
                writer.WriteString("measures", agg.Measures);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            await writer.FlushAsync(context.RequestAborted);
        }
        catch (Exception ex)
        {
            _logger?.LogError("BinaryAPI|aggregation-defs", ex);
            await WriteError(context, (500, "Error loading aggregation definitions."));
        }
    }

    /// <summary>
    /// GET /api/_binary/{type}/_aggregate?fn=count|sum|avg|min|max|stddev&amp;field=FieldName
    /// Returns aggregation result. Supports multiple aggregates via repeated fn/field params.
    /// </summary>
    public static async ValueTask AggregateHandler(BmwContext context)
    {
        var (meta, _, error) = await ValidateAsync(context);
        if (meta == null) { await WriteError(context, error!.Value); return; }

        var fn = context.HttpRequest.Query["fn"].ToString().ToLowerInvariant();
        var fieldName = context.HttpRequest.Query["field"].ToString();

        if (string.IsNullOrWhiteSpace(fn))
        {
            await WriteError(context, (400, "Aggregate function not specified (use ?fn=count|sum|avg|min|max|stddev)."));
            return;
        }

        var aggFn = fn switch
        {
            "count" => AggregateFunction.Count,
            "sum" => AggregateFunction.Sum,
            "avg" => AggregateFunction.Average,
            "min" => AggregateFunction.Min,
            "max" => AggregateFunction.Max,
            "stddev" => AggregateFunction.StdDev,
            _ => AggregateFunction.None,
        };

        if (aggFn == AggregateFunction.None)
        {
            await WriteError(context, (400, $"Unsupported aggregate function '{fn}'."));
            return;
        }

        if (aggFn != AggregateFunction.Count && string.IsNullOrWhiteSpace(fieldName))
        {
            await WriteError(context, (400, $"Field name required for '{fn}' (use ?field=FieldName)."));
            return;
        }

        try
        {
            var queryDef = LookupApiHandlers.BuildQueryFromRequest(context, meta);
            var result = await AggregationEngine.ComputeAsync(
                meta, queryDef, fieldName, aggFn, context.RequestAborted);

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await using var writer = new System.Text.Json.Utf8JsonWriter(context.Response.Body);
            writer.WriteStartObject();
            writer.WriteString("function", fn);
            writer.WriteString("field", fieldName);
            writer.WriteNumber("count", result.Count);
            if (result.Value is int iv) writer.WriteNumber("result", iv);
            else if (result.Value is long lv) writer.WriteNumber("result", lv);
            else if (result.Value is double dv) writer.WriteNumber("result", dv);
            else if (result.Value is decimal mv) writer.WriteNumber("result", mv);
            else if (result.Value != null) writer.WriteNumber("result", Convert.ToDouble(result.Value));
            else writer.WriteNull("result");
            writer.WriteEndObject();
            await writer.FlushAsync(context.RequestAborted);
        }
        catch (Exception ex)
        {
            _logger?.LogError("BinaryAPI|aggregate", ex);
            await WriteError(context, (500, "Error computing aggregate."));
        }
    }

    /// <summary>
    /// GET /api/_binary/{type}/{id}
    /// Returns a single entity in binary or JSON based on Accept header.
    /// </summary>
    public static async ValueTask GetHandler(BmwContext context)
    {
        var (meta, _, error) = await ValidateAsync(context);
        if (meta == null) { await WriteError(context, error!.Value); return; }
        if (_serializer == null) { await WriteError(context, (500, "Binary API not initialized.")); return; }

        var idStr = GetRouteValue(context, "id");
        if (string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var id))
        {
            await WriteError(context, (400, "Invalid entity ID."));
            return;
        }

        try
        {
            var entity = await meta.Handlers.LoadAsync(id, context.RequestAborted);
            if (entity == null) { await WriteError(context, (404, "Entity not found.")); return; }

            var plan = GetOrBuildPlan(meta);
            await WriteEntityResponse(context, entity, plan);
        }
        catch (Exception ex)
        {
            _logger?.LogError("BinaryAPI|get", ex);
            await WriteError(context, (500, "Error loading entity."));
        }
    }

    /// <summary>
    /// POST /api/_binary/{type}
    /// Accepts binary or JSON entity, saves it, returns in matching format.
    /// </summary>
    public static async ValueTask CreateHandler(BmwContext context)
    {
        if (!HasValidApiContentType(context)) { await WriteError(context, (415, "Unsupported Content-Type.")); return; }
        if (!await CheckBodySizeAsync(context)) return;
        var (meta, _, error) = await ValidateAsync(context);
        if (meta == null) { await WriteError(context, error!.Value); return; }
        if (_serializer == null) { await WriteError(context, (500, "Binary API not initialized.")); return; }

        try
        {
            var plan = GetOrBuildPlan(meta);
            var entity = await ReadEntityFromRequest(context, plan, meta.Type);
            if (entity == null) { await WriteError(context, (400, "Invalid request body.")); return; }

            await DataScaffold.SaveAsync(meta, entity, context.RequestAborted);
            await WriteEntityResponse(context, entity, plan, StatusCodes.Status201Created);
        }
        catch (Exception ex)
        {
            _logger?.LogError("BinaryAPI|create", ex);
            await WriteError(context, (500, "Error creating entity."));
        }
    }

    /// <summary>
    /// PUT /api/_binary/{type}/{id}
    /// Accepts binary or JSON entity, updates it, returns in matching format.
    /// </summary>
    public static async ValueTask UpdateHandler(BmwContext context)
    {
        if (!HasValidApiContentType(context)) { await WriteError(context, (415, "Unsupported Content-Type.")); return; }
        if (!await CheckBodySizeAsync(context)) return;
        var (meta, _, error) = await ValidateAsync(context);
        if (meta == null) { await WriteError(context, error!.Value); return; }
        if (_serializer == null) { await WriteError(context, (500, "Binary API not initialized.")); return; }

        var idStr = GetRouteValue(context, "id");
        if (string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var id))
        {
            await WriteError(context, (400, "Invalid entity ID."));
            return;
        }

        try
        {
            var plan = GetOrBuildPlan(meta);
            var entity = await ReadEntityFromRequest(context, plan, meta.Type);
            if (entity == null) { await WriteError(context, (400, "Invalid request body.")); return; }

            if (entity is BaseDataObject bdo && bdo.Key != id)
                bdo.Key = id;

            await DataScaffold.SaveAsync(meta, entity, context.RequestAborted);
            await WriteEntityResponse(context, entity, plan);
        }
        catch (Exception ex)
        {
            _logger?.LogError("BinaryAPI|update", ex);
            await WriteError(context, (500, "Error updating entity."));
        }
    }

    /// <summary>
    /// DELETE /api/_binary/{type}/{id}
    /// Deletes an entity by key.
    /// </summary>
    public static async ValueTask DeleteHandler(BmwContext context)
    {
        var (meta, _, error) = await ValidateAsync(context);
        if (meta == null) { await WriteError(context, error!.Value); return; }

        var idStr = GetRouteValue(context, "id");
        if (string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var id))
        {
            await WriteError(context, (400, "Invalid entity ID."));
            return;
        }

        try
        {
            await meta.Handlers.DeleteAsync(id, context.RequestAborted);
            context.Response.StatusCode = StatusCodes.Status204NoContent;
        }
        catch (Exception ex)
        {
            _logger?.LogError("BinaryAPI|delete", ex);
            await WriteError(context, (500, "Error deleting entity."));
        }
    }

    // ────────────── Shared utilities ──────────────

    private const long MaxRequestBodyBytes = 10 * 1024 * 1024; // 10 MB

    /// <summary>Reject requests without a recognized Content-Type (CSRF mitigation).</summary>
    internal static bool HasValidApiContentType(BmwContext context)
    {
        var ct = context.HttpRequest.ContentType ?? string.Empty;
        return ct.Contains("application/json", StringComparison.OrdinalIgnoreCase)
            || ct.Contains(BinaryContentType, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Returns 413 if Content-Length exceeds the limit. Returns true if OK.</summary>
    internal static async ValueTask<bool> CheckBodySizeAsync(BmwContext context, long maxBytes = MaxRequestBodyBytes)
    {
        if (context.HttpRequest.ContentLength.HasValue && context.HttpRequest.ContentLength.Value > maxBytes)
        {
            await WriteError(context, (StatusCodes.Status413PayloadTooLarge, $"Request body exceeds {maxBytes / (1024 * 1024)}MB limit."));
            return false;
        }
        return true;
    }

    private static bool WantsJson(BmwContext context)
    {
        var accept = context.HttpRequest.Headers.Accept.ToString();
        // Default to binary; only use JSON if explicitly requested
        return accept.Contains("application/json", StringComparison.OrdinalIgnoreCase);
    }

    private static bool RequestIsJson(BmwContext context)
    {
        var ct = context.HttpRequest.ContentType ?? string.Empty;
        return ct.Contains("application/json", StringComparison.OrdinalIgnoreCase);
    }

    private static async ValueTask WriteEntityResponse(BmwContext context, object entity, MetadataWireSerializer.FieldPlan[] plan, int statusCode = StatusCodes.Status200OK)
    {
        context.Response.StatusCode = statusCode;
        if (WantsJson(context))
        {
            context.Response.ContentType = "application/json";
            await using var writer = new System.Text.Json.Utf8JsonWriter(context.Response.Body);
            MetadataWireSerializer.WriteEntityJson(writer, entity, plan);
            await writer.FlushAsync(context.RequestAborted);
        }
        else
        {
            var payload = _serializer!.Serialize(entity, plan, 1);
            context.Response.ContentType = BinaryContentType;
            context.Response.ContentLength = payload.Length;
            await context.Response.Body.WriteAsync(payload, context.RequestAborted);
        }
    }

    private static async ValueTask WriteListResponse(BmwContext context, List<object> list, MetadataWireSerializer.FieldPlan[] plan)
    {
        if (WantsJson(context))
        {
            context.Response.ContentType = "application/json";
            await using var writer = new System.Text.Json.Utf8JsonWriter(context.Response.Body);
            MetadataWireSerializer.WriteEntityListJson(writer, list, plan, list.Count);
            await writer.FlushAsync(context.RequestAborted);
        }
        else
        {
            var payload = _serializer!.SerializeList(list, plan, 1, list.Count);
            context.Response.ContentType = BinaryContentType;
            context.Response.ContentLength = payload.Length;
            await context.Response.Body.WriteAsync(payload, context.RequestAborted);
        }
    }

    private static async ValueTask<object?> ReadEntityFromRequest(BmwContext context, MetadataWireSerializer.FieldPlan[] plan, Type entityType)
    {
        if (RequestIsJson(context))
        {
            using var doc = await System.Text.Json.JsonDocument.ParseAsync(context.HttpRequest.Body, cancellationToken: context.RequestAborted);
            return MetadataWireSerializer.DeserializeFromJson(doc.RootElement, plan, entityType);
        }
        else
        {
            var body = await ReadBodyAsync(context);
            return _serializer!.Deserialize(body.Span, plan, entityType);
        }
    }

    private static async ValueTask<(DataEntityMetadata? Meta, string TypeSlug, (int StatusCode, string Message)? Error)> ValidateAsync(BmwContext context)
    {
        var typeSlug = GetRouteValue(context, "type") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(typeSlug))
            return (null, typeSlug, (400, "Entity type not specified."));

        if (!DataScaffold.TryGetEntity(typeSlug, out var meta))
            return (null, typeSlug, (404, "Not found."));

        // Permission check
        var permissionsNeeded = meta!.Permissions?.Trim();
        if (!string.IsNullOrWhiteSpace(permissionsNeeded)
            && !string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted);
            if (user == null && !string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase))
                return (null, typeSlug, (403, "Access denied."));
            if (user != null)
            {
                if (string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase))
                    return (null, typeSlug, (403, "Access denied."));
                if (!string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase))
                {
                    var userPerms = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                    var altLookup = userPerms.GetAlternateLookup<ReadOnlySpan<char>>();
                    var remaining = permissionsNeeded.AsSpan();
                    bool hasRequired = false;
                    bool allPresent = true;
                    while (remaining.Length > 0)
                    {
                        int idx = remaining.IndexOf(',');
                        ReadOnlySpan<char> segment;
                        if (idx < 0) { segment = remaining; remaining = default; }
                        else { segment = remaining[..idx]; remaining = remaining[(idx + 1)..]; }
                        var trimmed = segment.Trim();
                        if (trimmed.IsEmpty) continue;
                        hasRequired = true;
                        if (!altLookup.Contains(trimmed))
                        {
                            allPresent = false;
                            break;
                        }
                    }
                    if (hasRequired && !allPresent)
                            return (null, typeSlug, (403, "Access denied."));
                }
            }
        }

        return (meta, typeSlug, null);
    }

    internal static string? GetRouteValue(BmwContext context, string key)
    {
        var pageContext = context.GetPageContext();
        if (pageContext == null) return null;
        for (int i = 0; i < pageContext.PageMetaDataKeys.Length; i++)
        {
            if (string.Equals(pageContext.PageMetaDataKeys[i], key, StringComparison.OrdinalIgnoreCase))
                return pageContext.PageMetaDataValues[i];
        }
        return null;
    }

    private static async ValueTask<ReadOnlyMemory<byte>> ReadBodyAsync(BmwContext context)
    {
        var ms = new MemoryStream();
        await context.HttpRequest.Body.CopyToAsync(ms, context.RequestAborted);
        // Return a view over the internal buffer — avoids a full copy.
        // MemoryStream() has no unmanaged resources; the backing byte[] lives until GC collects it.
        return ms.GetBuffer().AsMemory(0, (int)ms.Length);
    }

    private static async ValueTask WriteError(BmwContext context, (int StatusCode, string Message) error)
    {
        context.Response.StatusCode = error.StatusCode;
        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body,
            new { error = error.Message, status = error.StatusCode }, JsonOpts, context.RequestAborted);
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };
}
