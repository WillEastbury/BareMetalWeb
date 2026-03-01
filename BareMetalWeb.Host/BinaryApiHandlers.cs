using System.Buffers;
using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using BareMetalWeb.Core;
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
    private static byte[]? _signingKeyRaw;
    private static readonly ConcurrentDictionary<string, MetadataWireSerializer.FieldPlan[]> _plans = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, MetadataWireSerializer.WireSchemaDescriptor> _schemas = new(StringComparer.OrdinalIgnoreCase);

    private const string BinaryContentType = "application/x-bmw-binary";

    /// <summary>
    /// Initialise the binary API subsystem with the shared signing key.
    /// Call once at startup after data store creation.
    /// </summary>
    public static void Initialize(byte[] signingKey)
    {
        _signingKeyRaw = (byte[])signingKey.Clone();
        _serializer = new MetadataWireSerializer(signingKey);
    }

    // ────────────── Helpers ──────────────

    private static MetadataWireSerializer.FieldPlan[] GetOrBuildPlan(DataEntityMetadata meta)
    {
        return _plans.GetOrAdd(meta.Slug, _ => BuildPlanFromMetadata(meta));
    }

    private static MetadataWireSerializer.FieldPlan[] BuildPlanFromMetadata(DataEntityMetadata meta)
    {
        // Build a lookup from metadata fields for getter/setter reuse
        var metaFieldsByName = meta.Fields.ToDictionary(f => f.Name, StringComparer.Ordinal);

        // Collect ALL public properties on the CLR type — same set the BinaryObjectSerializer uses.
        // Sort by name (Ordinal compare) to match binary serializer member ordering.
        var props = meta.Type.GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .ToArray();

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
    public static async ValueTask KeyHandler(HttpContext context)
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
    public static async ValueTask SchemaHandler(HttpContext context)
    {
        var (meta, _, error) = await ValidateAsync(context);
        if (meta == null) { await WriteError(context, error!.Value); return; }

        var schema = GetOrBuildSchema(meta);
        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body, schema, JsonOpts, context.RequestAborted);
    }

    /// <summary>
    /// GET /api/_binary/{type}
    /// Returns binary-encoded entity list.
    /// </summary>
    public static async ValueTask ListHandler(HttpContext context)
    {
        var (meta, _, error) = await ValidateAsync(context);
        if (meta == null) { await WriteError(context, error!.Value); return; }
        if (_serializer == null) { await WriteError(context, (500, "Binary API not initialized.")); return; }

        try
        {
            var queryDef = LookupApiHandlers.BuildQueryFromRequest(context, meta);
            var entities = await meta.Handlers.QueryAsync(queryDef, context.RequestAborted);
            var list = entities.Cast<object>().ToList();

            var plan = GetOrBuildPlan(meta);
            var payload = _serializer.SerializeList(list, plan, 1, list.Count);

            context.Response.ContentType = BinaryContentType;
            context.Response.ContentLength = payload.Length;
            await context.Response.Body.WriteAsync(payload, context.RequestAborted);
        }
        catch (Exception)
        {
            await WriteError(context, (500, "Error querying entities."));
        }
    }

    /// <summary>
    /// GET /api/_binary/{type}/{id}
    /// Returns a single binary-encoded entity.
    /// </summary>
    public static async ValueTask GetHandler(HttpContext context)
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
            var payload = _serializer.Serialize(entity, plan, 1);

            context.Response.ContentType = BinaryContentType;
            context.Response.ContentLength = payload.Length;
            await context.Response.Body.WriteAsync(payload, context.RequestAborted);
        }
        catch (Exception)
        {
            await WriteError(context, (500, "Error loading entity."));
        }
    }

    /// <summary>
    /// POST /api/_binary/{type}
    /// Accepts a binary-encoded entity, saves it, returns the saved entity as binary.
    /// </summary>
    public static async ValueTask CreateHandler(HttpContext context)
    {
        var (meta, _, error) = await ValidateAsync(context);
        if (meta == null) { await WriteError(context, error!.Value); return; }
        if (_serializer == null) { await WriteError(context, (500, "Binary API not initialized.")); return; }

        try
        {
            var body = await ReadBodyAsync(context);
            var plan = GetOrBuildPlan(meta);
            var entity = _serializer.Deserialize(body.Span, plan, meta.Type);

            await DataScaffold.SaveAsync(meta, entity, context.RequestAborted);

            var payload = _serializer.Serialize(entity, plan, 1);
            context.Response.StatusCode = StatusCodes.Status201Created;
            context.Response.ContentType = BinaryContentType;
            context.Response.ContentLength = payload.Length;
            await context.Response.Body.WriteAsync(payload, context.RequestAborted);
        }
        catch (Exception)
        {
            await WriteError(context, (500, "Error creating entity."));
        }
    }

    /// <summary>
    /// PUT /api/_binary/{type}/{id}
    /// Accepts a binary-encoded entity, updates it.
    /// </summary>
    public static async ValueTask UpdateHandler(HttpContext context)
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
            var body = await ReadBodyAsync(context);
            var plan = GetOrBuildPlan(meta);
            var entity = _serializer.Deserialize(body.Span, plan, meta.Type);

            // Ensure key matches URL
            if (entity is BaseDataObject bdo && bdo.Key != id)
                bdo.Key = id;

            await DataScaffold.SaveAsync(meta, entity, context.RequestAborted);

            var payload = _serializer.Serialize(entity, plan, 1);
            context.Response.ContentType = BinaryContentType;
            context.Response.ContentLength = payload.Length;
            await context.Response.Body.WriteAsync(payload, context.RequestAborted);
        }
        catch (Exception)
        {
            await WriteError(context, (500, "Error updating entity."));
        }
    }

    /// <summary>
    /// DELETE /api/_binary/{type}/{id}
    /// Deletes an entity by key.
    /// </summary>
    public static async ValueTask DeleteHandler(HttpContext context)
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
        catch (Exception)
        {
            await WriteError(context, (500, "Error deleting entity."));
        }
    }

    // ────────────── Shared utilities ──────────────

    private static async ValueTask<(DataEntityMetadata? Meta, string TypeSlug, (int StatusCode, string Message)? Error)> ValidateAsync(HttpContext context)
    {
        var typeSlug = GetRouteValue(context, "type") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(typeSlug))
            return (null, typeSlug, (400, "Entity type not specified."));

        if (!DataScaffold.TryGetEntity(typeSlug, out var meta))
            return (null, typeSlug, (404, $"Unknown entity type '{typeSlug}'."));

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
                    var required = permissionsNeeded.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    if (required.Length > 0 && !required.All(userPerms.Contains))
                        return (null, typeSlug, (403, "Access denied."));
                }
            }
        }

        return (meta, typeSlug, null);
    }

    private static string? GetRouteValue(HttpContext context, string key)
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

    private static async ValueTask<ReadOnlyMemory<byte>> ReadBodyAsync(HttpContext context)
    {
        using var ms = new MemoryStream();
        await context.Request.Body.CopyToAsync(ms, context.RequestAborted);
        return ms.ToArray();
    }

    private static async ValueTask WriteError(HttpContext context, (int StatusCode, string Message) error)
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
