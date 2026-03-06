using System;
using System.Collections;
using System.Collections.Generic;

using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

/// <summary>
/// API handlers for the lookup() JavaScript function.
/// Provides endpoints for dynamic client-side data queries.
/// </summary>
public static class LookupApiHandlers
{
    private static IBufferedLogger? _logger;

    /// <summary>Initialise with a logger for error diagnostics.</summary>
    public static void Init(IBufferedLogger? logger) => _logger = logger;

    /// <summary>
    /// GET /api/_lookup/{EntityType}/{Id}
    /// Fetches a single entity by ID.
    /// </summary>
    public static async ValueTask GetEntityByIdHandler(BmwContext context)
    {
        var (meta, typeSlug, errorResponse) = await ValidateAndResolveEntityAsync(context);
        if (meta == null)
        {
            await WriteJsonErrorAsync(context, errorResponse!.StatusCode, errorResponse!.Message);
            return;
        }

        var id = GetRouteValue(context, "id") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(id))
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, "Entity ID not specified.");
            return;
        }

        var traverse = context.HttpRequest.Query.TryGetValue("traverseRelationships", out var tvVal)
            && string.Equals(tvVal.Count > 0 ? tvVal[0] : null, "true", StringComparison.OrdinalIgnoreCase);

        try
        {
            var entity = await meta.Handlers.LoadAsync(uint.Parse(id), context.RequestAborted);
            if (entity == null)
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status404NotFound, $"Entity with ID '{id}' not found.");
                return;
            }

            var result = await EntityToJsonAsync(entity, meta, traverse, context.RequestAborted);
            await WriteJsonAsync(context, result);
        }
        catch (Exception ex)
        {
            _logger?.LogError("LookupAPI|get", ex);
            await WriteJsonErrorAsync(context, StatusCodes.Status500InternalServerError, "Error loading entity.");
        }
    }

    /// <summary>
    /// GET /api/_lookup/{EntityType}?filter=field:value&filter=field2:value2
    /// Queries entities with optional filters.
    /// Supports multiple filters, sorting, pagination.
    /// </summary>
    public static async ValueTask QueryEntitiesHandler(BmwContext context)
    {
        var (meta, typeSlug, errorResponse) = await ValidateAndResolveEntityAsync(context);
        if (meta == null)
        {
            await WriteJsonErrorAsync(context, errorResponse!.StatusCode, errorResponse!.Message);
            return;
        }

        // Validate lookup relationship if source context is provided
        var sourceSlug = context.HttpRequest.Query["from"].ToString();
        var sourceField = context.HttpRequest.Query["via"].ToString();
        if (!string.IsNullOrWhiteSpace(sourceSlug) || !string.IsNullOrWhiteSpace(sourceField))
        {
            if (!ValidateLookupRelationship(sourceSlug, sourceField, typeSlug))
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status403Forbidden, "No declared lookup relationship between the specified entities.");
                return;
            }
        }

        var traverse = context.HttpRequest.Query.TryGetValue("traverseRelationships", out var tvVal)
            && string.Equals(tvVal.Count > 0 ? tvVal[0] : null, "true", StringComparison.OrdinalIgnoreCase);

        try
        {
            var queryDef = BuildQueryFromRequest(context, meta);
            var entities = await meta.Handlers.QueryAsync(queryDef, context.RequestAborted);
            var results = new List<Dictionary<string, object?>>(entities is ICollection entColl ? entColl.Count : 16);
            foreach (var e in entities)
                results.Add(await EntityToJsonAsync(e, meta, traverse, context.RequestAborted));

            await WriteJsonAsync(context, new Dictionary<string, object>
            {
                ["data"] = results,
                ["count"] = results.Count
            });
        }
        catch (Exception ex)
        {
            _logger?.LogError("LookupAPI|query", ex);
            await WriteJsonErrorAsync(context, StatusCodes.Status500InternalServerError, "Error querying entities.");
        }
    }

    /// <summary>
    /// POST /api/_lookup/{EntityType}/_batch
    /// Fetches multiple entities by ID in a single request.
    /// Request body: { "ids": ["id1", "id2", ...] }
    /// Response: { "results": { "id1": {...}, "id2": {...} } }
    /// </summary>
    public static async ValueTask BatchGetEntitiesHandler(BmwContext context)
    {
        var (meta, typeSlug, errorResponse) = await ValidateAndResolveEntityAsync(context);
        if (meta == null)
        {
            await WriteJsonErrorAsync(context, errorResponse!.StatusCode, errorResponse!.Message);
            return;
        }

        List<string> ids;
        try
        {
            using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body, cancellationToken: context.RequestAborted);
            if (!doc.RootElement.TryGetProperty("ids", out var idsElement) || idsElement.ValueKind != JsonValueKind.Array)
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, "Request body must contain an 'ids' array.");
                return;
            }

            ids = new List<string>(Math.Min(idsElement.GetArrayLength(), 500));
            var seen = new HashSet<string>(Math.Min(idsElement.GetArrayLength(), 500), StringComparer.Ordinal);
            foreach (var e in idsElement.EnumerateArray())
            {
                if (ids.Count >= 500) break;
                if (e.ValueKind != JsonValueKind.String) continue;
                var s = e.GetString()!;
                if (string.IsNullOrWhiteSpace(s)) continue;
                if (!seen.Add(s)) continue;
                ids.Add(s);
            }
        }
        catch (JsonException)
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, "Invalid JSON body.");
            return;
        }

        if (ids.Count == 0)
        {
            await WriteJsonAsync(context, new Dictionary<string, object> { ["results"] = new Dictionary<string, object?>() });
            return;
        }

        var traverse = context.HttpRequest.Query.TryGetValue("traverseRelationships", out var tvVal)
            && string.Equals(tvVal.Count > 0 ? tvVal[0] : null, "true", StringComparison.OrdinalIgnoreCase);

        try
        {
            var results = new Dictionary<string, object?>(ids.Count);
            foreach (var id in ids)
            {
                var entity = await meta.Handlers.LoadAsync(uint.Parse(id), context.RequestAborted);
                if (entity != null)
                    results[id] = await EntityToJsonAsync(entity, meta, traverse, context.RequestAborted);
            }

            await WriteJsonAsync(context, new Dictionary<string, object> { ["results"] = results });
        }
        catch (Exception ex)
        {
            _logger?.LogError("LookupAPI|batch", ex);
            await WriteJsonErrorAsync(context, StatusCodes.Status500InternalServerError, "Error loading entities.");
        }
    }

    /// <summary>
    /// GET /api/_lookup/{EntityType}/_field/{Id}/{FieldName}
    /// Fetches a single field value from an entity.
    /// </summary>
    public static async ValueTask GetEntityFieldHandler(BmwContext context)
    {
        var (meta, typeSlug, errorResponse) = await ValidateAndResolveEntityAsync(context);
        if (meta == null)
        {
            await WriteJsonErrorAsync(context, errorResponse!.StatusCode, errorResponse!.Message);
            return;
        }

        var id = GetRouteValue(context, "id") ?? string.Empty;
        var fieldName = GetRouteValue(context, "fieldName") ?? string.Empty;

        if (string.IsNullOrWhiteSpace(id))
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, "Entity ID not specified.");
            return;
        }

        if (string.IsNullOrWhiteSpace(fieldName))
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, "Field name not specified.");
            return;
        }

        try
        {
            var entity = await meta.Handlers.LoadAsync(uint.Parse(id), context.RequestAborted);
            if (entity == null)
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status404NotFound, $"Entity with ID '{id}' not found.");
                return;
            }

            DataFieldMetadata? field = null;
            foreach (var f in meta.Fields)
            {
                if (string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase) && f.View)
                {
                    field = f;
                    break;
                }
            }
            
            if (field == null)
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status404NotFound, $"Field '{fieldName}' not found.");
                return;
            }

            var value = field.GetValueFn(entity);
            await WriteJsonAsync(context, new Dictionary<string, object?>
            {
                ["field"] = field.Name,
                ["value"] = value
            });
        }
        catch (Exception ex)
        {
            _logger?.LogError("LookupAPI|field", ex);
            await WriteJsonErrorAsync(context, StatusCodes.Status500InternalServerError, "Error loading field.");
        }
    }

    /// <summary>
    /// GET /api/_lookup/{EntityType}/_aggregate?fn=count&field=Total&filter=field:value
    /// Performs aggregate operations on entities (count, sum, avg, min, max).
    /// </summary>
    public static async ValueTask AggregateEntitiesHandler(BmwContext context)
    {
        var (meta, typeSlug, errorResponse) = await ValidateAndResolveEntityAsync(context);
        if (meta == null)
        {
            await WriteJsonErrorAsync(context, errorResponse!.StatusCode, errorResponse!.Message);
            return;
        }

        var fn = context.HttpRequest.Query["fn"].ToString().ToLowerInvariant();
        var fieldName = context.HttpRequest.Query["field"].ToString();

        if (string.IsNullOrWhiteSpace(fn))
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, "Aggregate function not specified (use ?fn=count|sum|avg|min|max|stddev).");
            return;
        }

        try
        {
            var queryDef = BuildQueryFromRequest(context, meta);
            
            // Map string function name to enum
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
                await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, $"Unsupported aggregate function '{fn}'. Use count|sum|avg|min|max|stddev.");
                return;
            }

            if (aggFn != AggregateFunction.Count && string.IsNullOrWhiteSpace(fieldName))
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, $"Field name required for '{fn}' function (use ?field=FieldName).");
                return;
            }

            var result = await AggregationEngine.ComputeAsync(
                meta, queryDef, fieldName, aggFn, context.RequestAborted);

            if (result.Value == null && aggFn != AggregateFunction.Count)
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status404NotFound, $"Field '{fieldName}' not found or not numeric.");
                return;
            }

            await WriteJsonAsync(context, new Dictionary<string, object?>
            {
                ["function"] = fn,
                ["field"] = fieldName,
                ["result"] = result.Value,
                ["count"] = result.Count
            });
        }
        catch (Exception ex)
        {
            _logger?.LogError("LookupAPI|aggregate", ex);
            await WriteJsonErrorAsync(context, StatusCodes.Status500InternalServerError, "Error computing aggregate.");
        }
    }

    #region Helper Methods

    private static async ValueTask<(DataEntityMetadata? Meta, string TypeSlug, ErrorResponse? Error)> ValidateAndResolveEntityAsync(BmwContext context)
    {
        var typeSlug = GetRouteValue(context, "type") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(typeSlug))
        {
            return (null, typeSlug, new ErrorResponse(StatusCodes.Status400BadRequest, "Entity type not specified."));
        }

        // Fast path: use compiled ordinal from PrefixRouter → O(1) array index
        DataEntityMetadata? metadata = null;
        var snapshot = RuntimeSnapshot.Current;
        if (context.EntityOrdinal >= 0 && snapshot != null)
        {
            var entities = snapshot.Entities;
            if ((uint)context.EntityOrdinal < (uint)entities.Count)
                metadata = entities.Metadata[context.EntityOrdinal];
        }

        // Fallback: dictionary lookup
        if (metadata == null && !DataScaffold.TryGetEntity(typeSlug, out metadata))
        {
            return (null, typeSlug, new ErrorResponse(StatusCodes.Status404NotFound, "Not found."));
        }

        // Check permissions
        if (!await HasEntityPermissionAsync(context, metadata!, context.RequestAborted))
        {
            return (null, typeSlug, new ErrorResponse(StatusCodes.Status403Forbidden, "Access denied."));
        }

        return (metadata, typeSlug, null);
    }

    private static async ValueTask<bool> HasEntityPermissionAsync(BmwContext context, DataEntityMetadata meta, CancellationToken cancellationToken)
    {
        var permissionsNeeded = meta.Permissions?.Trim();
        if (string.IsNullOrWhiteSpace(permissionsNeeded) || 
            string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
            return true;

        var user = await UserAuth.GetRequestUserAsync(context, cancellationToken);
        if (user == null)
        {
            return string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase);
        }

        if (string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase))
            return false;

        var userPermissions = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        var altLookup = userPermissions.GetAlternateLookup<ReadOnlySpan<char>>();
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

    private static string? GetRouteValue(BmwContext context, string key)
    {
        // Fast path: prefix router sets these directly (zero allocation)
        if (string.Equals(key, "type", StringComparison.OrdinalIgnoreCase) && context.EntitySlug != null)
            return context.EntitySlug;
        if (string.Equals(key, "id", StringComparison.OrdinalIgnoreCase) && context.EntityId != null)
            return context.EntityId;
        if (context.RouteExtraKey != null && string.Equals(key, context.RouteExtraKey, StringComparison.OrdinalIgnoreCase))
            return context.RouteExtra;

        var pageContext = context.GetPageContext();
        if (pageContext == null)
            return null;

        for (int i = 0; i < pageContext.PageMetaDataKeys.Length; i++)
        {
            if (string.Equals(pageContext.PageMetaDataKeys[i], key, StringComparison.OrdinalIgnoreCase))
                return pageContext.PageMetaDataValues[i];
        }
        return null;
    }

    internal static QueryDefinition BuildQueryFromRequest(BmwContext context, DataEntityMetadata meta)
    {
        var queryDef = new QueryDefinition();

        var viewableFields = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in meta.ViewFields)
            viewableFields.Add(f.Name);

        // Parse filters from query string: ?filter=field:value
        var filters = context.HttpRequest.Query["filter"];
        foreach (var filter in filters)
        {
            if (string.IsNullOrWhiteSpace(filter))
                continue;

            var parts_idx = filter.IndexOf(':');
            if (parts_idx >= 0)
            {
                var fieldName = filter.AsSpan(0, parts_idx).Trim().ToString();
                if (!viewableFields.Contains(fieldName))
                    continue; // reject unknown or non-viewable fields
                queryDef.Clauses.Add(new QueryClause
                {
                    Field = fieldName,
                    Operator = QueryOperator.Equals,
                    Value = filter.AsSpan(parts_idx + 1).Trim().ToString()
                });
            }
        }

        // Parse sort: ?sort=fieldName&dir=asc|desc — only allow viewable fields
        var sortField = context.HttpRequest.Query["sort"].ToString();
        var sortDir = context.HttpRequest.Query["dir"].ToString();
        if (!string.IsNullOrWhiteSpace(sortField) && viewableFields.Contains(sortField))
        {
            queryDef.Sorts.Add(new SortClause
            {
                Field = sortField,
                Direction = string.Equals(sortDir, "desc", StringComparison.OrdinalIgnoreCase) 
                    ? SortDirection.Desc 
                    : SortDirection.Asc
            });
        }
        else if (!string.IsNullOrWhiteSpace(meta.DefaultSortField) && viewableFields.Contains(meta.DefaultSortField))
        {
            queryDef.Sorts.Add(new SortClause
            {
                Field = meta.DefaultSortField,
                Direction = meta.DefaultSortDirection
            });
        }

        // Parse pagination: ?skip=0&top=10
        if (int.TryParse(context.HttpRequest.Query["skip"].ToString(), out var skip) && skip > 0)
            queryDef.Skip = skip;
        
        const int LookupMaxPageSize = 10000;
        const int LookupDefaultPageSize = 200;
        queryDef.Top = int.TryParse(context.HttpRequest.Query["top"].ToString(), out var top) && top > 0
            ? Math.Min(top, LookupMaxPageSize)
            : LookupDefaultPageSize;

        // Parse search: ?search=term&searchField=FieldName — only allow viewable fields
        var searchTerm = context.HttpRequest.Query["search"].ToString();
        var searchField = context.HttpRequest.Query["searchField"].ToString();
        if (!string.IsNullOrWhiteSpace(searchTerm) && !string.IsNullOrWhiteSpace(searchField)
            && viewableFields.Contains(searchField))
        {
            queryDef.Clauses.Add(new QueryClause
            {
                Field = searchField,
                Operator = QueryOperator.Contains,
                Value = searchTerm
            });
        }

        return queryDef;
    }

    /// <summary>
    /// Validates that <paramref name="sourceSlug"/> declares a field named <paramref name="sourceFieldName"/>
    /// with a lookup that targets the entity identified by <paramref name="targetSlug"/>.
    /// Returns <c>false</c> if either entity is unknown, the field does not exist, or the field has no
    /// lookup pointing at the target entity.
    /// </summary>
    private static bool ValidateLookupRelationship(string sourceSlug, string sourceFieldName, string targetSlug)
    {
        if (string.IsNullOrWhiteSpace(sourceSlug) || string.IsNullOrWhiteSpace(sourceFieldName))
            return false;

        if (!DataScaffold.TryGetEntity(sourceSlug, out var sourceMeta))
            return false;

        DataFieldMetadata? field = null;
        foreach (var f in sourceMeta!.Fields)
        {
            if (string.Equals(f.Name, sourceFieldName, StringComparison.OrdinalIgnoreCase))
            {
                field = f;
                break;
            }
        }

        if (field?.Lookup == null)
            return false;

        var targetMeta = DataScaffold.GetEntityByType(field.Lookup.TargetType);
        return string.Equals(targetMeta?.Slug, targetSlug, StringComparison.OrdinalIgnoreCase);
    }

    private static Dictionary<string, object?> EntityToJson(BaseDataObject entity, DataEntityMetadata meta)
    {
        var result = new Dictionary<string, object?>
        {
            ["id"] = entity.Key.ToString()
        };

        foreach (var field in meta.ViewFields)
        {
            var value = field.GetValueFn(entity);
            result[field.Name] = value;
        }

        return result;
    }

    /// <summary>
    /// Builds the JSON dictionary for an entity, optionally expanding lookup FK fields into nested objects.
    /// When <paramref name="traverseRelationships"/> is <c>true</c>, each viewable field decorated with
    /// <see cref="DataLookupAttribute"/> will have an additional key added alongside it — the field name
    /// with any trailing "Id" stripped — whose value is the full related entity object.
    /// For example, <c>CustomerId: "abc"</c> becomes accompanied by <c>Customer: {id: "abc", Name: "Acme", ...}</c>.
    /// Expansion is one level deep only to prevent circular traversal.
    /// </summary>
    private static async ValueTask<Dictionary<string, object?>> EntityToJsonAsync(
        BaseDataObject entity,
        DataEntityMetadata meta,
        bool traverseRelationships,
        CancellationToken cancellationToken)
    {
        var result = EntityToJson(entity, meta);

        if (!traverseRelationships)
            return result;

        int traversed = 0;
        const int MaxTraversals = 20; // Cap FK loads per entity to prevent N+1 explosion
        foreach (var field in meta.Fields)
        {
            if (!field.View || field.Lookup == null) continue;
            if (traversed >= MaxTraversals) break;

            if (!result.TryGetValue(field.Name, out var rawValue) || rawValue == null)
                continue;

            if (rawValue is not string idStr || string.IsNullOrWhiteSpace(idStr))
                continue;

            var relatedMeta = DataScaffold.GetEntityByType(field.Lookup!.TargetType);
            if (relatedMeta == null)
                continue;

            var expandedKey = StripIdSuffix(field.Name);
            if (string.Equals(expandedKey, field.Name, StringComparison.Ordinal) || result.ContainsKey(expandedKey))
                continue;

            if (!uint.TryParse(idStr, out var relatedId)) continue;
            var related = await relatedMeta.Handlers.LoadAsync(relatedId, cancellationToken);
            if (related != null)
                result[expandedKey] = EntityToJson(related, relatedMeta);
            traversed++;
        }

        return result;
    }

    /// <summary>
    /// Returns <paramref name="fieldName"/> with a trailing "Id" (case-insensitive) stripped.
    /// Returns the original name unchanged when it does not end with "Id" or is 2 characters or shorter.
    /// </summary>
    private static string StripIdSuffix(string fieldName)
    {
        if (fieldName.Length > 2 && fieldName.EndsWith("Id", StringComparison.OrdinalIgnoreCase))
            return fieldName[..^2];
        return fieldName;
    }

    private static async ValueTask WriteJsonAsync(BmwContext context, object data)
    {
        context.Response.StatusCode = StatusCodes.Status200OK;
        await JsonWriterHelper.WriteResponseAsync(context.Response, data);
    }

    private static async ValueTask WriteJsonErrorAsync(BmwContext context, int statusCode, string message)
    {
        context.Response.StatusCode = statusCode;
        await JsonWriterHelper.WriteResponseAsync(context.Response, new Dictionary<string, object?>
        {
            ["error"] = message,
            ["status"] = statusCode
        });
    }

    private record ErrorResponse(int StatusCode, string Message);

    #endregion
}
