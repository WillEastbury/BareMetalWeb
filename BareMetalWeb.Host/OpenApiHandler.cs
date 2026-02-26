using System.Net;
using System.Text;
using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Builds and serves a rudimentary OpenAPI 3.1.1 specification for the BareMetalWeb
/// entity API, constructed entirely without any Swagger/NSwag library by recursing
/// entity types registered with <see cref="DataScaffold"/>.
///
/// Endpoint: GET /openapi.json
///
/// Only entities and schemas that the authenticated caller has permission to access
/// are included in the returned document.
/// </summary>
internal static class OpenApiHandler
{
    private static readonly JsonSerializerOptions _writeOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    // ── Entry point ───────────────────────────────────────────────────────────

    internal static async ValueTask HandleAsync(HttpContext context)
    {
        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted)
            .ConfigureAwait(false);

        var userPermissions = user?.Permissions ?? Array.Empty<string>();

        var accessibleEntities = DataScaffold.Entities
            .Where(e => IsEntityAccessible(e, user, userPermissions))
            .OrderBy(e => e.Slug)
            .ToArray();

        var document = BuildDocument(context, accessibleEntities);

        context.Response.ContentType = "application/json; charset=utf-8";
        context.Response.Headers["Cache-Control"] = "no-store";
        await context.Response.WriteAsync(
            JsonSerializer.Serialize(document, _writeOptions),
            context.RequestAborted).ConfigureAwait(false);
    }

    // ── Document builder ──────────────────────────────────────────────────────

    private static Dictionary<string, object?> BuildDocument(
        HttpContext context,
        DataEntityMetadata[] entities)
    {
        var request = context.Request;
        var scheme = request.IsHttps ? "https" : "http";
        var host = request.Host.Value ?? "localhost";
        var serverUrl = $"{scheme}://{host}";

        // Collect schema components (may be referenced by multiple entities).
        var components = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var entity in entities)
            AddSchemaComponent(components, entity);

        var paths = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var entity in entities)
        {
            AddCollectionPath(paths, entity);
            AddItemPath(paths, entity);
            if (entity.Commands.Count > 0)
            {
                foreach (var cmd in entity.Commands)
                    AddCommandPath(paths, entity, cmd);
            }
        }

        return new Dictionary<string, object?>
        {
            ["openapi"] = "3.1.1",
            ["info"] = new Dictionary<string, object?>
            {
                ["title"]   = "BareMetalWeb API",
                ["version"] = "1.0.0",
                ["description"] = "Auto-generated OpenAPI specification. Only resources accessible to the authenticated caller are listed."
            },
            ["servers"] = new object[]
            {
                new Dictionary<string, object?> { ["url"] = serverUrl }
            },
            ["paths"] = paths,
            ["components"] = new Dictionary<string, object?>
            {
                ["schemas"] = components,
                ["securitySchemes"] = new Dictionary<string, object?>
                {
                    ["cookieAuth"] = new Dictionary<string, object?>
                    {
                        ["type"] = "apiKey",
                        ["in"]   = "cookie",
                        ["name"] = UserAuth.SessionCookieName
                    }
                }
            },
            ["security"] = new object[]
            {
                new Dictionary<string, object?> { ["cookieAuth"] = Array.Empty<string>() }
            }
        };
    }

    // ── Path builders ─────────────────────────────────────────────────────────

    /// <summary>Adds GET /api/{slug} and POST /api/{slug} paths.</summary>
    private static void AddCollectionPath(Dictionary<string, object?> paths, DataEntityMetadata entity)
    {
        var path = $"/api/{entity.Slug}";
        var ops = new Dictionary<string, object?>();
        var tag = entity.Name;
        var schemaRef = SchemaRef(entity.Slug);
        var listSchemaRef = new Dictionary<string, object?>
        {
            ["type"]  = "array",
            ["items"] = schemaRef
        };

        // GET — list
        ops["get"] = new Dictionary<string, object?>
        {
            ["tags"]        = new[] { tag },
            ["summary"]     = $"List {entity.Name} records",
            ["operationId"] = $"list_{entity.Slug}",
            ["parameters"]  = BuildQueryParameters(),
            ["responses"]   = new Dictionary<string, object?>
            {
                ["200"] = OkResponse($"List of {entity.Name}", listSchemaRef),
                ["401"] = ErrorResponse("Unauthorized"),
                ["403"] = ErrorResponse("Forbidden")
            }
        };

        // POST — create
        ops["post"] = new Dictionary<string, object?>
        {
            ["tags"]        = new[] { tag },
            ["summary"]     = $"Create a new {entity.Name}",
            ["operationId"] = $"create_{entity.Slug}",
            ["requestBody"] = RequestBody(entity.Slug, $"New {entity.Name} to create", required: true),
            ["responses"]   = new Dictionary<string, object?>
            {
                ["201"] = OkResponse($"Created {entity.Name}", schemaRef),
                ["400"] = ErrorResponse("Bad request"),
                ["401"] = ErrorResponse("Unauthorized"),
                ["403"] = ErrorResponse("Forbidden")
            }
        };

        paths[path] = ops;
    }

    /// <summary>Adds GET/PUT/PATCH/DELETE /api/{slug}/{id} paths.</summary>
    private static void AddItemPath(Dictionary<string, object?> paths, DataEntityMetadata entity)
    {
        var path = $"/api/{entity.Slug}/{{id}}";
        var tag = entity.Name;
        var schemaRef = SchemaRef(entity.Slug);
        var idParam = IdParameter();

        var ops = new Dictionary<string, object?>
        {
            ["get"] = new Dictionary<string, object?>
            {
                ["tags"]        = new[] { tag },
                ["summary"]     = $"Get a {entity.Name} by Id",
                ["operationId"] = $"get_{entity.Slug}",
                ["parameters"]  = new object[]
                {
                    idParam,
                    new Dictionary<string, object?>
                    {
                        ["name"]        = "traverseRelationships",
                        ["in"]          = "query",
                        ["description"] = "When true, lookup FK fields are expanded into nested objects containing the full related entity.",
                        ["schema"]      = new Dictionary<string, object?> { ["type"] = "boolean", ["default"] = false }
                    }
                },
                ["responses"]   = new Dictionary<string, object?>
                {
                    ["200"] = OkResponse(entity.Name, schemaRef),
                    ["401"] = ErrorResponse("Unauthorized"),
                    ["403"] = ErrorResponse("Forbidden"),
                    ["404"] = ErrorResponse("Not found")
                }
            },
            ["put"] = new Dictionary<string, object?>
            {
                ["tags"]        = new[] { tag },
                ["summary"]     = $"Replace a {entity.Name}",
                ["operationId"] = $"replace_{entity.Slug}",
                ["parameters"]  = new[] { idParam },
                ["requestBody"] = RequestBody(entity.Slug, $"Replacement {entity.Name}", required: true),
                ["responses"]   = new Dictionary<string, object?>
                {
                    ["200"] = OkResponse($"Updated {entity.Name}", schemaRef),
                    ["400"] = ErrorResponse("Bad request"),
                    ["401"] = ErrorResponse("Unauthorized"),
                    ["403"] = ErrorResponse("Forbidden"),
                    ["404"] = ErrorResponse("Not found")
                }
            },
            ["patch"] = new Dictionary<string, object?>
            {
                ["tags"]        = new[] { tag },
                ["summary"]     = $"Partially update a {entity.Name}",
                ["operationId"] = $"patch_{entity.Slug}",
                ["parameters"]  = new[] { idParam },
                ["requestBody"] = RequestBody(entity.Slug, $"Partial {entity.Name} update", required: true),
                ["responses"]   = new Dictionary<string, object?>
                {
                    ["200"] = OkResponse($"Updated {entity.Name}", schemaRef),
                    ["400"] = ErrorResponse("Bad request"),
                    ["401"] = ErrorResponse("Unauthorized"),
                    ["403"] = ErrorResponse("Forbidden"),
                    ["404"] = ErrorResponse("Not found")
                }
            },
            ["delete"] = new Dictionary<string, object?>
            {
                ["tags"]        = new[] { tag },
                ["summary"]     = $"Delete a {entity.Name}",
                ["operationId"] = $"delete_{entity.Slug}",
                ["parameters"]  = new[] { idParam },
                ["responses"]   = new Dictionary<string, object?>
                {
                    ["204"] = new Dictionary<string, object?> { ["description"] = "Deleted" },
                    ["401"] = ErrorResponse("Unauthorized"),
                    ["403"] = ErrorResponse("Forbidden"),
                    ["404"] = ErrorResponse("Not found")
                }
            }
        };

        paths[path] = ops;
    }

    /// <summary>Adds POST /api/{slug}/{id}/_command/{command} paths.</summary>
    private static void AddCommandPath(
        Dictionary<string, object?> paths,
        DataEntityMetadata entity,
        RemoteCommandMetadata cmd)
    {
        var path = $"/api/{entity.Slug}/{{id}}/_command/{WebUtility.UrlEncode(cmd.Name)}";
        paths[path] = new Dictionary<string, object?>
        {
            ["post"] = new Dictionary<string, object?>
            {
                ["tags"]        = new[] { entity.Name },
                ["summary"]     = string.IsNullOrWhiteSpace(cmd.Label) ? cmd.Name : cmd.Label,
                ["operationId"] = $"cmd_{entity.Slug}_{cmd.Name}",
                ["parameters"]  = new[] { IdParameter() },
                ["responses"]   = new Dictionary<string, object?>
                {
                    ["200"] = OkResponse("Command result", new Dictionary<string, object?> { ["type"] = "object" }),
                    ["400"] = ErrorResponse("Bad request"),
                    ["401"] = ErrorResponse("Unauthorized"),
                    ["403"] = ErrorResponse("Forbidden"),
                    ["404"] = ErrorResponse("Not found")
                }
            }
        };
    }

    // ── Schema builder ────────────────────────────────────────────────────────

    private static void AddSchemaComponent(Dictionary<string, object?> components, DataEntityMetadata entity)
    {
        var schemaKey = SchemaKey(entity.Slug);
        if (components.ContainsKey(schemaKey))
            return;

        var properties = new Dictionary<string, object?>(StringComparer.Ordinal);
        var required = new List<string>();

        foreach (var field in entity.Fields.OrderBy(f => f.Order))
        {
            // Skip fields that are not viewable
            if (!field.View && !field.Edit && !field.Create)
                continue;

            var prop = BuildFieldSchema(field);
            properties[field.Name] = prop;

            if (field.Required && field.IdGeneration == IdGenerationStrategy.None)
                required.Add(field.Name);
        }

        var schema = new Dictionary<string, object?>
        {
            ["type"]       = "object",
            ["properties"] = properties
        };

        if (required.Count > 0)
            schema["required"] = required;

        components[schemaKey] = schema;
    }

    private static Dictionary<string, object?> BuildFieldSchema(DataFieldMetadata field)
    {
        // If it is a lookup field, the stored value is a string (the referenced entity's key).
        if (field.Lookup != null)
        {
            return new Dictionary<string, object?>
            {
                ["type"]        = "string",
                ["description"] = $"FK → {field.Lookup.TargetType?.Name ?? "unknown"} ({field.Lookup.DisplayField})"
            };
        }

        return field.FieldType switch
        {
            FormFieldType.Integer => SimpleSchema("integer", "int64"),
            FormFieldType.Decimal => SimpleSchema("number", "double"),
            FormFieldType.Money   => SimpleSchema("number", "double"),
            FormFieldType.YesNo   => new Dictionary<string, object?> { ["type"] = "boolean" },
            FormFieldType.DateOnly  => SimpleSchema("string", "date"),
            FormFieldType.DateTime  => SimpleSchema("string", "date-time"),
            FormFieldType.TimeOnly  => SimpleSchema("string", "time"),
            FormFieldType.Email     => SimpleSchema("string", "email"),
            FormFieldType.Password  => SimpleSchema("string", "password"),
            FormFieldType.Image
            or FormFieldType.File   => SimpleSchema("string", "binary"),
            FormFieldType.Enum      => BuildEnumSchema(field),
            FormFieldType.Tags      => new Dictionary<string, object?>
            {
                ["type"]  = "array",
                ["items"] = new Dictionary<string, object?> { ["type"] = "string" }
            },
            FormFieldType.Hidden
            or FormFieldType.ReadOnly
            or FormFieldType.CustomHtml => SimpleSchema("string", null),
            _                           => SimpleSchema("string", null)
        };
    }

    private static Dictionary<string, object?> BuildEnumSchema(DataFieldMetadata field)
    {
        var enumValues = DataScaffold.BuildEnumOptions(field.Property.PropertyType);
        if (enumValues.Count == 0)
            return SimpleSchema("string", null);

        return new Dictionary<string, object?>
        {
            ["type"] = "string",
            ["enum"] = enumValues.Select(kv => kv.Key).ToArray()
        };
    }

    // ── Reusable helpers ──────────────────────────────────────────────────────

    private static Dictionary<string, object?> SimpleSchema(string type, string? format)
    {
        var d = new Dictionary<string, object?> { ["type"] = type };
        if (format != null) d["format"] = format;
        return d;
    }

    private static Dictionary<string, object?> SchemaRef(string slug) =>
        new() { ["$ref"] = $"#/components/schemas/{SchemaKey(slug)}" };

    private static string SchemaKey(string slug) =>
        string.Concat(slug.Split('-')
            .Where(p => p.Length > 0)
            .Select(p => char.ToUpperInvariant(p[0]) + p[1..]));

    private static Dictionary<string, object?> IdParameter() =>
        new()
        {
            ["name"]     = "id",
            ["in"]       = "path",
            ["required"] = true,
            ["schema"]   = new Dictionary<string, object?> { ["type"] = "string" }
        };

    private static object[] BuildQueryParameters() =>
    [
        new Dictionary<string, object?>
        {
            ["name"]   = "skip",
            ["in"]     = "query",
            ["schema"] = new Dictionary<string, object?> { ["type"] = "integer", ["default"] = 0 }
        },
        new Dictionary<string, object?>
        {
            ["name"]   = "top",
            ["in"]     = "query",
            ["schema"] = new Dictionary<string, object?> { ["type"] = "integer", ["default"] = 50 }
        },
        new Dictionary<string, object?>
        {
            ["name"]   = "search",
            ["in"]     = "query",
            ["schema"] = new Dictionary<string, object?> { ["type"] = "string" }
        },
        new Dictionary<string, object?>
        {
            ["name"]        = "traverseRelationships",
            ["in"]          = "query",
            ["description"] = "When true, lookup FK fields are expanded into nested objects containing the full related entity.",
            ["schema"]      = new Dictionary<string, object?> { ["type"] = "boolean", ["default"] = false }
        }
    ];

    private static Dictionary<string, object?> RequestBody(string slug, string description, bool required)
    {
        return new Dictionary<string, object?>
        {
            ["description"] = description,
            ["required"]    = required,
            ["content"]     = new Dictionary<string, object?>
            {
                ["application/json"] = new Dictionary<string, object?>
                {
                    ["schema"] = SchemaRef(slug)
                }
            }
        };
    }

    private static Dictionary<string, object?> OkResponse(string description, object schema)
    {
        return new Dictionary<string, object?>
        {
            ["description"] = description,
            ["content"]     = new Dictionary<string, object?>
            {
                ["application/json"] = new Dictionary<string, object?>
                {
                    ["schema"] = schema
                }
            }
        };
    }

    private static Dictionary<string, object?> ErrorResponse(string description)
    {
        return new Dictionary<string, object?>
        {
            ["description"] = description,
            ["content"]     = new Dictionary<string, object?>
            {
                ["application/json"] = new Dictionary<string, object?>
                {
                    ["schema"] = new Dictionary<string, object?>
                    {
                        ["type"]       = "object",
                        ["properties"] = new Dictionary<string, object?>
                        {
                            ["error"] = new Dictionary<string, object?> { ["type"] = "string" }
                        }
                    }
                }
            }
        };
    }

    // ── Permission helpers ────────────────────────────────────────────────────

    private static bool IsEntityAccessible(DataEntityMetadata entity, User? user, string[] userPermissions)
    {
        var perms = entity.Permissions ?? string.Empty;
        if (string.IsNullOrWhiteSpace(perms) || string.Equals(perms, "Public", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.Equals(perms, "Authenticated", StringComparison.OrdinalIgnoreCase))
            return user != null;

        var required = perms.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return required.Any(r => userPermissions.Any(p => string.Equals(p, r, StringComparison.OrdinalIgnoreCase)));
    }
}
