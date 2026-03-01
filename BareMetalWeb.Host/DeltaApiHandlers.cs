using System.Buffers;
using System.Buffers.Binary;
using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// HTTP handler for delta mutations: PATCH /api/_binary/{type}/{id}
/// Accepts binary MutationDelta or JSON field changes, applies via DeltaMutationEngine.
/// </summary>
public static class DeltaApiHandlers
{
    private const string BinaryContentType = "application/octet-stream";

    /// <summary>
    /// PATCH /api/_binary/{type}/{id}
    /// Binary body: raw MutationDelta wire format
    /// JSON body: { "expectedVersion": N, "changes": { "FieldName": value, ... } }
    /// </summary>
    public static async ValueTask DeltaHandler(HttpContext context)
    {
        // Resolve entity type + auth
        var typeSlug = BinaryApiHandlers.GetRouteValue(context, "type") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(typeSlug))
        {
            await WriteResult(context, 400, MutationResult.EntityNotFound, "Entity type not specified.");
            return;
        }

        if (!DataScaffold.TryGetEntity(typeSlug, out var meta))
        {
            await WriteResult(context, 404, MutationResult.EntityNotFound, $"Unknown entity type '{typeSlug}'.");
            return;
        }

        var idStr = BinaryApiHandlers.GetRouteValue(context, "id");
        if (string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var entityId))
        {
            await WriteResult(context, 400, MutationResult.EntityNotFound, "Invalid entity ID.");
            return;
        }

        // Auth check
        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted);
        var userName = user?.UserName ?? "anonymous";
        var permissionsNeeded = meta!.Permissions?.Trim();
        if (!string.IsNullOrWhiteSpace(permissionsNeeded)
            && !string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
        {
            if (user == null)
            {
                await WriteResult(context, 403, MutationResult.ValidationFailed, "Access denied.");
                return;
            }
        }

        try
        {
            var layout = EntityLayoutCompiler.GetOrCompile(meta);
            MutationDelta delta;

            if (RequestIsJson(context))
            {
                delta = await ParseJsonDelta(context, layout, entityId);
            }
            else
            {
                using var ms = new MemoryStream();
                await context.Request.Body.CopyToAsync(ms, context.RequestAborted);
                delta = MutationDelta.Deserialize(ms.ToArray());
            }

            var (entity, result) = await DeltaMutationEngine.ApplyDeltaAsync(
                meta, layout, delta, userName, context.RequestAborted);

            if (result != MutationResult.Success)
            {
                int statusCode = result switch
                {
                    MutationResult.VersionConflict => 409,
                    MutationResult.SchemaHashMismatch => 409,
                    MutationResult.EntityNotFound => 404,
                    MutationResult.ValidationFailed => 422,
                    MutationResult.InvalidOrdinal => 400,
                    _ => 500,
                };
                await WriteResult(context, statusCode, result, result.ToString());
                return;
            }

            // Return updated entity (binary or JSON)
            if (WantsJson(context))
            {
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await using var writer = new Utf8JsonWriter(context.Response.Body);
                WriteEntityJson(writer, entity!, layout);
                await writer.FlushAsync(context.RequestAborted);
            }
            else
            {
                // Return binary: version(4) + serialized entity via MetadataWireSerializer
                var plan = BinaryApiHandlers.GetOrBuildPlanPublic(meta);
                var serializer = BinaryApiHandlers.GetSerializer();
                if (serializer == null)
                {
                    await WriteResult(context, 500, MutationResult.ValidationFailed, "Serializer not initialized.");
                    return;
                }
                var payload = serializer.Serialize(entity!, plan, 1);
                context.Response.StatusCode = 200;
                context.Response.ContentType = BinaryContentType;
                context.Response.ContentLength = payload.Length;
                await context.Response.Body.WriteAsync(payload, context.RequestAborted);
            }
        }
        catch (Exception ex)
        {
            await WriteResult(context, 500, MutationResult.ValidationFailed, $"Error applying delta: {ex.Message}");
        }
    }

    /// <summary>
    /// GET /api/_binary/{type}/_layout
    /// Returns the EntityLayout schema as JSON (field ordinals, types, flags, schema hash).
    /// </summary>
    public static async ValueTask LayoutHandler(HttpContext context)
    {
        var typeSlug = BinaryApiHandlers.GetRouteValue(context, "type") ?? string.Empty;
        if (!DataScaffold.TryGetEntity(typeSlug, out var meta))
        {
            context.Response.StatusCode = 404;
            return;
        }

        var layout = EntityLayoutCompiler.GetOrCompile(meta!);

        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";
        await using var writer = new Utf8JsonWriter(context.Response.Body);
        writer.WriteStartObject();
        writer.WriteString("entity", layout.EntityName);
        writer.WriteString("slug", layout.Slug);
        writer.WriteString("schemaHash", layout.SchemaHash.ToString());
        writer.WriteNumber("nullBitmapBytes", layout.NullBitmapBytes);
        writer.WriteNumber("fixedRegionBytes", layout.FixedRegionBytes);
        writer.WriteNumber("varFieldCount", layout.VarFieldCount);
        writer.WriteNumber("rowMinBytes", layout.RowMinBytes);

        writer.WriteStartArray("fields");
        foreach (var field in layout.Fields)
        {
            writer.WriteStartObject();
            writer.WriteNumber("ordinal", field.Ordinal);
            writer.WriteString("name", field.Name);
            writer.WriteString("type", field.Type.ToString());
            writer.WriteNumber("flags", (ushort)field.Flags);
            writer.WriteNumber("fixedSizeBytes", field.FixedSizeBytes);
            writer.WriteNumber("fixedOffset", field.FixedOffset);
            writer.WriteNumber("varIndex", field.VarIndex);
            writer.WriteNumber("codecId", field.CodecId);
            writer.WriteBoolean("nullable", field.Is(FieldFlags.Nullable));
            writer.WriteBoolean("readOnly", field.Is(FieldFlags.ReadOnly));
            writer.WriteEndObject();
        }
        writer.WriteEndArray();

        writer.WriteEndObject();
        await writer.FlushAsync(context.RequestAborted);
    }

    // ── Helpers ──

    private static bool WantsJson(HttpContext context)
        => context.Request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase);

    private static bool RequestIsJson(HttpContext context)
        => context.Request.ContentType?.Contains("application/json", StringComparison.OrdinalIgnoreCase) == true;

    private static async Task<MutationDelta> ParseJsonDelta(
        HttpContext context, EntityLayout layout, uint entityId)
    {
        using var doc = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: context.RequestAborted);
        var root = doc.RootElement;

        uint expectedVersion = 0;
        if (root.TryGetProperty("expectedVersion", out var ev))
            expectedVersion = ev.GetUInt32();

        var changes = new List<FieldDelta>();

        if (root.TryGetProperty("changes", out var changesEl) && changesEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in changesEl.EnumerateObject())
            {
                var field = layout.FieldByName(prop.Name);
                if (field == null) continue;
                if (field.Is(FieldFlags.ReadOnly)) continue;

                if (prop.Value.ValueKind == JsonValueKind.Null)
                {
                    changes.Add(new FieldDelta((ushort)field.Ordinal, ReadOnlyMemory<byte>.Empty));
                    continue;
                }

                // Parse JSON value to CLR object, then encode via codec
                var codec = CodecTable.Get(field.CodecId);
                object? parsed = ParseJsonFieldValue(prop.Value, field, codec);
                if (parsed != null)
                {
                    var encoded = DeltaMutationEngine.EncodeFieldValue(field, parsed);
                    changes.Add(new FieldDelta((ushort)field.Ordinal, encoded));
                }
            }
        }

        return new MutationDelta
        {
            RowId = entityId,
            ExpectedVersion = expectedVersion,
            SchemaHash = layout.SchemaHash,
            Changes = changes.ToArray(),
        };
    }

    private static object? ParseJsonFieldValue(JsonElement el, FieldRuntime field, IFieldCodec codec)
    {
        return field.Type switch
        {
            FieldType.Bool => el.GetBoolean(),
            FieldType.Byte => (byte)el.GetUInt32(),
            FieldType.SByte => (sbyte)el.GetInt32(),
            FieldType.Int16 => (short)el.GetInt32(),
            FieldType.UInt16 => (ushort)el.GetUInt32(),
            FieldType.Int32 => el.GetInt32(),
            FieldType.UInt32 => el.GetUInt32(),
            FieldType.Int64 => el.GetInt64(),
            FieldType.UInt64 => el.GetUInt64(),
            FieldType.Float32 => (float)el.GetDouble(),
            FieldType.Float64 => el.GetDouble(),
            FieldType.Decimal => el.GetDecimal(),
            FieldType.Char => el.GetString()?.FirstOrDefault() ?? '\0',
            FieldType.StringUtf8 => el.GetString(),
            FieldType.Guid => Guid.Parse(el.GetString()!),
            FieldType.DateTime => DateTime.Parse(el.GetString()!),
            FieldType.DateOnly => DateOnly.Parse(el.GetString()!),
            FieldType.TimeOnly => TimeOnly.Parse(el.GetString()!),
            FieldType.DateTimeOffset => DateTimeOffset.Parse(el.GetString()!),
            FieldType.TimeSpan => TimeSpan.Parse(el.GetString()!),
            FieldType.Identifier => IdentifierValue.Parse(el.GetString()!),
            FieldType.EnumInt32 => el.ValueKind == JsonValueKind.Number
                ? Enum.ToObject(field.ClrType, el.GetInt32())
                : Enum.Parse(field.ClrType, el.GetString()!, true),
            _ => el.GetString(),
        };
    }

    private static void WriteEntityJson(Utf8JsonWriter writer, BaseDataObject entity, EntityLayout layout)
    {
        writer.WriteStartObject();
        foreach (var field in layout.Fields)
        {
            var val = field.Getter(entity);
            writer.WritePropertyName(field.Name);
            if (val is null)
            {
                writer.WriteNullValue();
                continue;
            }
            switch (field.Type)
            {
                case FieldType.Bool: writer.WriteBooleanValue((bool)val); break;
                case FieldType.Byte: writer.WriteNumberValue((byte)val); break;
                case FieldType.SByte: writer.WriteNumberValue((sbyte)val); break;
                case FieldType.Int16: writer.WriteNumberValue((short)val); break;
                case FieldType.UInt16: writer.WriteNumberValue((ushort)val); break;
                case FieldType.Int32: writer.WriteNumberValue((int)val); break;
                case FieldType.UInt32: writer.WriteNumberValue((uint)val); break;
                case FieldType.Int64: writer.WriteNumberValue((long)val); break;
                case FieldType.UInt64: writer.WriteNumberValue((ulong)val); break;
                case FieldType.Float32: writer.WriteNumberValue((float)val); break;
                case FieldType.Float64: writer.WriteNumberValue((double)val); break;
                case FieldType.Decimal: writer.WriteNumberValue((decimal)val); break;
                case FieldType.DateTime: writer.WriteStringValue(((DateTime)val).ToString("O")); break;
                case FieldType.DateOnly: writer.WriteStringValue(((DateOnly)val).ToString("O")); break;
                case FieldType.TimeOnly: writer.WriteStringValue(((TimeOnly)val).ToString("O")); break;
                case FieldType.DateTimeOffset: writer.WriteStringValue(((DateTimeOffset)val).ToString("O")); break;
                case FieldType.TimeSpan: writer.WriteStringValue(((TimeSpan)val).ToString()); break;
                case FieldType.Guid: writer.WriteStringValue(((Guid)val).ToString("D")); break;
                case FieldType.Identifier: writer.WriteStringValue(val.ToString()); break;
                case FieldType.EnumInt32: writer.WriteNumberValue(Convert.ToInt32(val)); break;
                default: writer.WriteStringValue(val.ToString()); break;
            }
        }
        writer.WriteEndObject();
    }

    private static async ValueTask WriteResult(HttpContext context, int statusCode, MutationResult result, string message)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        await using var writer = new Utf8JsonWriter(context.Response.Body);
        writer.WriteStartObject();
        writer.WriteString("result", result.ToString());
        writer.WriteString("message", message);
        writer.WriteEndObject();
        await writer.FlushAsync(context.RequestAborted);
    }
}
