using System.Collections;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Host;

/// <summary>
/// Zero-dependency GraphQL endpoint.  Auto-generates a schema from DataScaffold metadata
/// and supports queries (single item by id, list with optional filters) and introspection (__schema).
/// POST /api/graphql  { "query": "...", "variables": { } }
/// </summary>
public static class GraphQLHandler
{
    // ── GraphQL type mapping ──────────────────────────────────────────────

    private static string ToGraphQLType(FormFieldType ft, bool required)
    {
        var t = ft switch
        {
            FormFieldType.Integer => "Int",
            FormFieldType.Decimal or FormFieldType.Money => "Float",
            FormFieldType.YesNo => "Boolean",
            _ => "String"
        };
        return required ? t + "!" : t;
    }

    // ── Schema introspection ──────────────────────────────────────────────

    private static void WriteIntrospectionSchema(Utf8JsonWriter writer)
    {
        var queryFieldData = new List<(string name, bool isList, string typeName)>();

        writer.WriteStartObject();
        writer.WritePropertyName("__schema");
        writer.WriteStartObject();
        writer.WriteStartArray("types");

        foreach (var meta in DataScaffold.Entities)
        {
            var pascalName = ToPascal(meta.Slug);
            writer.WriteStartObject();
            writer.WriteString("kind", "OBJECT");
            writer.WriteString("name", pascalName);
            writer.WriteStartArray("fields");

            writer.WriteStartObject();
            writer.WriteString("name", "id");
            writer.WriteStartObject("type");
            writer.WriteString("kind", "SCALAR");
            writer.WriteString("name", "ID");
            writer.WriteNull("ofType");
            writer.WriteEndObject();
            writer.WriteEndObject();

            for (int fi = 0; fi < meta.Fields.Count; fi++)
            {
                var f = meta.Fields[fi];
                writer.WriteStartObject();
                writer.WriteString("name", ToCamel(f.Name));
                writer.WriteStartObject("type");
                writer.WriteString("kind", "SCALAR");
                writer.WriteString("name", ToGraphQLType(f.FieldType, f.Required));
                writer.WriteNull("ofType");
                writer.WriteEndObject();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();

            queryFieldData.Add((ToCamel(meta.Slug) + "List", true, pascalName));
            queryFieldData.Add((ToCamel(meta.Slug), false, pascalName));
        }

        writer.WriteStartObject();
        writer.WriteString("kind", "OBJECT");
        writer.WriteString("name", "Query");
        writer.WriteStartArray("fields");
        foreach (var (name, isList, typeName) in queryFieldData)
        {
            writer.WriteStartObject();
            writer.WriteString("name", name);
            writer.WriteStartObject("type");
            if (isList)
            {
                writer.WriteString("kind", "LIST");
                writer.WriteNull("name");
                writer.WriteStartObject("ofType");
                writer.WriteString("kind", "OBJECT");
                writer.WriteString("name", typeName);
                writer.WriteEndObject();
            }
            else
            {
                writer.WriteString("kind", "OBJECT");
                writer.WriteString("name", typeName);
                writer.WriteNull("ofType");
            }
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
        writer.WriteEndObject();

        writer.WriteEndArray();
        writer.WriteStartObject("queryType");
        writer.WriteString("name", "Query");
        writer.WriteEndObject();
        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    // ── Query execution ───────────────────────────────────────────────────

    public static async ValueTask HandleAsync(BmwContext context)
    {
        context.Response.ContentType = "application/json; charset=utf-8";

        string? queryText = null;
        JsonElement variables = default;

        try
        {
            using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body, cancellationToken: context.RequestAborted);
            if (doc.RootElement.TryGetProperty("query", out var qProp)) queryText = qProp.GetString();
            if (doc.RootElement.TryGetProperty("variables", out var vProp)) variables = vProp.Clone();
        }
        catch
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("{\"errors\":[{\"message\":\"Invalid request body.\"}]}");
            return;
        }

        if (string.IsNullOrWhiteSpace(queryText))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("{\"errors\":[{\"message\":\"Missing query.\"}]}");
            return;
        }

        // SECURITY: Enforce query depth and field count limits to prevent abuse (see #1207)
        const int MaxQueryDepth = 5;
        const int MaxFieldCount = 50;
        int depth = 0, maxDepth = 0, fieldCount = 0;
        for (int i = 0; i < queryText.Length; i++)
        {
            var ch = queryText[i];
            if (ch == '{') { depth++; if (depth > maxDepth) maxDepth = depth; }
            else if (ch == '}') { depth--; }
            else if (char.IsLetter(ch))
            {
                fieldCount++;
                while (i + 1 < queryText.Length && char.IsLetterOrDigit(queryText[i + 1])) i++;
            }
        }
        if (maxDepth > MaxQueryDepth)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync($"{{\"errors\":[{{\"message\":\"Query depth {maxDepth} exceeds maximum of {MaxQueryDepth}.\"}}]}}");
            return;
        }
        if (fieldCount > MaxFieldCount)
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync($"{{\"errors\":[{{\"message\":\"Query field count {fieldCount} exceeds maximum of {MaxFieldCount}.\"}}]}}");
            return;
        }

        // Introspection shortcut — require authentication to prevent schema disclosure
        if (queryText.Contains("__schema"))
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted);
            if (user == null)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("{\"errors\":[{\"message\":\"Authentication required for introspection.\"}]}");
                return;
            }

            await using var writer = new Utf8JsonWriter(context.Response.Body);
            writer.WriteStartObject();
            writer.WritePropertyName("data");
            WriteIntrospectionSchema(writer);
            writer.WriteEndObject();
            await writer.FlushAsync(context.RequestAborted);
            return;
        }

        // Parse simple query { fieldName(args) { subfields } }
        try
        {
            var result = await ExecuteQuery(queryText, variables, context.RequestAborted);
            await using var writer = new Utf8JsonWriter(context.Response.Body);
            writer.WriteStartObject();
            writer.WritePropertyName("data");
            WriteJsonValue(writer, result);
            writer.WriteEndObject();
            await writer.FlushAsync(context.RequestAborted);
        }
        catch (Exception ex)
        {
            context.Response.StatusCode = 400;
            await using var writer = new Utf8JsonWriter(context.Response.Body);
            writer.WriteStartObject();
            writer.WriteStartArray("errors");
            writer.WriteStartObject();
            writer.WriteString("message", "An error occurred processing the query.");
            writer.WriteEndObject();
            writer.WriteEndArray();
            writer.WriteEndObject();
            await writer.FlushAsync(context.RequestAborted);
        }
    }

    private static async ValueTask<Dictionary<string, object?>> ExecuteQuery(string query, JsonElement variables, CancellationToken ct)
    {
        var result = new Dictionary<string, object?>();

        // Strip outer "query { ... }" or "{ ... }"
        var body = query.Trim();
        if (body.StartsWith("query", StringComparison.OrdinalIgnoreCase))
        {
            var braceIdx = body.IndexOf('{');
            if (braceIdx >= 0) body = body[(braceIdx + 1)..];
        }
        else if (body.StartsWith('{'))
        {
            body = body[1..];
        }
        if (body.EndsWith('}')) body = body[..^1];

        // Parse top-level fields: fieldName(args) { subfields }
        var pos = 0;
        while (pos < body.Length)
        {
            SkipWhitespace(body, ref pos);
            if (pos >= body.Length) break;

            var fieldName = ReadIdentifier(body, ref pos);
            if (string.IsNullOrEmpty(fieldName)) break;

            // Parse optional arguments
            var args = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            SkipWhitespace(body, ref pos);
            if (pos < body.Length && body[pos] == '(')
            {
                pos++; // skip (
                while (pos < body.Length && body[pos] != ')')
                {
                    SkipWhitespace(body, ref pos);
                    var argName = ReadIdentifier(body, ref pos);
                    SkipWhitespace(body, ref pos);
                    if (pos < body.Length && body[pos] == ':') pos++;
                    SkipWhitespace(body, ref pos);
                    var argVal = ReadValue(body, ref pos, variables);
                    if (!string.IsNullOrEmpty(argName)) args[argName] = argVal;
                    SkipWhitespace(body, ref pos);
                    if (pos < body.Length && body[pos] == ',') pos++;
                }
                if (pos < body.Length && body[pos] == ')') pos++;
            }

            // Parse selected fields
            var selectedFields = new List<string>();
            SkipWhitespace(body, ref pos);
            if (pos < body.Length && body[pos] == '{')
            {
                pos++;
                while (pos < body.Length && body[pos] != '}')
                {
                    SkipWhitespace(body, ref pos);
                    var sf = ReadIdentifier(body, ref pos);
                    if (!string.IsNullOrEmpty(sf)) selectedFields.Add(sf);
                    SkipWhitespace(body, ref pos);
                    if (pos < body.Length && body[pos] == ',') pos++;
                }
                if (pos < body.Length && body[pos] == '}') pos++;
            }

            // Resolve entity
            var isList = fieldName.EndsWith("List", StringComparison.OrdinalIgnoreCase);
            var slug = isList ? fieldName[..^4] : fieldName;

            // Try slug directly, then PascalCase → slug conversion
            if (!DataScaffold.TryGetEntity(slug, out var meta))
            {
                // Convert PascalCase to kebab-case
                var kebab = ToKebab(slug);
                if (!DataScaffold.TryGetEntity(kebab, out meta))
                    throw new InvalidOperationException($"Unknown field: {fieldName}");
            }

            if (isList)
            {
                // List query
                var qd = new QueryDefinition();
                if (args.TryGetValue("take", out var take) && int.TryParse(take, out var t)) qd.Top = t;
                if (args.TryGetValue("skip", out var skip) && int.TryParse(skip, out var s)) qd.Skip = s;
                if (args.TryGetValue("sort", out var sort)) qd.Sorts.Add(new SortClause { Field = sort });
                // Filter args become equality clauses
                foreach (var kv in args)
                {
                    if (kv.Key is "take" or "skip" or "sort") continue;
                    qd.Clauses.Add(new QueryClause { Field = kv.Key, Operator = QueryOperator.Equals, Value = kv.Value });
                }
                var items = await meta!.Handlers.QueryAsync(qd, ct);
                var list = new List<Dictionary<string, object?>>();
                foreach (var item in items)
                    list.Add(ProjectItem(meta, item, selectedFields));
                result[fieldName] = list;
            }
            else
            {
                // Single item
                if (args.TryGetValue("id", out var idStr) && uint.TryParse(idStr, out var id))
                {
                    var item = await meta!.Handlers.LoadAsync(id, ct);
                    result[fieldName] = item != null ? ProjectItem(meta, item, selectedFields) : null;
                }
                else
                {
                    throw new InvalidOperationException($"Single-item query '{fieldName}' requires an 'id' argument.");
                }
            }
        }

        return result;
    }

    private static Dictionary<string, object?> ProjectItem(DataEntityMetadata meta, object item, List<string> selectedFields)
    {
        var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

        // Always include id if requested or no selection
        bool hasIdField = false;
        foreach (var sf in selectedFields)
        {
            if (sf.Equals("id", StringComparison.OrdinalIgnoreCase))
            {
                hasIdField = true;
                break;
            }
        }
        if (selectedFields.Count == 0 || hasIdField)
        {
            if (item is BaseDataObject bdo) row["id"] = bdo.Key;
        }

        foreach (var f in meta.Fields)
        {
            var camel = ToCamel(f.Name);
            if (selectedFields.Count > 0)
            {
                bool fieldSelected = false;
                foreach (var s in selectedFields)
                {
                    if (s.Equals(camel, StringComparison.OrdinalIgnoreCase)
                        || s.Equals(f.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        fieldSelected = true;
                        break;
                    }
                }
                if (!fieldSelected) continue;
            }

            try { row[camel] = f.GetValueFn(item)?.ToString(); }
            catch (Exception) { row[camel] = null; }
        }

        return row;
    }

    // ── JSON writing helpers ─────────────────────────────────────────────

    private static void WriteJsonValue(Utf8JsonWriter writer, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNullValue();
                break;
            case Dictionary<string, object?> dict:
                writer.WriteStartObject();
                foreach (var kv in dict)
                {
                    writer.WritePropertyName(kv.Key);
                    WriteJsonValue(writer, kv.Value);
                }
                writer.WriteEndObject();
                break;
            case IList list:
                writer.WriteStartArray();
                foreach (var item in list)
                    WriteJsonValue(writer, item);
                writer.WriteEndArray();
                break;
            case string s:
                writer.WriteStringValue(s);
                break;
            case uint u:
                writer.WriteNumberValue(u);
                break;
            case int i:
                writer.WriteNumberValue(i);
                break;
            case long l:
                writer.WriteNumberValue(l);
                break;
            case double d:
                writer.WriteNumberValue(d);
                break;
            case decimal m:
                writer.WriteNumberValue(m);
                break;
            case bool b:
                writer.WriteBooleanValue(b);
                break;
            default:
                writer.WriteStringValue(value.ToString());
                break;
        }
    }

    // ── Parsing helpers ───────────────────────────────────────────────────

    private static void SkipWhitespace(string s, ref int pos)
    {
        while (pos < s.Length && char.IsWhiteSpace(s[pos])) pos++;
    }

    private static string ReadIdentifier(string s, ref int pos)
    {
        var start = pos;
        while (pos < s.Length && (char.IsLetterOrDigit(s[pos]) || s[pos] == '_')) pos++;
        return s[start..pos];
    }

    private static string ReadValue(string s, ref int pos, JsonElement variables)
    {
        SkipWhitespace(s, ref pos);
        if (pos >= s.Length) return "";

        // Variable reference $varName
        if (s[pos] == '$')
        {
            pos++;
            var varName = ReadIdentifier(s, ref pos);
            if (variables.ValueKind == JsonValueKind.Object && variables.TryGetProperty(varName, out var v))
                return v.ToString();
            return "";
        }

        // Quoted string
        if (s[pos] == '"')
        {
            pos++;
            var sb = new StringBuilder(64);
            while (pos < s.Length && s[pos] != '"')
            {
                if (s[pos] == '\\' && pos + 1 < s.Length) { pos++; sb.Append(s[pos]); pos++; }
                else { sb.Append(s[pos]); pos++; }
            }
            if (pos < s.Length) pos++; // skip closing quote
            return sb.ToString();
        }

        // Bare number/word
        var start = pos;
        while (pos < s.Length && !char.IsWhiteSpace(s[pos]) && s[pos] != ')' && s[pos] != ',' && s[pos] != '}') pos++;
        return s[start..pos];
    }

    // ── Name conversion helpers ───────────────────────────────────────────

    private static string ToCamel(string name)
    {
        if (string.IsNullOrEmpty(name)) return name;
        return char.ToLowerInvariant(name[0]) + name[1..];
    }

    private static string ToPascal(string slug)
    {
        if (string.IsNullOrEmpty(slug)) return slug;
        var sb = new StringBuilder(slug.Length);
        bool upper = true;
        foreach (var c in slug)
        {
            if (c == '-' || c == '_') { upper = true; continue; }
            sb.Append(upper ? char.ToUpperInvariant(c) : c);
            upper = false;
        }
        return sb.ToString();
    }

    private static string ToKebab(string pascalCase)
    {
        if (string.IsNullOrEmpty(pascalCase)) return pascalCase;
        var sb = new StringBuilder(pascalCase.Length + 4);
        for (int i = 0; i < pascalCase.Length; i++)
        {
            if (char.IsUpper(pascalCase[i]) && i > 0) sb.Append('-');
            sb.Append(char.ToLowerInvariant(pascalCase[i]));
        }
        return sb.ToString();
    }
}
