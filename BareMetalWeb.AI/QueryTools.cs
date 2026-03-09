using System.ComponentModel;
using BareMetalWeb.Core;
using BareMetalWeb.Data;

namespace BareMetalWeb.AI;

/// <summary>
/// AI tools for querying entities via natural language.
/// The Copilot agent calls these to translate user questions into structured queries.
/// </summary>
public static class QueryTools
{
    [Description("Search entity records by name or text. Matches against all string fields. Use this when you have a name or text to find instead of a numeric ID. Entity slug is flexible.")]
    public static async Task<QueryResultInfo> SearchByName(
        string entitySlug,
        string searchText,
        int top = 10)
    {
        var meta = ResolveEntity(entitySlug);
        if (meta == null)
            return new QueryResultInfo(0, [], $"Entity '{entitySlug}' not found. Available entities: {string.Join(", ", DataScaffold.Entities?.Select(e => e.Slug) ?? [])}.");

        var items = await meta.Handlers.QueryAsync(null, CancellationToken.None)
            .ConfigureAwait(false);

        var layout = EntityLayoutCompiler.GetOrCompile(meta);
        var stringFields = layout.Fields.Where(f => f.ClrType == typeof(string)).ToArray();

        var matches = new List<Dictionary<string, object?>>();
        foreach (var entity in items)
        {
            bool matched = false;
            foreach (var field in stringFields)
            {
                try
                {
                    var val = field.Getter(entity)?.ToString();
                    if (val != null && val.Contains(searchText, StringComparison.OrdinalIgnoreCase))
                    {
                        matched = true;
                        break;
                    }
                }
                catch { }
            }

            if (matched)
            {
                var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Key"] = entity.Key
                };
                foreach (var field in layout.Fields)
                {
                    try { dict[field.Name] = field.Getter(entity); }
                    catch { dict[field.Name] = null; }
                }
                matches.Add(dict);
                if (matches.Count >= top) break;
            }
        }

        return new QueryResultInfo(matches.Count, matches.ToArray(), null);
    }

    [Description("List all fields for an entity by slug. Entity slug is flexible — accepts singular forms, abbreviations, and partial names.")]
    public static FieldQueryInfo[]? ListEntityFields(string entitySlug)
    {
        var meta = ResolveEntity(entitySlug);
        if (meta == null) return null;

        var result = new FieldQueryInfo[meta.Fields.Count];
        for (int i = 0; i < meta.Fields.Count; i++)
        {
            var f = meta.Fields[i];
            result[i] = new FieldQueryInfo(f.Name, f.FieldType.ToString(), f.IsIndexed);
        }
        return result;
    }

    /// <summary>
    /// Resolves an entity by exact slug/name, singular→plural, plural→singular,
    /// or prefix/substring match.
    /// </summary>
    private static DataEntityMetadata? ResolveEntity(string input)
    {
        // Exact match first
        if (DataScaffold.TryGetEntity(input, out var exact)) return exact;

        var entities = DataScaffold.Entities;
        if (entities is null || entities.Count == 0) return null;

        // Exact name match
        foreach (var e in entities)
            if (string.Equals(e.Name, input, StringComparison.OrdinalIgnoreCase)) return e;

        // Singular → plural
        var plural = input + "s";
        if (DataScaffold.TryGetEntity(plural, out var p)) return p;
        foreach (var e in entities)
            if (string.Equals(e.Name, plural, StringComparison.OrdinalIgnoreCase)) return e;

        // Plural → singular variants
        if (input.Length > 3 && input.EndsWith("ies", StringComparison.OrdinalIgnoreCase))
        {
            var s = input[..^3] + "y";
            if (DataScaffold.TryGetEntity(s, out var r)) return r;
        }
        else if (input.Length > 2 && input.EndsWith("es", StringComparison.OrdinalIgnoreCase))
        {
            var s = input[..^2];
            if (DataScaffold.TryGetEntity(s, out var r)) return r;
        }
        else if (input.Length > 1 && input.EndsWith('s'))
        {
            var s = input[..^1];
            if (DataScaffold.TryGetEntity(s, out var r)) return r;
        }

        // Prefix match
        foreach (var e in entities)
            if (e.Slug.StartsWith(input, StringComparison.OrdinalIgnoreCase) ||
                e.Name.StartsWith(input, StringComparison.OrdinalIgnoreCase)) return e;

        // Contains match
        foreach (var e in entities)
            if (e.Slug.Contains(input, StringComparison.OrdinalIgnoreCase) ||
                e.Name.Contains(input, StringComparison.OrdinalIgnoreCase)) return e;

        return null;
    }

    [Description("Get valid query operators (Equals, NotEquals, Contains, StartsWith, EndsWith, In, NotIn, GreaterThan, LessThan, etc.).")]
    public static string[] GetOperators()
    {
        return Enum.GetNames<QueryOperator>();
    }

    [Description("Query an entity by slug with optional filter clauses, sort field, sort direction, and pagination (top/skip). Returns matching records as field-value dictionaries. Entity slug is flexible — singular forms, abbreviations, and partial names are accepted.")]
    public static async Task<QueryResultInfo> QueryEntities(
        string entitySlug,
        QueryClauseInput[]? filters = null,
        string? sortField = null,
        bool sortDescending = false,
        int top = 50,
        int skip = 0)
    {
        var meta = ResolveEntity(entitySlug);
        if (meta == null)
            return new QueryResultInfo(0, [], $"Entity '{entitySlug}' not found. Available entities: {string.Join(", ", DataScaffold.Entities?.Select(e => e.Slug) ?? [])}.");

        var query = new QueryDefinition { Top = top, Skip = skip };

        if (!string.IsNullOrEmpty(sortField))
        {
            query.Sorts.Add(new SortClause
            {
                Field = sortField,
                Direction = sortDescending ? SortDirection.Desc : SortDirection.Asc
            });
        }

        if (filters is { Length: > 0 })
        {
            query.Clauses = new List<QueryClause>(filters.Length);
            foreach (var f in filters)
            {
                Enum.TryParse<QueryOperator>(f.Operator, ignoreCase: true, out var op);
                query.Clauses.Add(new QueryClause { Field = f.Field, Operator = op, Value = f.Value });
            }
        }

        var results = await meta.Handlers.QueryAsync(query, CancellationToken.None)
            .ConfigureAwait(false);

        var layout = EntityLayoutCompiler.GetOrCompile(meta);
        var rowsList = new List<Dictionary<string, object?>>();
        foreach (var entity in results)
        {
            var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["Key"] = entity.Key
            };
            foreach (var field in layout.Fields)
            {
                try { dict[field.Name] = field.Getter(entity); }
                catch (Exception) { dict[field.Name] = null; }
            }
            rowsList.Add(dict);
        }
        var rows = rowsList.ToArray();

        return new QueryResultInfo(rows.Length, rows, null);
    }

    [Description("Count entities matching optional filter clauses. Faster than QueryEntities when you only need the count. Entity slug is flexible.")]
    public static async Task<int> CountEntities(
        string entitySlug,
        QueryClauseInput[]? filters = null)
    {
        var meta = ResolveEntity(entitySlug);
        if (meta == null) return -1;

        QueryDefinition? query = null;
        if (filters is { Length: > 0 })
        {
            var clauses = new List<QueryClause>(filters.Length);
            foreach (var f in filters)
            {
                Enum.TryParse<QueryOperator>(f.Operator, ignoreCase: true, out var op);
                clauses.Add(new QueryClause { Field = f.Field, Operator = op, Value = f.Value });
            }
            query = new QueryDefinition
            {
                Clauses = clauses
            };
        }

        return await meta.Handlers.CountAsync(query, CancellationToken.None)
            .ConfigureAwait(false);
    }

    [Description("Load a single entity record by its uint key. Returns field-value dictionary or null if not found. Entity slug is flexible.")]
    public static async Task<Dictionary<string, object?>?> LoadEntity(string entitySlug, uint key)
    {
        var meta = ResolveEntity(entitySlug);
        if (meta == null) return null;

        var entity = await meta.Handlers.LoadAsync(key, CancellationToken.None)
            .ConfigureAwait(false);
        if (entity == null) return null;

        var layout = EntityLayoutCompiler.GetOrCompile(meta);
        var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["Key"] = entity.Key
        };
        foreach (var field in layout.Fields)
        {
            try { dict[field.Name] = field.Getter(entity); }
            catch (Exception) { dict[field.Name] = null; }
        }
        return dict;
    }
}

// ── DTOs ──

public sealed record FieldQueryInfo(string Name, string Type, bool Indexed);

public sealed record QueryClauseInput(string Field, string Operator, string? Value);

public sealed record QueryResultInfo(int Count, Dictionary<string, object?>[] Rows, string? Error);
