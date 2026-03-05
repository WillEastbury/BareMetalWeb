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
    [Description("List all fields for an entity by slug, showing name, type, and whether it's indexed. Use this to know which fields can be filtered/sorted.")]
    public static FieldQueryInfo[]? ListEntityFields(string entitySlug)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta)) return null;

        var result = new FieldQueryInfo[meta.Fields.Count];
        for (int i = 0; i < meta.Fields.Count; i++)
        {
            var f = meta.Fields[i];
            result[i] = new FieldQueryInfo(f.Name, f.FieldType.ToString(), f.IsIndexed);
        }
        return result;
    }

    [Description("Get valid query operators (Equals, NotEquals, Contains, StartsWith, EndsWith, In, NotIn, GreaterThan, LessThan, etc.).")]
    public static string[] GetOperators()
    {
        return Enum.GetNames<QueryOperator>();
    }

    [Description("Query an entity by slug with optional filter clauses, sort field, sort direction, and pagination (top/skip). Returns matching records as field-value dictionaries.")]
    public static async Task<QueryResultInfo> QueryEntities(
        string entitySlug,
        QueryClauseInput[]? filters = null,
        string? sortField = null,
        bool sortDescending = false,
        int top = 50,
        int skip = 0)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta))
            return new QueryResultInfo(0, [], $"Entity '{entitySlug}' not found.");

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
                catch { dict[field.Name] = null; }
            }
            rowsList.Add(dict);
        }
        var rows = rowsList.ToArray();

        return new QueryResultInfo(rows.Length, rows, null);
    }

    [Description("Count entities matching optional filter clauses. Faster than QueryEntities when you only need the count.")]
    public static async Task<int> CountEntities(
        string entitySlug,
        QueryClauseInput[]? filters = null)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta)) return -1;

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

    [Description("Load a single entity record by its uint key. Returns field-value dictionary or null if not found.")]
    public static async Task<Dictionary<string, object?>?> LoadEntity(string entitySlug, uint key)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta)) return null;

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
            catch { dict[field.Name] = null; }
        }
        return dict;
    }
}

// ── DTOs ──

public sealed record FieldQueryInfo(string Name, string Type, bool Indexed);

public sealed record QueryClauseInput(string Field, string Operator, string? Value);

public sealed record QueryResultInfo(int Count, Dictionary<string, object?>[] Rows, string? Error);
