using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace BareMetalWeb.Data;

/// <summary>
/// Simple JSON-file-based storage for virtual entity instances.
/// Each instance is stored as a UTF-8 JSON file at
/// <c>{rootPath}/virtual/{entityTypeName}/{id}.json</c>.
/// </summary>
/// <remarks>
/// Deprecated: use <see cref="WalDataProvider"/> with <see cref="DataRecord"/> instead.
/// This class is retained for backward compatibility during migration.
/// </remarks>
[Obsolete("Use WalDataProvider with DataRecord instead. Will be removed in a future release.")]
public sealed class VirtualEntityJsonStore
{
    private readonly string _rootPath;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    public VirtualEntityJsonStore(string rootPath)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
            throw new ArgumentException("Root path cannot be null or whitespace.", nameof(rootPath));
        _rootPath = rootPath;
    }

    // ── Storage helpers ──────────────────────────────────────────────────────

    private string GetEntityFolder(string entityTypeName)
        => Path.Combine(_rootPath, "virtual", SanitizeName(entityTypeName));

    private string GetFilePath(string entityTypeName, uint key)
        => Path.Combine(GetEntityFolder(entityTypeName), key.ToString() + ".json");

    private static string SanitizeName(string name)
    {
        if (string.IsNullOrEmpty(name))
            return "_empty";
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name;
    }

    // ── CRUD ─────────────────────────────────────────────────────────────────

    public async ValueTask SaveAsync(string entityTypeName, DynamicDataObject obj, CancellationToken cancellationToken = default)
    {
        var folder = GetEntityFolder(entityTypeName);
        Directory.CreateDirectory(folder);
        var json = JsonSerializer.Serialize(obj, JsonOptions);
        await File.WriteAllTextAsync(GetFilePath(entityTypeName, obj.Key), json, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<DynamicDataObject?> LoadAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default)
    {
        var filePath = GetFilePath(entityTypeName, key);
        if (!File.Exists(filePath))
            return null;

        var json = await File.ReadAllTextAsync(filePath, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<DynamicDataObject>(json);
    }

    public ValueTask DeleteAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default)
    {
        var filePath = GetFilePath(entityTypeName, key);
        if (File.Exists(filePath))
            File.Delete(filePath);
        return ValueTask.CompletedTask;
    }

    public async ValueTask<IEnumerable<DynamicDataObject>> QueryAsync(
        string entityTypeName,
        QueryDefinition? query,
        CancellationToken cancellationToken = default)
    {
        var folder = GetEntityFolder(entityTypeName);
        if (!Directory.Exists(folder))
            return Array.Empty<DynamicDataObject>();

        var files = Directory.GetFiles(folder, "*.json");
        var results = new List<DynamicDataObject>(files.Length);

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var json = await File.ReadAllTextAsync(file, cancellationToken).ConfigureAwait(false);
                var obj = JsonSerializer.Deserialize<DynamicDataObject>(json);
                if (obj != null && Matches(obj, query))
                    results.Add(obj);
            }
            catch
            {
                // Skip corrupt or unreadable files
            }
        }

        // Apply sorting
        if (query?.Sorts is { Count: > 0 })
            results = ApplySorts(results, query);

        // Apply skip / top
        var skip = Math.Max(0, query?.Skip ?? 0);
        var top = query?.Top ?? int.MaxValue;
        if (top <= 0)
            return Array.Empty<DynamicDataObject>();

        return (skip > 0 || top < int.MaxValue)
            ? results.Skip(skip).Take(top).ToList()
            : results;
    }

    public async ValueTask<int> CountAsync(string entityTypeName, QueryDefinition? query, CancellationToken cancellationToken = default)
    {
        var folder = GetEntityFolder(entityTypeName);
        if (!Directory.Exists(folder))
            return 0;

        var files = Directory.GetFiles(folder, "*.json");
        if (query == null)
            return files.Length;

        // Apply filter to get accurate count
        var results = await QueryAsync(entityTypeName, query, cancellationToken).ConfigureAwait(false);
        return results is ICollection<DynamicDataObject> col ? col.Count : results.Count();
    }

    // ── Query helpers ─────────────────────────────────────────────────────────

    private static bool Matches(DynamicDataObject obj, QueryDefinition? query)
    {
        if (query == null)
            return true;

        return EvaluateGroup(obj, query.Clauses, query.Groups, query.Logic);
    }

    private static bool EvaluateGroup(
        DynamicDataObject obj,
        IReadOnlyList<QueryClause> clauses,
        IReadOnlyList<QueryGroup> groups,
        QueryGroupLogic logic)
    {
        if (logic == QueryGroupLogic.And)
        {
            foreach (var c in clauses)
                if (!EvaluateClause(obj, c)) return false;
            foreach (var g in groups)
                if (!EvaluateGroup(obj, g.Clauses, g.Groups, g.Logic)) return false;
            return true;
        }

        // Or
        foreach (var c in clauses)
            if (EvaluateClause(obj, c)) return true;
        foreach (var g in groups)
            if (EvaluateGroup(obj, g.Clauses, g.Groups, g.Logic)) return true;

        return false;
    }

    private static bool EvaluateClause(DynamicDataObject obj, QueryClause clause)
    {
        var value = ResolveField(obj, clause.Field);
        var target = clause.Value?.ToString() ?? string.Empty;

        return clause.Operator switch
        {
            QueryOperator.Contains => value != null && value.Contains(target, StringComparison.OrdinalIgnoreCase),
            QueryOperator.StartsWith => value != null && value.StartsWith(target, StringComparison.OrdinalIgnoreCase),
            QueryOperator.EndsWith => value != null && value.EndsWith(target, StringComparison.OrdinalIgnoreCase),
            QueryOperator.Equals => string.Equals(value, target, StringComparison.OrdinalIgnoreCase),
            QueryOperator.NotEquals => !string.Equals(value, target, StringComparison.OrdinalIgnoreCase),
            QueryOperator.GreaterThan => CompareValues(value, target) > 0,
            QueryOperator.LessThan => CompareValues(value, target) < 0,
            QueryOperator.GreaterThanOrEqual => CompareValues(value, target) >= 0,
            QueryOperator.LessThanOrEqual => CompareValues(value, target) <= 0,
            QueryOperator.In => IsInList(value, target),
            QueryOperator.NotIn => !IsInList(value, target),
            _ => true
        };
    }

    private static string? ResolveField(DynamicDataObject obj, string field)
    {
        if (string.IsNullOrWhiteSpace(field))
            return null;

        return field.ToLowerInvariant() switch
        {
            "id" => obj.Key.ToString(),
            "createdby" => obj.CreatedBy,
            "updatedby" => obj.UpdatedBy,
            "createdonutc" => obj.CreatedOnUtc.ToString("O"),
            "updatedonutc" => obj.UpdatedOnUtc.ToString("O"),
            _ => obj.GetField(field)
        };
    }

    private static int CompareValues(string? a, string? b)
    {
        if (decimal.TryParse(a, out var aNum) && decimal.TryParse(b, out var bNum))
            return aNum.CompareTo(bNum);
        if (DateTime.TryParse(a, out var aDate) && DateTime.TryParse(b, out var bDate))
            return aDate.CompareTo(bDate);
        return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsInList(string? value, string rawList)
    {
        if (value == null) return false;
        var items = rawList.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return items.Any(item => string.Equals(item.Trim('"', '\''), value, StringComparison.OrdinalIgnoreCase));
    }

    private static List<DynamicDataObject> ApplySorts(List<DynamicDataObject> items, QueryDefinition query)
    {
        if (query.Sorts.Count == 0)
            return items;

        IOrderedEnumerable<DynamicDataObject>? ordered = null;
        foreach (var sort in query.Sorts)
        {
            var field = sort.Field;
            var asc = sort.Direction == SortDirection.Asc;
            if (ordered == null)
            {
                ordered = asc
                    ? items.OrderBy(o => ResolveField(o, field), StringComparer.OrdinalIgnoreCase)
                    : items.OrderByDescending(o => ResolveField(o, field), StringComparer.OrdinalIgnoreCase);
            }
            else
            {
                ordered = asc
                    ? ordered.ThenBy(o => ResolveField(o, field), StringComparer.OrdinalIgnoreCase)
                    : ordered.ThenByDescending(o => ResolveField(o, field), StringComparer.OrdinalIgnoreCase);
            }
        }

        return ordered?.ToList() ?? items;
    }
}
