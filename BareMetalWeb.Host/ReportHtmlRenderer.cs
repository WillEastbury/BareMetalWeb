using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

/// <summary>
/// Helper utilities for report parameter resolution.
/// </summary>
public static class ReportHtmlRenderer
{
    /// <summary>
    /// Resolves distinct values for a dynamic dropdown parameter.
    /// FieldSource format: "entitySlug.fieldName"
    /// </summary>
    internal static IReadOnlyList<string> ResolveDistinctValues(string fieldSource)
    {
        var dot = fieldSource.IndexOf('.');
        if (dot < 0) return Array.Empty<string>();

        var entitySlug = fieldSource[..dot];
        var fieldName = fieldSource[(dot + 1)..];

        if (!BareMetalWeb.Core.DataScaffold.TryGetEntity(entitySlug, out var meta))
            return Array.Empty<string>();

        BareMetalWeb.Core.DataFieldMetadata? field = null;
        foreach (var f in meta.Fields)
        {
            if (string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase))
            {
                field = f;
                break;
            }
        }
        if (field == null) return Array.Empty<string>();

        var getter = field.GetValueFn;
        if (getter == null) return Array.Empty<string>();

        // Use capped query to avoid loading entire table; async-safe via Task.Run
        var distinct = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        var queryDef = new BareMetalWeb.Data.QueryDefinition { Top = 10000 };
        // TODO: convert to async
        var allItems = Task.Run(async () => await meta.Handlers.QueryAsync(queryDef, CancellationToken.None)).GetAwaiter().GetResult();
        foreach (var item in allItems)
        {
            var val = getter(item);
            if (val != null)
            {
                var str = val.ToString();
                if (!string.IsNullOrWhiteSpace(str))
                    distinct.Add(str);
            }
        }

        var distinctArray = new string[distinct.Count];
        distinct.CopyTo(distinctArray);
        return distinctArray;
    }
}
