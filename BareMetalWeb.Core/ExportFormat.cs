using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Core;

/// <summary>
/// Export format options for entity data export
/// </summary>
public enum ExportFormat
{
    /// <summary>
    /// Simple CSV with top-level fields only (current default)
    /// </summary>
    SimpleCSV,
    
    /// <summary>
    /// Flat CSV with parent fields repeated for each child row (denormalized)
    /// </summary>
    FlatCSV,
    
    /// <summary>
    /// ZIP archive containing separate CSV files for parent and child entities
    /// </summary>
    MultiSheetZip,
    
    /// <summary>
    /// Hierarchical JSON with nested child arrays
    /// </summary>
    HierarchicalJSON
}

/// <summary>
/// Configuration options for data export
/// </summary>
public sealed class ExportOptions
{
    /// <summary>
    /// Export format to use
    /// </summary>
    public ExportFormat Format { get; set; } = ExportFormat.SimpleCSV;
    
    /// <summary>
    /// Maximum depth of nested components to include (default 1 level)
    /// </summary>
    public int MaxDepth { get; set; } = 1;
    
    /// <summary>
    /// Field names of nested components to include (null = all)
    /// </summary>
    public HashSet<string>? IncludeNestedComponents { get; set; }
    
    /// <summary>
    /// Whether to include nested components at all
    /// </summary>
    public bool IncludeNested { get; set; } = true;

    /// <summary>
    /// Parse export options from query string
    /// </summary>
    public static ExportOptions FromQuery(IQueryCollection query)
    {
        var options = new ExportOptions();
        
        if (query.TryGetValue("format", out var formatValue))
        {
            if (Enum.TryParse<ExportFormat>(formatValue.ToString(), true, out var format))
                options.Format = format;
        }
        
        if (query.TryGetValue("depth", out var depthValue))
        {
            if (int.TryParse(depthValue.ToString(), out var depth) && depth >= 0 && depth <= 10)
                options.MaxDepth = depth;
        }
        
        if (query.TryGetValue("includeNested", out var includeValue))
        {
            if (bool.TryParse(includeValue.ToString(), out var include))
                options.IncludeNested = include;
        }
        
        if (query.TryGetValue("components", out var componentsValue))
        {
            var componentList = componentsValue.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (componentList.Length > 0)
                options.IncludeNestedComponents = new HashSet<string>(componentList, StringComparer.OrdinalIgnoreCase);
        }
        
        return options;
    }
}
