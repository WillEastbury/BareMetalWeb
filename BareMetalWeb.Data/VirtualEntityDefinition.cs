using System.Collections.Generic;

namespace BareMetalWeb.Data;

/// <summary>
/// Root container for virtual entity definitions loaded from JSON metadata.
/// Parsed manually via JsonDocument — no attribute-based serialization.
/// </summary>
public sealed class VirtualEntitiesRoot
{
    public List<VirtualEntityDef> VirtualEntities { get; set; } = new();
}

/// <summary>
/// Defines a virtual entity — a runtime-defined data entity type backed by JSON metadata
/// rather than a compiled C# class.
/// </summary>
public sealed class VirtualEntityDef
{
    /// <summary>Stable GUID for this entity. Used for migration tracking. Generate once and keep.</summary>
    public string EntityId { get; set; } = Guid.NewGuid().ToString("D");

    /// <summary>Display name (e.g. "Ticket").</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>URL slug override. If omitted, derived from Name.</summary>
    public string? Slug { get; set; }

    /// <summary>Show this entity in the navigation menu.</summary>
    public bool ShowOnNav { get; set; } = false;

    /// <summary>Permissions string (comma-separated roles). Defaults to entity name.</summary>
    public string? Permissions { get; set; }

    /// <summary>ID generation strategy: "guid" (default), "sequential", or "none".</summary>
    public string IdStrategy { get; set; } = "guid";

    /// <summary>Navigation group (default: "Admin").</summary>
    public string NavGroup { get; set; } = "Admin";

    /// <summary>Navigation order within the group.</summary>
    public int NavOrder { get; set; } = 0;

    /// <summary>View type for list rendering: "table" (default), "treeview", "orgchart", "timeline", "timetable".</summary>
    public string? ViewType { get; set; }

    /// <summary>Field name used as the parent reference for tree/org chart views.</summary>
    public string? ParentField { get; set; }

    /// <summary>Field definitions for this entity.</summary>
    public List<VirtualFieldDef> Fields { get; set; } = new();
}

/// <summary>
/// Defines a single field on a virtual entity.
/// </summary>
public sealed class VirtualFieldDef
{
    /// <summary>Stable GUID for this field. Used for migration/rename tracking. Generate once and keep.</summary>
    public string FieldId { get; set; } = Guid.NewGuid().ToString("D");

    /// <summary>Field name (used as property name and form field name).</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Display label override. Derived from Name if omitted.</summary>
    public string? Label { get; set; }

    /// <summary>
    /// Field data type. Supported values: "string", "multiline", "textarea", "bool", "boolean", "yesno",
    /// "int", "integer", "decimal", "number", "datetime", "date", "time", "enum", "lookup",
    /// "email", "phone", "url".
    /// </summary>
    public string Type { get; set; } = "string";

    /// <summary>Whether the field is required.</summary>
    public bool Required { get; set; } = false;

    /// <summary>Render as multi-line textarea (only applies to "string" type).</summary>
    public bool Multiline { get; set; } = false;

    /// <summary>Whether the field allows null values (affects CLR type).</summary>
    public bool Nullable { get; set; } = true;

    /// <summary>Enum values (required when type = "enum").</summary>
    public List<string>? Values { get; set; }

    /// <summary>Target entity slug for lookup fields (required when type = "lookup").</summary>
    public string? LookupEntity { get; set; }

    /// <summary>Value field on the target entity (default: "Id").</summary>
    public string? LookupValueField { get; set; }

    /// <summary>Display field on the target entity (default: "Id").</summary>
    public string? LookupDisplayField { get; set; }

    /// <summary>Query field used to filter lookup results (e.g. "Id" to exclude current record).</summary>
    public string? LookupQueryField { get; set; }

    /// <summary>Query operator for lookup filtering: "equals", "notequals", "contains", etc.</summary>
    public string? LookupQueryOperator { get; set; }

    /// <summary>Display order in forms and list views.</summary>
    public int Order { get; set; } = 0;

    /// <summary>Show in list (table) views.</summary>
    public bool List { get; set; } = true;

    /// <summary>Show in detail/view pages.</summary>
    public bool View { get; set; } = true;

    /// <summary>Show in edit forms.</summary>
    public bool Edit { get; set; } = true;

    /// <summary>Show in create forms.</summary>
    public bool Create { get; set; } = true;

    /// <summary>Render as read-only.</summary>
    public bool ReadOnly { get; set; } = false;

    /// <summary>Placeholder text for the input.</summary>
    public string? Placeholder { get; set; }

    /// <summary>Minimum string length validation.</summary>
    public int? MinLength { get; set; }

    /// <summary>Maximum string length validation.</summary>
    public int? MaxLength { get; set; }

    /// <summary>Minimum numeric range validation.</summary>
    public double? RangeMin { get; set; }

    /// <summary>Maximum numeric range validation.</summary>
    public double? RangeMax { get; set; }

    /// <summary>Regex pattern validation.</summary>
    public string? Pattern { get; set; }
}
