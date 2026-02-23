using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted schema definition for a single field on a runtime-managed entity.
/// </summary>
[DataEntity("Field Definitions", ShowOnNav = true, NavGroup = "System", NavOrder = 1001)]
public class FieldDefinition : RenderableDataObject
{
    /// <summary>Stable GUID identity that survives renames. Defaults to Id.</summary>
    [DataField(Label = "Field ID", Order = 1, ReadOnly = true)]
    public string FieldId { get; set; } = string.Empty;

    /// <summary>Foreign key to <see cref="EntityDefinition.Id"/>.</summary>
    [DataField(Label = "Entity ID", Order = 2, Required = true)]
    [DataLookup(typeof(EntityDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string EntityId { get; set; } = string.Empty;

    [DataField(Label = "Name", Order = 3, Required = true)]
    public string Name { get; set; } = string.Empty;

    /// <summary>Display label override. Derived from Name via DeCamelcase if empty.</summary>
    [DataField(Label = "Label", Order = 4)]
    public string? Label { get; set; }

    /// <summary>
    /// Storage ordinal — assigned deterministically at compile time.
    /// Stable across renames. Used by storage to locate field data.
    /// </summary>
    [DataField(Label = "Ordinal", Order = 5, ReadOnly = true)]
    public int Ordinal { get; set; } = 0;

    /// <summary>
    /// Field type string. Supported: string, multiline, textarea, bool, boolean,
    /// int, integer, decimal, number, datetime, date, dateonly, time, timeonly,
    /// enum, lookup, email, phone, url.
    /// </summary>
    [DataField(Label = "Type", Order = 6, Required = true)]
    public string Type { get; set; } = "string";

    [DataField(Label = "Nullable", Order = 7)]
    public bool IsNullable { get; set; } = true;

    [DataField(Label = "Required", Order = 8)]
    public bool Required { get; set; } = false;

    [DataField(Label = "Show in List", Order = 9)]
    public bool List { get; set; } = true;

    [DataField(Label = "Show in View", Order = 10)]
    public bool View { get; set; } = true;

    [DataField(Label = "Show in Edit", Order = 11)]
    public bool Edit { get; set; } = true;

    [DataField(Label = "Show in Create", Order = 12)]
    public bool Create { get; set; } = true;

    [DataField(Label = "Read Only", Order = 13)]
    public bool ReadOnly { get; set; } = false;

    [DataField(Label = "Default Value", Order = 14)]
    public string? DefaultValue { get; set; }

    [DataField(Label = "Placeholder", Order = 15)]
    public string? Placeholder { get; set; }

    /// <summary>Minimum string length validation rule.</summary>
    [DataField(Label = "Min Length", Order = 16)]
    public int? MinLength { get; set; }

    /// <summary>Maximum string length validation rule.</summary>
    [DataField(Label = "Max Length", Order = 17)]
    public int? MaxLength { get; set; }

    /// <summary>Minimum numeric range validation rule.</summary>
    [DataField(Label = "Range Min", Order = 18)]
    public double? RangeMin { get; set; }

    /// <summary>Maximum numeric range validation rule.</summary>
    [DataField(Label = "Range Max", Order = 19)]
    public double? RangeMax { get; set; }

    /// <summary>Regex pattern validation rule.</summary>
    [DataField(Label = "Pattern", Order = 20)]
    public string? Pattern { get; set; }

    /// <summary>Pipe-separated enum member names, e.g. "Low|Medium|High|Critical".</summary>
    [DataField(Label = "Enum Values (pipe-separated)", Order = 21)]
    public string? EnumValues { get; set; }

    /// <summary>Slug of the target entity for lookup fields.</summary>
    [DataField(Label = "Lookup Entity Slug", Order = 22)]
    public string? LookupEntitySlug { get; set; }

    [DataField(Label = "Lookup Value Field", Order = 23)]
    public string? LookupValueField { get; set; }

    [DataField(Label = "Lookup Display Field", Order = 24)]
    public string? LookupDisplayField { get; set; }

    /// <summary>Render as multiline textarea (for string fields).</summary>
    [DataField(Label = "Multiline", Order = 25)]
    public bool Multiline { get; set; } = false;

    public override string ToString() => $"{Name} ({Type})";
}
