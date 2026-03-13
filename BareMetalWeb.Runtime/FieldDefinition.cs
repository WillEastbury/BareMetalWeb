using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted schema definition for a single field on a runtime-managed entity.
/// </summary>
[DataEntity("Field Definitions", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1001)]
public class FieldDefinition : BaseDataObject
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

    /// <summary>Slug of child entity for childlist fields (e.g. "order-rows").</summary>
    [DataField(Label = "Child Entity Slug", Order = 26)]
    public string? ChildEntitySlug { get; set; }

    /// <summary>Lookup copy-fields mapping for child entity lookup fields (e.g. "Price->UnitPrice").</summary>
    [DataField(Label = "Lookup Copy Fields", Order = 27)]
    public string? LookupCopyFields { get; set; }

    /// <summary>Calculated expression for child entity calculated fields (e.g. "Quantity * UnitPrice").</summary>
    [DataField(Label = "Calculated Expression", Order = 28)]
    public string? CalculatedExpression { get; set; }

    /// <summary>Display format for calculated fields (e.g. "N2").</summary>
    [DataField(Label = "Calculated Display Format", Order = 29)]
    public string? CalculatedDisplayFormat { get; set; }

    /// <summary>Parent field name for CopyFromParent fields (e.g. "CustomerId").</summary>
    [DataField(Label = "Copy From Parent Field", Order = 30)]
    public string? CopyFromParentField { get; set; }

    /// <summary>Entity slug for CopyFromParent resolution (e.g. "customers").</summary>
    [DataField(Label = "Copy From Parent Slug", Order = 31)]
    public string? CopyFromParentSlug { get; set; }

    /// <summary>Source field on the parent's target entity for CopyFromParent (e.g. "DiscountPercent").</summary>
    [DataField(Label = "Copy From Parent Source Field", Order = 32)]
    public string? CopyFromParentSourceField { get; set; }

    /// <summary>Slug of the related document entity for document-chain navigation (e.g. "customers").</summary>
    [DataField(Label = "Related Document Slug", Order = 33)]
    public string? RelatedDocumentSlug { get; set; }

    /// <summary>Display field on the related document entity (e.g. "Name").</summary>
    [DataField(Label = "Related Document Display Field", Order = 34)]
    public string? RelatedDocumentDisplayField { get; set; }

    /// <summary>
    /// Name of another field on the same entity whose value filters this lookup's options.
    /// When the cascade-from field changes, this field's options are re-fetched with a filter.
    /// E.g. on a Region field: CascadeFromField = "CountryId", CascadeFilterField = "CountryId".
    /// </summary>
    [DataField(Label = "Cascade From Field", Order = 35)]
    public string? CascadeFromField { get; set; }

    /// <summary>
    /// Field name on the lookup target entity used to filter results in a cascade.
    /// E.g. on a Region lookup targeting "regions": CascadeFilterField = "CountryId".
    /// </summary>
    [DataField(Label = "Cascade Filter Field", Order = 36)]
    public string? CascadeFilterField { get; set; }

    /// <summary>
    /// Logical group name for organising fields into sections/cards on the form.
    /// Fields with the same FieldGroup are rendered together under a shared heading.
    /// Null/empty means the field sits in the default (ungrouped) section.
    /// </summary>
    [DataField(Label = "Field Group", Order = 37)]
    public string? FieldGroup { get; set; }

    /// <summary>
    /// Number of CSS grid columns this field should span (1–12, Bootstrap grid).
    /// Defaults to 12 (full width). Use 6 for half-width, 4 for third-width, etc.
    /// </summary>
    [DataField(Label = "Column Span", Order = 38)]
    public int ColumnSpan { get; set; } = 12;

    public override string ToString() => $"{Name} ({Type})";
}
