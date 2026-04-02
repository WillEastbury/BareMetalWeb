using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted schema definition for a single field on a runtime-managed entity.
/// </summary>
[DataEntity("Field Definitions", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1001)]
public class FieldDefinition : DataRecord
{
    public override string EntityTypeName => "FieldDefinition";
    private const int Ord_FieldId = BaseFieldCount + 0;
    private const int Ord_EntityId = BaseFieldCount + 1;
    private const int Ord_Name = BaseFieldCount + 2;
    private const int Ord_Label = BaseFieldCount + 3;
    private const int Ord_Ordinal = BaseFieldCount + 4;
    private const int Ord_Type = BaseFieldCount + 5;
    private const int Ord_IsNullable = BaseFieldCount + 6;
    private const int Ord_Required = BaseFieldCount + 7;
    private const int Ord_List = BaseFieldCount + 8;
    private const int Ord_View = BaseFieldCount + 9;
    private const int Ord_Edit = BaseFieldCount + 10;
    private const int Ord_Create = BaseFieldCount + 11;
    private const int Ord_ReadOnly = BaseFieldCount + 12;
    private const int Ord_DefaultValue = BaseFieldCount + 13;
    private const int Ord_Placeholder = BaseFieldCount + 14;
    private const int Ord_MinLength = BaseFieldCount + 15;
    private const int Ord_MaxLength = BaseFieldCount + 16;
    private const int Ord_RangeMin = BaseFieldCount + 17;
    private const int Ord_RangeMax = BaseFieldCount + 18;
    private const int Ord_Pattern = BaseFieldCount + 19;
    private const int Ord_EnumValues = BaseFieldCount + 20;
    private const int Ord_LookupEntitySlug = BaseFieldCount + 21;
    private const int Ord_LookupValueField = BaseFieldCount + 22;
    private const int Ord_LookupDisplayField = BaseFieldCount + 23;
    private const int Ord_Multiline = BaseFieldCount + 24;
    private const int Ord_ChildEntitySlug = BaseFieldCount + 25;
    private const int Ord_LookupCopyFields = BaseFieldCount + 26;
    private const int Ord_CalculatedExpression = BaseFieldCount + 27;
    private const int Ord_CalculatedDisplayFormat = BaseFieldCount + 28;
    private const int Ord_CopyFromParentField = BaseFieldCount + 29;
    private const int Ord_CopyFromParentSlug = BaseFieldCount + 30;
    private const int Ord_CopyFromParentSourceField = BaseFieldCount + 31;
    private const int Ord_RelatedDocumentSlug = BaseFieldCount + 32;
    private const int Ord_RelatedDocumentDisplayField = BaseFieldCount + 33;
    private const int Ord_CascadeFromField = BaseFieldCount + 34;
    private const int Ord_CascadeFilterField = BaseFieldCount + 35;
    private const int Ord_FieldGroup = BaseFieldCount + 36;
    private const int Ord_ColumnSpan = BaseFieldCount + 37;
    internal const int TotalFieldCount = BaseFieldCount + 38;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CalculatedDisplayFormat", Ord_CalculatedDisplayFormat),
        new FieldSlot("CalculatedExpression", Ord_CalculatedExpression),
        new FieldSlot("CascadeFilterField", Ord_CascadeFilterField),
        new FieldSlot("CascadeFromField", Ord_CascadeFromField),
        new FieldSlot("ChildEntitySlug", Ord_ChildEntitySlug),
        new FieldSlot("ColumnSpan", Ord_ColumnSpan),
        new FieldSlot("CopyFromParentField", Ord_CopyFromParentField),
        new FieldSlot("CopyFromParentSlug", Ord_CopyFromParentSlug),
        new FieldSlot("CopyFromParentSourceField", Ord_CopyFromParentSourceField),
        new FieldSlot("Create", Ord_Create),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("DefaultValue", Ord_DefaultValue),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Edit", Ord_Edit),
        new FieldSlot("EntityId", Ord_EntityId),
        new FieldSlot("EnumValues", Ord_EnumValues),
        new FieldSlot("FieldGroup", Ord_FieldGroup),
        new FieldSlot("FieldId", Ord_FieldId),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("IsNullable", Ord_IsNullable),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Label", Ord_Label),
        new FieldSlot("List", Ord_List),
        new FieldSlot("LookupCopyFields", Ord_LookupCopyFields),
        new FieldSlot("LookupDisplayField", Ord_LookupDisplayField),
        new FieldSlot("LookupEntitySlug", Ord_LookupEntitySlug),
        new FieldSlot("LookupValueField", Ord_LookupValueField),
        new FieldSlot("MaxLength", Ord_MaxLength),
        new FieldSlot("MinLength", Ord_MinLength),
        new FieldSlot("Multiline", Ord_Multiline),
        new FieldSlot("Name", Ord_Name),
        new FieldSlot("Ordinal", Ord_Ordinal),
        new FieldSlot("Pattern", Ord_Pattern),
        new FieldSlot("Placeholder", Ord_Placeholder),
        new FieldSlot("RangeMax", Ord_RangeMax),
        new FieldSlot("RangeMin", Ord_RangeMin),
        new FieldSlot("ReadOnly", Ord_ReadOnly),
        new FieldSlot("RelatedDocumentDisplayField", Ord_RelatedDocumentDisplayField),
        new FieldSlot("RelatedDocumentSlug", Ord_RelatedDocumentSlug),
        new FieldSlot("Required", Ord_Required),
        new FieldSlot("Type", Ord_Type),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
        new FieldSlot("View", Ord_View),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public FieldDefinition() : base(TotalFieldCount) { }
    public FieldDefinition(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Stable GUID identity that survives renames. Defaults to Id.</summary>
    [DataField(Label = "Field ID", Order = 1, ReadOnly = true)]
    public string FieldId
    {
        get => (string?)_values[Ord_FieldId] ?? string.Empty;
        set => _values[Ord_FieldId] = value;
    }

    /// <summary>Foreign key to <see cref="EntityDefinition.Id"/>.</summary>
    [DataField(Label = "Entity ID", Order = 2, Required = true)]
    [DataLookup(typeof(EntityDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string EntityId
    {
        get => (string?)_values[Ord_EntityId] ?? string.Empty;
        set => _values[Ord_EntityId] = value;
    }

    [DataField(Label = "Name", Order = 3, Required = true)]
    public string Name
    {
        get => (string?)_values[Ord_Name] ?? string.Empty;
        set => _values[Ord_Name] = value;
    }

    /// <summary>Display label override. Derived from Name via DeCamelcase if empty.</summary>
    [DataField(Label = "Label", Order = 4)]
    public string? Label
    {
        get => (string?)_values[Ord_Label];
        set => _values[Ord_Label] = value;
    }

    /// <summary>
    /// Storage ordinal — assigned deterministically at compile time.
    /// Stable across renames. Used by storage to locate field data.
    /// </summary>
    [DataField(Label = "Ordinal", Order = 5, ReadOnly = true)]
    public int Ordinal
    {
        get => (int)(_values[Ord_Ordinal] ?? 0);
        set => _values[Ord_Ordinal] = value;
    }

    /// <summary>
    /// Field type string. Supported: string, multiline, textarea, bool, boolean,
    /// int, integer, decimal, number, datetime, date, dateonly, time, timeonly,
    /// enum, lookup, email, phone, url.
    /// </summary>
    [DataField(Label = "Type", Order = 6, Required = true)]
    public string Type
    {
        get => (string?)_values[Ord_Type] ?? "string";
        set => _values[Ord_Type] = value;
    }

    [DataField(Label = "Nullable", Order = 7)]
    public bool IsNullable
    {
        get => _values[Ord_IsNullable] is true;
        set => _values[Ord_IsNullable] = value;
    }

    [DataField(Label = "Required", Order = 8)]
    public bool Required
    {
        get => _values[Ord_Required] is true;
        set => _values[Ord_Required] = value;
    }

    [DataField(Label = "Show in List", Order = 9)]
    public bool List
    {
        get => _values[Ord_List] is true;
        set => _values[Ord_List] = value;
    }

    [DataField(Label = "Show in View", Order = 10)]
    public bool View
    {
        get => _values[Ord_View] is true;
        set => _values[Ord_View] = value;
    }

    [DataField(Label = "Show in Edit", Order = 11)]
    public bool Edit
    {
        get => _values[Ord_Edit] is true;
        set => _values[Ord_Edit] = value;
    }

    [DataField(Label = "Show in Create", Order = 12)]
    public bool Create
    {
        get => _values[Ord_Create] is true;
        set => _values[Ord_Create] = value;
    }

    [DataField(Label = "Read Only", Order = 13)]
    public bool ReadOnly
    {
        get => _values[Ord_ReadOnly] is true;
        set => _values[Ord_ReadOnly] = value;
    }

    [DataField(Label = "Default Value", Order = 14)]
    public string? DefaultValue
    {
        get => (string?)_values[Ord_DefaultValue];
        set => _values[Ord_DefaultValue] = value;
    }

    [DataField(Label = "Placeholder", Order = 15)]
    public string? Placeholder
    {
        get => (string?)_values[Ord_Placeholder];
        set => _values[Ord_Placeholder] = value;
    }

    /// <summary>Minimum string length validation rule.</summary>
    [DataField(Label = "Min Length", Order = 16)]
    public int? MinLength
    {
        get => _values[Ord_MinLength] as int?;
        set => _values[Ord_MinLength] = value;
    }

    /// <summary>Maximum string length validation rule.</summary>
    [DataField(Label = "Max Length", Order = 17)]
    public int? MaxLength
    {
        get => _values[Ord_MaxLength] as int?;
        set => _values[Ord_MaxLength] = value;
    }

    /// <summary>Minimum numeric range validation rule.</summary>
    [DataField(Label = "Range Min", Order = 18)]
    public double? RangeMin
    {
        get => _values[Ord_RangeMin] as double?;
        set => _values[Ord_RangeMin] = value;
    }

    /// <summary>Maximum numeric range validation rule.</summary>
    [DataField(Label = "Range Max", Order = 19)]
    public double? RangeMax
    {
        get => _values[Ord_RangeMax] as double?;
        set => _values[Ord_RangeMax] = value;
    }

    /// <summary>Regex pattern validation rule.</summary>
    [DataField(Label = "Pattern", Order = 20)]
    public string? Pattern
    {
        get => (string?)_values[Ord_Pattern];
        set => _values[Ord_Pattern] = value;
    }

    /// <summary>Pipe-separated enum member names, e.g. "Low|Medium|High|Critical".</summary>
    [DataField(Label = "Enum Values (pipe-separated)", Order = 21)]
    public string? EnumValues
    {
        get => (string?)_values[Ord_EnumValues];
        set => _values[Ord_EnumValues] = value;
    }

    /// <summary>Slug of the target entity for lookup fields.</summary>
    [DataField(Label = "Lookup Entity Slug", Order = 22)]
    public string? LookupEntitySlug
    {
        get => (string?)_values[Ord_LookupEntitySlug];
        set => _values[Ord_LookupEntitySlug] = value;
    }

    [DataField(Label = "Lookup Value Field", Order = 23)]
    public string? LookupValueField
    {
        get => (string?)_values[Ord_LookupValueField];
        set => _values[Ord_LookupValueField] = value;
    }

    [DataField(Label = "Lookup Display Field", Order = 24)]
    public string? LookupDisplayField
    {
        get => (string?)_values[Ord_LookupDisplayField];
        set => _values[Ord_LookupDisplayField] = value;
    }

    /// <summary>Render as multiline textarea (for string fields).</summary>
    [DataField(Label = "Multiline", Order = 25)]
    public bool Multiline
    {
        get => _values[Ord_Multiline] is true;
        set => _values[Ord_Multiline] = value;
    }

    /// <summary>Slug of child entity for childlist fields (e.g. "order-rows").</summary>
    [DataField(Label = "Child Entity Slug", Order = 26)]
    public string? ChildEntitySlug
    {
        get => (string?)_values[Ord_ChildEntitySlug];
        set => _values[Ord_ChildEntitySlug] = value;
    }

    /// <summary>Lookup copy-fields mapping for child entity lookup fields (e.g. "Price->UnitPrice").</summary>
    [DataField(Label = "Lookup Copy Fields", Order = 27)]
    public string? LookupCopyFields
    {
        get => (string?)_values[Ord_LookupCopyFields];
        set => _values[Ord_LookupCopyFields] = value;
    }

    /// <summary>Calculated expression for child entity calculated fields (e.g. "Quantity * UnitPrice").</summary>
    [DataField(Label = "Calculated Expression", Order = 28)]
    public string? CalculatedExpression
    {
        get => (string?)_values[Ord_CalculatedExpression];
        set => _values[Ord_CalculatedExpression] = value;
    }

    /// <summary>Display format for calculated fields (e.g. "N2").</summary>
    [DataField(Label = "Calculated Display Format", Order = 29)]
    public string? CalculatedDisplayFormat
    {
        get => (string?)_values[Ord_CalculatedDisplayFormat];
        set => _values[Ord_CalculatedDisplayFormat] = value;
    }

    /// <summary>Parent field name for CopyFromParent fields (e.g. "CustomerId").</summary>
    [DataField(Label = "Copy From Parent Field", Order = 30)]
    public string? CopyFromParentField
    {
        get => (string?)_values[Ord_CopyFromParentField];
        set => _values[Ord_CopyFromParentField] = value;
    }

    /// <summary>Entity slug for CopyFromParent resolution (e.g. "customers").</summary>
    [DataField(Label = "Copy From Parent Slug", Order = 31)]
    public string? CopyFromParentSlug
    {
        get => (string?)_values[Ord_CopyFromParentSlug];
        set => _values[Ord_CopyFromParentSlug] = value;
    }

    /// <summary>Source field on the parent's target entity for CopyFromParent (e.g. "DiscountPercent").</summary>
    [DataField(Label = "Copy From Parent Source Field", Order = 32)]
    public string? CopyFromParentSourceField
    {
        get => (string?)_values[Ord_CopyFromParentSourceField];
        set => _values[Ord_CopyFromParentSourceField] = value;
    }

    /// <summary>Slug of the related document entity for document-chain navigation (e.g. "customers").</summary>
    [DataField(Label = "Related Document Slug", Order = 33)]
    public string? RelatedDocumentSlug
    {
        get => (string?)_values[Ord_RelatedDocumentSlug];
        set => _values[Ord_RelatedDocumentSlug] = value;
    }

    /// <summary>Display field on the related document entity (e.g. "Name").</summary>
    [DataField(Label = "Related Document Display Field", Order = 34)]
    public string? RelatedDocumentDisplayField
    {
        get => (string?)_values[Ord_RelatedDocumentDisplayField];
        set => _values[Ord_RelatedDocumentDisplayField] = value;
    }

    /// <summary>
    /// Name of another field on the same entity whose value filters this lookup's options.
    /// When the cascade-from field changes, this field's options are re-fetched with a filter.
    /// E.g. on a Region field: CascadeFromField = "CountryId", CascadeFilterField = "CountryId".
    /// </summary>
    [DataField(Label = "Cascade From Field", Order = 35)]
    public string? CascadeFromField
    {
        get => (string?)_values[Ord_CascadeFromField];
        set => _values[Ord_CascadeFromField] = value;
    }

    /// <summary>
    /// Field name on the lookup target entity used to filter results in a cascade.
    /// E.g. on a Region lookup targeting "regions": CascadeFilterField = "CountryId".
    /// </summary>
    [DataField(Label = "Cascade Filter Field", Order = 36)]
    public string? CascadeFilterField
    {
        get => (string?)_values[Ord_CascadeFilterField];
        set => _values[Ord_CascadeFilterField] = value;
    }

    /// <summary>
    /// Logical group name for organising fields into sections/cards on the form.
    /// Fields with the same FieldGroup are rendered together under a shared heading.
    /// Null/empty means the field sits in the default (ungrouped) section.
    /// </summary>
    [DataField(Label = "Field Group", Order = 37)]
    public string? FieldGroup
    {
        get => (string?)_values[Ord_FieldGroup];
        set => _values[Ord_FieldGroup] = value;
    }

    /// <summary>
    /// Number of CSS grid columns this field should span (1–12, Bootstrap grid).
    /// Defaults to 12 (full width). Use 6 for half-width, 4 for third-width, etc.
    /// </summary>
    [DataField(Label = "Column Span", Order = 38)]
    public int ColumnSpan
    {
        get => (int)(_values[Ord_ColumnSpan] ?? 12);
        set => _values[Ord_ColumnSpan] = value;
    }

    /// <summary>
    /// Marks this field as the target for the GET ingress endpoint.
    /// When the parent entity has <see cref="EntityDefinition.EnableGetIngress"/> = true,
    /// the <c>text</c> query-string parameter is written to this field.
    /// Only one field per entity should have this set.
    /// </summary>
    [DataField(Label = "Is Ingress Target", Order = 39)]
    public bool IsIngressTarget { get; set; } = false;

    public override string ToString() => $"{Name} ({Type})";
}
