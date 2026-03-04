using BareMetalWeb.Core;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Compiled, immutable representation of a single field on a <see cref="RuntimeEntityModel"/>.
/// Produced by <see cref="IRuntimeEntityCompiler"/> from a <see cref="FieldDefinition"/>.
/// </summary>
/// <param name="FieldId">Stable GUID identity (from <see cref="FieldDefinition.FieldId"/>).</param>
/// <param name="Ordinal">Storage ordinal — stable across renames.</param>
/// <param name="Name">Current field name.</param>
/// <param name="Label">Display label.</param>
/// <param name="FieldType">Mapped <see cref="FormFieldType"/>.</param>
/// <param name="IsNullable">Whether the field allows null values.</param>
/// <param name="Required">Whether the field is required for create/edit.</param>
/// <param name="List">Whether to show in list views.</param>
/// <param name="View">Whether to show in detail views.</param>
/// <param name="Edit">Whether to show in edit forms.</param>
/// <param name="Create">Whether to show in create forms.</param>
/// <param name="ReadOnly">Whether the field is render-only.</param>
/// <param name="DefaultValue">Optional default value string.</param>
/// <param name="Placeholder">Optional input placeholder.</param>
/// <param name="EnumValues">Ordered enum member names (only when <paramref name="FieldType"/> is Enum).</param>
/// <param name="LookupEntitySlug">Slug of the lookup target entity (only when FieldType is LookupList).</param>
/// <param name="LookupValueField">Value field on the lookup target.</param>
/// <param name="LookupDisplayField">Display field on the lookup target.</param>
/// <param name="MinLength">Optional minimum string length validation.</param>
/// <param name="MaxLength">Optional maximum string length validation.</param>
/// <param name="RangeMin">Optional numeric range minimum.</param>
/// <param name="RangeMax">Optional numeric range maximum.</param>
/// <param name="Pattern">Optional regex pattern validation.</param>
public sealed record RuntimeFieldModel(
    string FieldId,
    int Ordinal,
    string Name,
    string Label,
    FormFieldType FieldType,
    bool IsNullable,
    bool Required,
    bool List,
    bool View,
    bool Edit,
    bool Create,
    bool ReadOnly,
    string? DefaultValue,
    string? Placeholder,
    IReadOnlyList<string> EnumValues,
    string? LookupEntitySlug,
    string? LookupValueField,
    string? LookupDisplayField,
    int? MinLength,
    int? MaxLength,
    double? RangeMin,
    double? RangeMax,
    string? Pattern,
    string? ChildEntitySlug = null,
    string? LookupCopyFields = null,
    string? CalculatedExpression = null,
    string? CalculatedDisplayFormat = null,
    string? CopyFromParentField = null,
    string? CopyFromParentSlug = null,
    string? CopyFromParentSourceField = null,
    string? RelatedDocumentSlug = null,
    string? RelatedDocumentDisplayField = null,
    string? CascadeFromField = null,
    string? CascadeFilterField = null,
    string? FieldGroup = null,
    int ColumnSpan = 12
);
