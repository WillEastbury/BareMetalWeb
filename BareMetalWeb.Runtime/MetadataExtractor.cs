using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Generates persisted metadata records (<see cref="EntityDefinition"/>,
/// <see cref="FieldDefinition"/>, <see cref="IndexDefinition"/>) from registered
/// <see cref="DataEntityMetadata"/>.
///
/// All metadata is read from <see cref="DataScaffold"/> — no reflection is used.
/// </summary>
public static class MetadataExtractor
{
    // Properties inherited from DataRecord that must not be included as schema fields.
    private static readonly HashSet<string> CorePropertyNames = new(StringComparer.Ordinal)
    {
        nameof(DataRecord.Key),
        nameof(DataRecord.CreatedOnUtc),
        nameof(DataRecord.UpdatedOnUtc),
        nameof(DataRecord.CreatedBy),
        nameof(DataRecord.UpdatedBy),
        nameof(DataRecord.ETag),
        "EntityTypeName"
    };

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Resolves the URL slug for a lookup target type.
    /// Checks the live <see cref="DataScaffold"/> registry; falls back to
    /// convention-based slug derivation from the type name (no reflection).
    /// </summary>
    internal static string? ResolveEntitySlug(Type targetType)
    {
        var meta = DataScaffold.GetEntityByType(targetType);
        if (meta != null)
            return meta.Slug;

        // Convention fallback: derive from type name without reflection
        var name = DataScaffold.Pluralize(DataScaffold.DeCamelcase(targetType.Name));
        return DataScaffold.ToSlug(name);
    }

    /// <summary>
    /// Maps a CLR property type (plus an optional explicit <see cref="FormFieldType"/>) to
    /// the string representation used in <see cref="FieldDefinition.Type"/>.
    /// </summary>
    internal static string MapFieldTypeString(Type propertyType, FormFieldType? explicitType, bool hasLookup)
    {
        if (hasLookup) return "lookup";

        if (explicitType.HasValue && explicitType.Value != FormFieldType.Unknown)
        {
            return explicitType.Value switch
            {
                FormFieldType.TextArea => "multiline",
                FormFieldType.YesNo => "bool",
                FormFieldType.Integer => "int",
                FormFieldType.Decimal or FormFieldType.Money => "decimal",
                FormFieldType.DateTime => "datetime",
                FormFieldType.DateOnly => "date",
                FormFieldType.TimeOnly => "time",
                FormFieldType.Enum => "enum",
                FormFieldType.LookupList => "lookup",
                FormFieldType.Email => "email",
                _ => "string"
            };
        }

        var effective = Nullable.GetUnderlyingType(propertyType) ?? propertyType;
        if (effective == typeof(bool)) return "bool";
        if (effective.IsEnum) return "enum";
        if (effective == typeof(DateOnly)) return "date";
        if (effective == typeof(TimeOnly)) return "time";
        if (effective == typeof(DateTime) || effective == typeof(DateTimeOffset)) return "datetime";
        if (effective == typeof(int) || effective == typeof(long) || effective == typeof(short)) return "int";
        if (effective == typeof(decimal) || effective == typeof(double) || effective == typeof(float)) return "decimal";

        return "string";
    }

    private static string MapIdStrategyString(AutoIdStrategy strategy) => strategy switch
    {
        AutoIdStrategy.Sequential => "sequential",
        AutoIdStrategy.None => "none",
        _ => "guid"
    };

    /// <summary>
    /// Builds persisted metadata records from an already-loaded <see cref="DataEntityMetadata"/>.
    /// All entity-level and field-level data is read directly from the metadata — no reflection.
    /// </summary>
    internal static (
        EntityDefinition Entity,
        IReadOnlyList<FieldDefinition> Fields,
        IReadOnlyList<IndexDefinition> Indexes)
        BuildFromMetadata(DataEntityMetadata meta)
    {
        var entity = new EntityDefinition
        {
            EntityId = Guid.NewGuid().ToString("D"),
            Name = meta.Name,
            Slug = meta.Slug,
            IdStrategy = MapIdStrategyString(meta.IdGeneration),
            ShowOnNav = meta.ShowOnNav,
            NavGroup = meta.NavGroup ?? "Admin",
            NavOrder = meta.NavOrder,
            Permissions = meta.Permissions,
            Version = 1
        };

        var fields = new List<FieldDefinition>();
        var indexes = new List<IndexDefinition>();

        foreach (var f in meta.Fields)
        {
            if (CorePropertyNames.Contains(f.Name)) continue;

            bool hasLookup = f.Lookup != null;
            string? lookupSlug = hasLookup ? ResolveEntitySlug(f.Lookup!.TargetType) : null;
            string fieldTypeStr = MapFieldTypeString(f.ClrType, f.FieldType, hasLookup);

            string? enumValues = null;
            var effectivePropType = Nullable.GetUnderlyingType(f.ClrType) ?? f.ClrType;
            if (effectivePropType.IsEnum && !hasLookup)
            {
                var enumNames = Enum.GetNames(effectivePropType);
                if (enumNames.Length > 0)
                    enumValues = string.Join("|", enumNames);
            }

            bool isNullable = Nullable.GetUnderlyingType(f.ClrType) != null
                || !f.ClrType.IsValueType;

            fields.Add(new FieldDefinition
            {
                FieldId = Guid.NewGuid().ToString("D"),
                EntityId = entity.EntityId,
                Name = f.Name,
                Label = f.Label,
                Ordinal = f.Order,
                Type = fieldTypeStr,
                IsNullable = isNullable,
                Required = f.Required,
                List = f.List,
                View = f.View,
                Edit = f.Edit,
                Create = f.Create,
                ReadOnly = f.ReadOnly,
                Placeholder = f.Placeholder,
                EnumValues = enumValues,
                LookupEntitySlug = lookupSlug,
                LookupValueField = hasLookup ? f.Lookup!.ValueField : null,
                LookupDisplayField = hasLookup ? f.Lookup!.DisplayField : null
            });

            if (f.DataIndex != null)
            {
                indexes.Add(new IndexDefinition
                {
                    EntityId = entity.EntityId,
                    FieldNames = f.Name,
                    Type = f.DataIndex.Kind == IndexKind.BTree ? "btree" : "secondary"
                });
            }
        }

        return (entity, fields, indexes);
    }
}
