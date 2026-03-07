using System.Reflection;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Generates persisted metadata records (<see cref="EntityDefinition"/>,
/// <see cref="FieldDefinition"/>, <see cref="IndexDefinition"/>) from the
/// reflection attributes on a compiled C# type.
///
/// This is the bridge between the "code-first" world (annotated <see cref="BaseDataObject"/>
/// subclasses) and the "metadata-first" world where entity schemas live in the
/// data store and can be browsed and edited through the admin UI.
/// </summary>
public static class MetadataExtractor
{
    // Properties inherited from BaseDataObject that must not be included as schema fields.
    private static readonly HashSet<string> CorePropertyNames = new(StringComparer.Ordinal)
    {
        nameof(BaseDataObject.Key),
        nameof(BaseDataObject.CreatedOnUtc),
        nameof(BaseDataObject.UpdatedOnUtc),
        nameof(BaseDataObject.CreatedBy),
        nameof(BaseDataObject.UpdatedBy),
        nameof(BaseDataObject.ETag),
        "EntityTypeName"
    };

    private static readonly NullabilityInfoContext _nullabilityCtx = new();

    /// <summary>
    /// Extracts an <see cref="EntityDefinition"/>, its <see cref="FieldDefinition"/>s,
    /// and any <see cref="IndexDefinition"/>s from the reflection attributes on
    /// <paramref name="type"/>.
    /// </summary>
    /// <param name="type">
    /// A concrete, non-abstract <see cref="BaseDataObject"/> subclass annotated with
    /// <see cref="DataEntityAttribute"/> and/or <see cref="DataFieldAttribute"/>.
    /// </param>
    /// <returns>
    /// A tuple containing the generated entity definition, field definitions, and
    /// index definitions. All records have freshly generated <c>Id</c> and stable
    /// <c>EntityId</c> / <c>FieldId</c> GUIDs.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="type"/> is <c>null</c>.</exception>
    public static (
        EntityDefinition Entity,
        IReadOnlyList<FieldDefinition> Fields,
        IReadOnlyList<IndexDefinition> Indexes)
        ExtractFromType(Type type)
    {
        ArgumentNullException.ThrowIfNull(type);

        var entityAttr = type.GetCustomAttribute<DataEntityAttribute>();

        var name = !string.IsNullOrWhiteSpace(entityAttr?.Name)
            ? entityAttr!.Name
            : DataScaffold.Pluralize(DataScaffold.DeCamelcase(type.Name));

        var slug = !string.IsNullOrWhiteSpace(entityAttr?.Slug)
            ? entityAttr!.Slug!.Trim().ToLowerInvariant()
            : DataScaffold.ToSlug(name);

        var entity = new EntityDefinition
        {
            EntityId = Guid.NewGuid().ToString("D"),
            Name = name,
            Slug = slug,
            IdStrategy = MapIdStrategyString(entityAttr?.IdGeneration ?? AutoIdStrategy.Sequential),
            ShowOnNav = entityAttr?.ShowOnNav ?? false,
            NavGroup = entityAttr?.NavGroup ?? "Admin",
            NavOrder = entityAttr?.NavOrder ?? 0,
            Permissions = !string.IsNullOrWhiteSpace(entityAttr?.Permissions)
                ? entityAttr!.Permissions
                : name,
            Version = 1
        };

        var fields = new List<FieldDefinition>();
        var indexes = new List<IndexDefinition>();
        var nullabilityCtx = new NullabilityInfoContext();

        var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        Array.Sort(properties, (a, b) => string.CompareOrdinal(a.Name, b.Name));

        int ordinal = 1;
        for (int i = 0; i < properties.Length; i++)
        {
            var prop = properties[i];
            if (!prop.CanRead || !prop.CanWrite) continue;
            if (IsCoreProperty(prop)) continue;

            var fieldAttr = prop.GetCustomAttribute<DataFieldAttribute>();
            var lookupAttribute = prop.GetCustomAttribute<DataLookupAttribute>();
            var indexAttr = prop.GetCustomAttribute<DataIndexAttribute>();

            // Only include properties that are explicitly annotated as fields or lookups
            if (fieldAttr == null && lookupAttribute == null) continue;

            var fieldOrdinal = fieldAttr?.Order > 0 ? fieldAttr.Order : ordinal;
            // Advance the auto-ordinal counter past any explicit ordinal to preserve gaps
            // intentionally set by the caller — matches RuntimeEntityCompiler behaviour.
            ordinal = Math.Max(ordinal, fieldOrdinal) + 1;

            bool hasLookup = lookupAttribute != null;
            string? lookupSlug = null;
            string? lookupValueField = null;
            string? lookupDisplayField = null;

            if (lookupAttribute != null)
            {
                lookupSlug = ResolveEntitySlug(lookupAttribute.TargetType);
                lookupValueField = lookupAttribute.ValueField;
                lookupDisplayField = lookupAttribute.DisplayField;
            }

            bool isNullable = IsNullableProperty(prop, nullabilityCtx);
            string fieldTypeStr = MapFieldTypeString(prop.PropertyType, fieldAttr?.FieldType, hasLookup);

            // Capture enum values for enum fields
            string? enumValues = null;
            var effectivePropType = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType;
            if (effectivePropType.IsEnum && !hasLookup)
            {
                var enumNames = Enum.GetNames(effectivePropType);
                if (enumNames.Length > 0)
                    enumValues = string.Join("|", enumNames);
            }

            fields.Add(new FieldDefinition
            {
                FieldId = Guid.NewGuid().ToString("D"),
                EntityId = entity.EntityId,
                Name = prop.Name,
                Label = !string.IsNullOrWhiteSpace(fieldAttr?.Label)
                    ? fieldAttr!.Label
                    : DataScaffold.DeCamelcase(prop.Name),
                Ordinal = fieldOrdinal,
                Type = fieldTypeStr,
                IsNullable = isNullable,
                Required = fieldAttr?.Required ?? false,
                List = fieldAttr?.List ?? true,
                View = fieldAttr?.View ?? true,
                Edit = fieldAttr?.Edit ?? true,
                Create = fieldAttr?.Create ?? true,
                ReadOnly = fieldAttr?.ReadOnly ?? false,
                Placeholder = fieldAttr?.Placeholder,
                EnumValues = enumValues,
                LookupEntitySlug = lookupSlug,
                LookupValueField = lookupValueField,
                LookupDisplayField = lookupDisplayField
            });

            if (indexAttr != null)
            {
                indexes.Add(new IndexDefinition
                {
                    EntityId = entity.EntityId,
                    FieldNames = prop.Name,
                    Type = indexAttr.Kind == IndexKind.BTree ? "btree" : "secondary"
                });
            }
        }

        return (entity, fields, indexes);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Resolves the URL slug for a lookup target type.
    /// Tries the live DataScaffold registry first; falls back to reading the
    /// <see cref="DataEntityAttribute"/> (or deriving by convention) from the CLR type.
    /// </summary>
    internal static string? ResolveEntitySlug(Type targetType)
    {
        // Check the live registry first
        var meta = DataScaffold.GetEntityByType(targetType);
        if (meta != null)
            return meta.Slug;

        // Fall back to reading the attribute directly
        var attr = targetType.GetCustomAttribute<DataEntityAttribute>();
        if (attr != null && !string.IsNullOrWhiteSpace(attr.Slug))
            return attr.Slug!.Trim().ToLowerInvariant();

        var name = !string.IsNullOrWhiteSpace(attr?.Name)
            ? attr!.Name
            : DataScaffold.Pluralize(DataScaffold.DeCamelcase(targetType.Name));

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

    private static bool IsCoreProperty(PropertyInfo prop) =>
        prop.DeclaringType == typeof(BaseDataObject) || CorePropertyNames.Contains(prop.Name);

    /// <summary>
    /// Builds persisted metadata records from an already-loaded <see cref="DataEntityMetadata"/>,
    /// avoiding the full reflection scan that <see cref="ExtractFromType"/> performs.
    /// </summary>
    internal static (
        EntityDefinition Entity,
        IReadOnlyList<FieldDefinition> Fields,
        IReadOnlyList<IndexDefinition> Indexes)
        BuildFromMetadata(DataEntityMetadata meta)
    {
        var entityAttr = meta.Type.GetCustomAttribute<DataEntityAttribute>();

        var entity = new EntityDefinition
        {
            EntityId = Guid.NewGuid().ToString("D"),
            Name = meta.Name,
            Slug = meta.Slug,
            IdStrategy = MapIdStrategyString(entityAttr?.IdGeneration ?? AutoIdStrategy.Sequential),
            ShowOnNav = entityAttr?.ShowOnNav ?? false,
            NavGroup = entityAttr?.NavGroup ?? "Admin",
            NavOrder = entityAttr?.NavOrder ?? 0,
            Permissions = !string.IsNullOrWhiteSpace(entityAttr?.Permissions)
                ? entityAttr!.Permissions
                : meta.Name,
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
                || (!f.ClrType.IsValueType && IsNullableProperty(f.Property, _nullabilityCtx));

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

    private static bool IsNullableProperty(PropertyInfo prop, NullabilityInfoContext ctx)
    {
        if (Nullable.GetUnderlyingType(prop.PropertyType) != null) return true;
        if (prop.PropertyType.IsValueType) return false;

        var info = ctx.Create(prop);
        return info.ReadState == NullabilityState.Nullable
               || info.WriteState == NullabilityState.Nullable;
    }
}
