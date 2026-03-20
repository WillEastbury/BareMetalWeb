using System.Diagnostics.CodeAnalysis;
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
    /// Extracts persisted metadata records directly from a compiled CLR type by scanning
    /// its <see cref="DataEntityAttribute"/>, <see cref="DataFieldAttribute"/> and
    /// <see cref="DataIndexAttribute"/> annotations.
    /// </summary>
    internal static (
        EntityDefinition Entity,
        IReadOnlyList<FieldDefinition> Fields,
        IReadOnlyList<IndexDefinition> Indexes)
        ExtractFromType([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties)] Type type)
    {
        var entityAttr = type.GetCustomAttribute<DataEntityAttribute>();

        string name = !string.IsNullOrWhiteSpace(entityAttr?.Name)
            ? entityAttr!.Name
            : DataScaffold.Pluralize(DataScaffold.DeCamelcase(type.Name));

        string slug = !string.IsNullOrWhiteSpace(entityAttr?.Slug)
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

        var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => !IsCoreProperty(p))
            .Select(p => (Prop: p, Attr: p.GetCustomAttribute<DataFieldAttribute>()))
            .Where(x => x.Attr != null)
            .OrderBy(x => x.Attr!.Order);

        foreach (var (prop, attr) in properties)
        {
            var dataIndex = prop.GetCustomAttribute<DataIndexAttribute>();
            var lookupAttr = prop.GetCustomAttribute<DataLookupAttribute>();
            bool hasLookup = lookupAttr != null;
            string? lookupSlug = hasLookup ? ResolveEntitySlug(lookupAttr!.TargetType) : null;

            FormFieldType? explicitType = attr!.FieldType != FormFieldType.Unknown
                ? attr.FieldType
                : null;
            string fieldTypeStr = MapFieldTypeString(prop.PropertyType, explicitType, hasLookup);

            string? enumValues = null;
            var effectivePropType = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType;
            if (effectivePropType.IsEnum && !hasLookup)
                enumValues = string.Join("|", Enum.GetNames(effectivePropType));

            bool isNullable = Nullable.GetUnderlyingType(prop.PropertyType) != null
                || (!prop.PropertyType.IsValueType && IsNullableProperty(prop, _nullabilityCtx));

            fields.Add(new FieldDefinition
            {
                FieldId = Guid.NewGuid().ToString("D"),
                EntityId = entity.EntityId,
                Name = prop.Name,
                Label = !string.IsNullOrWhiteSpace(attr.Label) ? attr.Label : prop.Name,
                Ordinal = attr.Order,
                Type = fieldTypeStr,
                IsNullable = isNullable,
                Required = attr.Required,
                List = attr.List,
                View = attr.View,
                Edit = attr.Edit,
                Create = attr.Create,
                ReadOnly = attr.ReadOnly,
                Placeholder = attr.Placeholder,
                EnumValues = enumValues,
                LookupEntitySlug = lookupSlug,
                LookupValueField = hasLookup ? lookupAttr!.ValueField : null,
                LookupDisplayField = hasLookup ? lookupAttr!.DisplayField : null
            });

            if (dataIndex != null)
            {
                indexes.Add(new IndexDefinition
                {
                    EntityId = entity.EntityId,
                    FieldNames = prop.Name,
                    Type = dataIndex.Kind == IndexKind.BTree ? "btree" : "secondary"
                });
            }
        }

        return (entity, fields, indexes);
    }

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
                if (f.EnumValues is { Count: > 0 })
                {
                    enumValues = string.Join("|", f.EnumValues);
                }
                else
                {
                    var enumNames = Enum.GetNames(effectivePropType);
                    if (enumNames.Length > 0)
                        enumValues = string.Join("|", enumNames);
                }
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

    private static bool IsNullableProperty(PropertyInfo prop, NullabilityInfoContext ctx)
    {
        if (Nullable.GetUnderlyingType(prop.PropertyType) != null) return true;
        if (prop.PropertyType.IsValueType) return false;

        var info = ctx.Create(prop);
        return info.ReadState == NullabilityState.Nullable
               || info.WriteState == NullabilityState.Nullable;
    }
}
