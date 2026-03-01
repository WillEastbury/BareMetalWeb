using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Data;

/// <summary>
/// Loads virtual entity definitions from a JSON file and registers them with
/// <see cref="DataScaffold"/>. Each virtual entity is treated as a first-class
/// entity at runtime — browsable, editable, and storable through the standard
/// admin UI and API routes.
/// </summary>
public static class VirtualEntityLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    /// <summary>
    /// Parses <paramref name="filePath"/> as a <see cref="VirtualEntitiesRoot"/> JSON document,
    /// builds <see cref="DataEntityMetadata"/> for each valid definition, and registers them
    /// with <see cref="DataScaffold"/>. Non-existent files are silently ignored.
    /// </summary>
    /// <param name="filePath">Path to the JSON file (e.g. "virtualEntities.json").</param>
    /// <param name="dataRootPath">Root path for data storage (e.g. the Data folder).</param>
    public static void LoadFromFile(string filePath, string dataRootPath)
    {
        if (!File.Exists(filePath))
            return;

        var json = File.ReadAllText(filePath);
        var root = JsonSerializer.Deserialize<VirtualEntitiesRoot>(json, JsonOptions);
        if (root?.VirtualEntities == null || root.VirtualEntities.Count == 0)
            return;

        var store = new VirtualEntityJsonStore(dataRootPath);

        // Pass 1: Register all entities without lookup resolution so self-referencing
        // and cross-entity lookups can resolve in the second pass.
        var deferredLookups = new List<(VirtualEntityDef Def, DataEntityMetadata Meta)>();

        foreach (var entityDef in root.VirtualEntities)
        {
            if (string.IsNullOrWhiteSpace(entityDef.Name))
                continue;

            var metadata = BuildEntityMetadata(entityDef, store, resolveLookups: false);
            if (metadata != null)
            {
                DataScaffold.RegisterVirtualEntity(metadata);
                deferredLookups.Add((entityDef, metadata));
            }
        }

        // Pass 2: Re-register entities that have lookup fields now that all slugs exist.
        foreach (var (entityDef, meta) in deferredLookups)
        {
            if (!entityDef.Fields.Any(f => string.Equals(f.Type, "lookup", StringComparison.OrdinalIgnoreCase)))
                continue;

            var updated = BuildEntityMetadata(entityDef, store, resolveLookups: true);
            if (updated != null)
                DataScaffold.RegisterVirtualEntity(updated);
        }
    }

    // ── Entity metadata ───────────────────────────────────────────────────────

    private static DataEntityMetadata? BuildEntityMetadata(VirtualEntityDef def, VirtualEntityJsonStore store, bool resolveLookups = true)
    {
        var entityTypeName = def.Name;
        var slug = !string.IsNullOrWhiteSpace(def.Slug)
            ? def.Slug!.Trim().ToLowerInvariant()
            : DataScaffold.ToSlug(DataScaffold.Pluralize(def.Name));

        var permissions = !string.IsNullOrWhiteSpace(def.Permissions)
            ? def.Permissions!
            : def.Name;

        var idStrategy = def.IdStrategy.ToLowerInvariant() switch
        {
            "sequential" => AutoIdStrategy.Sequential,
            "none" => AutoIdStrategy.None,
            _ => AutoIdStrategy.Sequential
        };

        // Build field metadata list
        var fields = new List<DataFieldMetadata>();
        for (int i = 0; i < def.Fields.Count; i++)
        {
            var field = BuildFieldMetadata(def.Fields[i], defaultOrder: i + 1, resolveLookups: resolveLookups);
            if (field != null)
                fields.Add(field);
        }

        // Build CRUD handlers backed by the JSON store
        var handlers = new DataEntityHandlers(
            Create: () => new DynamicDataObject { EntityTypeName = entityTypeName },
            LoadAsync: async (key, ct) =>
            {
                var obj = await store.LoadAsync(entityTypeName, key, ct).ConfigureAwait(false);
                if (obj != null) obj.EntityTypeName = entityTypeName;
                return obj;
            },
            SaveAsync: async (obj, ct) =>
            {
                if (obj is DynamicDataObject dyn)
                    await store.SaveAsync(entityTypeName, dyn, ct).ConfigureAwait(false);
            },
            DeleteAsync: (key, ct) => store.DeleteAsync(entityTypeName, key, ct),
            QueryAsync: async (query, ct) =>
            {
                var items = await store.QueryAsync(entityTypeName, query, ct).ConfigureAwait(false);
                foreach (var item in items)
                    item.EntityTypeName = entityTypeName;
                return (IEnumerable<BaseDataObject>)items;
            },
            CountAsync: (query, ct) => store.CountAsync(entityTypeName, query, ct)
        );

        var viewType = (def.ViewType?.ToLowerInvariant()) switch
        {
            "treeview" or "tree" => Data.ViewType.TreeView,
            "orgchart" or "org" => Data.ViewType.OrgChart,
            "timeline" => Data.ViewType.Timeline,
            "timetable" => Data.ViewType.Timetable,
            "sankey" => Data.ViewType.Sankey,
            _ => Data.ViewType.Table
        };

        var orderedFields = fields.OrderBy(f => f.Order).ToList();

        DataFieldMetadata? parentField = null;
        if (!string.IsNullOrWhiteSpace(def.ParentField))
            parentField = orderedFields.FirstOrDefault(f =>
                string.Equals(f.Name, def.ParentField, StringComparison.OrdinalIgnoreCase));

        return new DataEntityMetadata(
            Type: typeof(DynamicDataObject),
            Name: def.Name,
            Slug: slug,
            Permissions: permissions,
            ShowOnNav: def.ShowOnNav,
            NavGroup: def.NavGroup,
            NavOrder: def.NavOrder,
            IdGeneration: idStrategy,
            ViewType: viewType,
            ParentField: parentField,
            Fields: orderedFields,
            Handlers: handlers,
            Commands: Array.Empty<RemoteCommandMetadata>()
        );
    }

    // ── Field metadata ─────────────────────────────────────────────────────────

    private static DataFieldMetadata? BuildFieldMetadata(VirtualFieldDef fieldDef, int defaultOrder, bool resolveLookups = true)
    {
        if (string.IsNullOrWhiteSpace(fieldDef.Name))
            return null;

        var name = fieldDef.Name;
        var label = !string.IsNullOrWhiteSpace(fieldDef.Label)
            ? fieldDef.Label!
            : DataScaffold.DeCamelcase(name);
        var order = fieldDef.Order > 0 ? fieldDef.Order : defaultOrder;

        var (clrType, fieldType) = MapFieldType(fieldDef);
        var lookup = resolveLookups ? BuildLookupConfig(fieldDef) : null;
        var validation = BuildValidationConfig(fieldDef);

        return new DataFieldMetadata(
            Property: new DynamicPropertyInfo(name, clrType),
            Name: name,
            Label: label,
            FieldType: fieldType,
            Order: order,
            Required: fieldDef.Required,
            List: fieldDef.List,
            View: fieldDef.View,
            Edit: fieldDef.Edit,
            Create: fieldDef.Create,
            ReadOnly: fieldDef.ReadOnly,
            Placeholder: fieldDef.Placeholder,
            Lookup: lookup,
            IdGeneration: IdGenerationStrategy.None,
            Computed: null,
            Upload: null,
            Calculated: null,
            Validation: validation
        );
    }

    // ── Type mapping ───────────────────────────────────────────────────────────

    private static (Type clrType, FormFieldType fieldType) MapFieldType(VirtualFieldDef fieldDef)
    {
        var typeStr = (fieldDef.Type ?? "string").ToLowerInvariant();

        return typeStr switch
        {
            "bool" or "boolean" or "yesno" =>
                (fieldDef.Nullable ? typeof(bool?) : typeof(bool), FormFieldType.YesNo),

            "int" or "integer" =>
                (fieldDef.Nullable ? typeof(int?) : typeof(int), FormFieldType.Integer),

            "decimal" or "number" or "float" or "double" =>
                (fieldDef.Nullable ? typeof(decimal?) : typeof(decimal), FormFieldType.Decimal),

            "datetime" =>
                (fieldDef.Nullable ? typeof(DateTime?) : typeof(DateTime), FormFieldType.DateTime),

            "date" or "dateonly" =>
                (fieldDef.Nullable ? typeof(DateOnly?) : typeof(DateOnly), FormFieldType.DateOnly),

            "time" or "timeonly" =>
                (fieldDef.Nullable ? typeof(TimeOnly?) : typeof(TimeOnly), FormFieldType.TimeOnly),

            "multiline" or "textarea" =>
                (typeof(string), FormFieldType.TextArea),

            "enum" =>
                (CreateVirtualEnumType(fieldDef), FormFieldType.Enum),

            "lookup" =>
                (typeof(string), FormFieldType.LookupList),

            "email" =>
                (typeof(string), FormFieldType.Email),

            _ =>  // "string", "phone", "url", and anything else
                (typeof(string), fieldDef.Multiline ? FormFieldType.TextArea : FormFieldType.String)
        };
    }

    /// <summary>
    /// Creates a real CLR enum type at runtime for enum-typed virtual fields.
    /// The generated enum has integer backing; value names match the JSON "values" list.
    /// Falls back to <see cref="string"/> if no values are provided.
    /// </summary>
    private static Type CreateVirtualEnumType(VirtualFieldDef fieldDef)
    {
        var values = fieldDef.Values;
        if (values == null || values.Count == 0)
            return typeof(string);

        var enumTypeName = $"VirtualEnum_{SanitizeIdentifier(fieldDef.Name)}_{Guid.NewGuid():N}";
        var assemblyName = new AssemblyName(enumTypeName);
        var assemblyBuilder = AssemblyBuilder.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
        var moduleBuilder = assemblyBuilder.DefineDynamicModule("Module");
        var enumBuilder = moduleBuilder.DefineEnum(enumTypeName, TypeAttributes.Public, typeof(int));

        for (int i = 0; i < values.Count; i++)
        {
            var sanitized = SanitizeIdentifier(values[i]);
            if (!string.IsNullOrWhiteSpace(sanitized))
                enumBuilder.DefineLiteral(sanitized, i);
        }

        return enumBuilder.CreateType() ?? typeof(string);
    }

    private static string SanitizeIdentifier(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return "_";

        var chars = new System.Text.StringBuilder();
        foreach (var c in input)
        {
            if (char.IsLetterOrDigit(c) || c == '_')
                chars.Append(c);
        }

        var result = chars.ToString();
        if (result.Length == 0)
            return "_";
        if (char.IsDigit(result[0]))
            result = "_" + result;

        return result;
    }

    // ── Lookup config ──────────────────────────────────────────────────────────

    private static DataLookupConfig? BuildLookupConfig(VirtualFieldDef fieldDef)
    {
        if (!string.Equals(fieldDef.Type, "lookup", StringComparison.OrdinalIgnoreCase))
            return null;
        if (string.IsNullOrWhiteSpace(fieldDef.LookupEntity))
            return null;

        // Resolve target entity by slug (must already be registered)
        if (!DataScaffold.TryGetEntity(fieldDef.LookupEntity!, out var targetMeta))
            return null;

        var valueField = !string.IsNullOrWhiteSpace(fieldDef.LookupValueField)
            ? fieldDef.LookupValueField!
            : "Id";
        var displayField = !string.IsNullOrWhiteSpace(fieldDef.LookupDisplayField)
            ? fieldDef.LookupDisplayField!
            : valueField;

        var queryField = !string.IsNullOrWhiteSpace(fieldDef.LookupQueryField)
            ? fieldDef.LookupQueryField
            : null;

        var queryOperator = (fieldDef.LookupQueryOperator?.ToLowerInvariant()) switch
        {
            "notequals" or "ne" or "!=" => QueryOperator.NotEquals,
            "equals" or "eq" or "==" => QueryOperator.Equals,
            "greaterthan" or "gt" or ">" => QueryOperator.GreaterThan,
            "lessthan" or "lt" or "<" => QueryOperator.LessThan,
            _ => QueryOperator.Contains
        };

        return new DataLookupConfig(
            TargetType: targetMeta.Type,
            ValueField: valueField,
            DisplayField: displayField,
            QueryField: queryField,
            QueryOperator: queryOperator,
            QueryValue: null,
            SortField: null,
            SortDirection: SortDirection.Asc,
            CacheTtl: TimeSpan.FromMinutes(5)
        );
    }

    // ── Validation config ──────────────────────────────────────────────────────

    private static ValidationConfig? BuildValidationConfig(VirtualFieldDef fieldDef)
    {
        if (fieldDef.MinLength == null && fieldDef.MaxLength == null &&
            fieldDef.RangeMin == null && fieldDef.RangeMax == null &&
            string.IsNullOrWhiteSpace(fieldDef.Pattern))
            return null;

        var validators = new List<ValidationAttribute>();

        if (fieldDef.MinLength.HasValue)
            validators.Add(new MinLengthAttribute(fieldDef.MinLength.Value));
        if (fieldDef.MaxLength.HasValue)
            validators.Add(new MaxLengthAttribute(fieldDef.MaxLength.Value));
        if (fieldDef.RangeMin.HasValue && fieldDef.RangeMax.HasValue)
            validators.Add(new RangeAttribute(fieldDef.RangeMin.Value, fieldDef.RangeMax.Value));
        if (!string.IsNullOrWhiteSpace(fieldDef.Pattern))
            validators.Add(new RegexPatternAttribute(fieldDef.Pattern!));

        return new ValidationConfig(
            MinLength: fieldDef.MinLength,
            MaxLength: fieldDef.MaxLength,
            RangeMin: fieldDef.RangeMin,
            RangeMax: fieldDef.RangeMax,
            RegexPattern: fieldDef.Pattern,
            RegexMessage: null,
            IsEmail: false,
            IsUrl: false,
            IsPhone: false,
            CustomValidators: validators,
            ExpressionRules: Array.Empty<ValidationRuleAttribute>()
        );
    }
}
