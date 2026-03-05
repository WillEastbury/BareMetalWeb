using System.Text;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Default implementation of <see cref="IRuntimeEntityCompiler"/>.
/// Assigns deterministic ordinals, validates field types and relationships,
/// generates a schema hash, and produces an immutable <see cref="RuntimeEntityModel"/>.
/// </summary>
public sealed class RuntimeEntityCompiler : IRuntimeEntityCompiler
{
    /// <inheritdoc/>
    public RuntimeEntityModel? Compile(
        EntityDefinition entity,
        IReadOnlyList<FieldDefinition> fields,
        IReadOnlyList<IndexDefinition> indexes,
        IReadOnlyList<ActionDefinition> actions,
        IReadOnlyList<ActionCommandDefinition> actionCommands,
        out IReadOnlyList<string> warnings)
    {
        var warnList = new List<string>();
        warnings = warnList;

        if (string.IsNullOrWhiteSpace(entity.Name))
        {
            warnList.Add($"EntityDefinition {entity.Key}: Name is empty — skipped.");
            return null;
        }

        var slug = !string.IsNullOrWhiteSpace(entity.Slug)
            ? entity.Slug!.Trim().ToLowerInvariant()
            : DataScaffold.ToSlug(DataScaffold.Pluralize(entity.Name));

        var idStrategy = ParseIdStrategy(entity.IdStrategy);
        var permissions = !string.IsNullOrWhiteSpace(entity.Permissions)
            ? entity.Permissions
            : entity.Name;

        // ── Field compilation ──────────────────────────────────────────────────

        // Sort fields: first by existing Ordinal (non-zero), then alphabetically.
        // Fields with Ordinal == 0 get assigned the next available ordinal.
        var sortedFields = new List<FieldDefinition>();
        foreach (var f in fields)
            if (!string.IsNullOrWhiteSpace(f.Name)) sortedFields.Add(f);
        sortedFields.Sort((a, b) =>
        {
            int ordA = a.Ordinal > 0 ? a.Ordinal : int.MaxValue;
            int ordB = b.Ordinal > 0 ? b.Ordinal : int.MaxValue;
            int cmp = ordA.CompareTo(ordB);
            if (cmp != 0) return cmp;
            return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
        });

        // Assign deterministic ordinals
        int nextOrdinal = 1;
        foreach (var f in sortedFields)
        {
            if (f.Ordinal <= 0)
                f.Ordinal = nextOrdinal;
            nextOrdinal = Math.Max(nextOrdinal, f.Ordinal) + 1;
        }

        // Re-sort by assigned ordinal
        sortedFields.Sort((a, b) => a.Ordinal.CompareTo(b.Ordinal));

        var compiledFields = new List<RuntimeFieldModel>(sortedFields.Count);
        foreach (var f in sortedFields)
        {
            var fieldId = !string.IsNullOrWhiteSpace(f.FieldId) ? f.FieldId : f.Key.ToString();
            var label = !string.IsNullOrWhiteSpace(f.Label) ? f.Label! : DataScaffold.DeCamelcase(f.Name);
            var fieldType = MapFormFieldType(f);
            var enumValues = ParsePipeList(f.EnumValues);

            // Validate lookup target
            if (fieldType == FormFieldType.LookupList && !string.IsNullOrWhiteSpace(f.LookupEntitySlug))
            {
                if (!DataScaffold.TryGetEntity(f.LookupEntitySlug!, out _))
                    warnList.Add($"Field '{f.Name}': lookup target '{f.LookupEntitySlug}' not yet registered — lookup may be unavailable.");
            }

            compiledFields.Add(new RuntimeFieldModel(
                FieldId: fieldId,
                Ordinal: f.Ordinal,
                Name: f.Name,
                Label: label,
                FieldType: fieldType,
                IsNullable: f.IsNullable,
                Required: f.Required,
                List: f.List,
                View: f.View,
                Edit: f.Edit,
                Create: f.Create,
                ReadOnly: f.ReadOnly,
                DefaultValue: f.DefaultValue,
                Placeholder: f.Placeholder,
                EnumValues: enumValues,
                LookupEntitySlug: f.LookupEntitySlug,
                LookupValueField: f.LookupValueField,
                LookupDisplayField: f.LookupDisplayField,
                MinLength: f.MinLength,
                MaxLength: f.MaxLength,
                RangeMin: f.RangeMin,
                RangeMax: f.RangeMax,
                Pattern: f.Pattern,
                ChildEntitySlug: f.ChildEntitySlug,
                LookupCopyFields: f.LookupCopyFields,
                CalculatedExpression: f.CalculatedExpression,
                CalculatedDisplayFormat: f.CalculatedDisplayFormat,
                CopyFromParentField: f.CopyFromParentField,
                CopyFromParentSlug: f.CopyFromParentSlug,
                CopyFromParentSourceField: f.CopyFromParentSourceField,
                RelatedDocumentSlug: f.RelatedDocumentSlug,
                RelatedDocumentDisplayField: f.RelatedDocumentDisplayField,
                CascadeFromField: f.CascadeFromField,
                CascadeFilterField: f.CascadeFilterField,
                FieldGroup: f.FieldGroup,
                ColumnSpan: f.ColumnSpan
            ));
        }

        // ── Index compilation ──────────────────────────────────────────────────

        var compiledIndexes = new List<RuntimeIndexModel>(indexes.Count);
        foreach (var idx in indexes)
        {
            compiledIndexes.Add(new RuntimeIndexModel(
                IndexId: idx.Key.ToString(),
                EntityId: idx.EntityId,
                FieldNames: idx.GetFieldList(),
                Type: string.IsNullOrWhiteSpace(idx.Type) ? "secondary" : idx.Type));
        }

        // ── Action compilation ─────────────────────────────────────────────────

        var compiledActions = new List<RuntimeActionModel>();
        foreach (var a in actions)
        {
            if (string.IsNullOrWhiteSpace(a.Name)) continue;
            var actionKey = a.Key.ToString();
            var topLevel = new List<ActionCommandDefinition>();
            foreach (var c in actionCommands)
            {
                if (string.Equals(c.ActionId, actionKey, StringComparison.OrdinalIgnoreCase)
                    && string.IsNullOrWhiteSpace(c.ParentCommandId))
                    topLevel.Add(c);
            }
            topLevel.Sort((x, y) => x.Order.CompareTo(y.Order));

            var compiled = CompileCommands(topLevel, actionCommands, warnList);

            compiledActions.Add(new RuntimeActionModel(
                ActionId: actionKey,
                EntityId: a.EntityId,
                Name: a.Name,
                Label: a.Label ?? a.Name,
                Icon: a.Icon,
                Permission: a.Permission,
                EnabledWhen: a.EnabledWhen,
                Operations: ParsePipeList(a.Operations),
                Commands: compiled,
                Version: a.Version
            ));
        }

        // ── Schema hash ────────────────────────────────────────────────────────

        var schemaHash = ComputeSchemaHash(compiledFields);

        // ── Entity identity ────────────────────────────────────────────────────

        var entityId = !string.IsNullOrWhiteSpace(entity.EntityId) ? entity.EntityId : entity.Key.ToString();

        return new RuntimeEntityModel(
            entityId: entityId,
            name: entity.Name,
            slug: slug,
            permissions: permissions,
            showOnNav: entity.ShowOnNav,
            navGroup: entity.NavGroup,
            navOrder: entity.NavOrder,
            idStrategy: idStrategy,
            version: entity.Version,
            schemaHash: schemaHash,
            formLayout: entity.FormLayout ?? "Standard",
            fields: compiledFields.AsReadOnly(),
            indexes: compiledIndexes.AsReadOnly(),
            actions: compiledActions.AsReadOnly()
        );
    }

    // ── Type mapping ───────────────────────────────────────────────────────────

    /// <summary>
    /// Maps a <see cref="FieldDefinition.Type"/> string to a <see cref="FormFieldType"/>.
    /// </summary>
    private static FormFieldType MapFormFieldType(FieldDefinition f)
    {
        var typeStr = (f.Type ?? "string").Trim().ToLowerInvariant();

        if (f.Multiline || typeStr is "multiline" or "textarea")
            return FormFieldType.TextArea;

        return typeStr switch
        {
            "bool" or "boolean" or "yesno" => FormFieldType.YesNo,
            "int" or "integer" => FormFieldType.Integer,
            "decimal" or "number" or "float" or "double" => FormFieldType.Decimal,
            "datetime" => FormFieldType.DateTime,
            "date" or "dateonly" => FormFieldType.DateOnly,
            "time" or "timeonly" => FormFieldType.TimeOnly,
            "enum" => FormFieldType.Enum,
            "lookup" => FormFieldType.LookupList,
            "childlist" or "child-list" or "child_list" => FormFieldType.ChildList,
            "markdown" or "md" => FormFieldType.Markdown,
            "email" => FormFieldType.Email,
            "country" => FormFieldType.Country,
            "phone" => FormFieldType.String,
            "url" => FormFieldType.String,
            _ => FormFieldType.String
        };
    }

    /// <summary>
    /// Returns the CLR <see cref="Type"/> that corresponds to a <see cref="FormFieldType"/>
    /// and nullable flag, for use when building <see cref="DynamicPropertyInfo"/> instances.
    /// </summary>
    public static Type MapClrType(FormFieldType fieldType, bool isNullable, IReadOnlyList<string> enumValues)
    {
        return fieldType switch
        {
            FormFieldType.YesNo => isNullable ? typeof(bool?) : typeof(bool),
            FormFieldType.Integer => isNullable ? typeof(int?) : typeof(int),
            FormFieldType.Decimal or FormFieldType.Money => isNullable ? typeof(decimal?) : typeof(decimal),
            FormFieldType.DateTime => isNullable ? typeof(DateTime?) : typeof(DateTime),
            FormFieldType.DateOnly => isNullable ? typeof(DateOnly?) : typeof(DateOnly),
            FormFieldType.TimeOnly => isNullable ? typeof(TimeOnly?) : typeof(TimeOnly),
            FormFieldType.Enum => BuildEnumType(enumValues),
            FormFieldType.ChildList => typeof(string), // JSON-serialized child rows
            _ => typeof(string)
        };
    }

    // ── CLR enum type cache ────────────────────────────────────────────────────

    private static readonly Dictionary<string, Type> EnumTypeCache = new(StringComparer.Ordinal);
    private static readonly object EnumTypeLock = new();

    /// <summary>
    /// Builds (and caches) a CLR enum type from the supplied member names.
    /// Returns <see cref="string"/> if the list is empty.
    /// </summary>
    private static Type BuildEnumType(IReadOnlyList<string> enumValues)
    {
        if (enumValues.Count == 0)
            return typeof(string);

        var key = string.Join("|", enumValues);
        lock (EnumTypeLock)
        {
            if (EnumTypeCache.TryGetValue(key, out var cached))
                return cached;
        }

        Type type;
        try
        {
            type = CreateRuntimeEnum(enumValues);
        }
        catch
        {
            // Enum creation failed (e.g. all values were unsanitary) — fall back to string
            return typeof(string);
        }

        lock (EnumTypeLock)
        {
            EnumTypeCache.TryAdd(key, type);
        }

        return type;
    }

    private static Type CreateRuntimeEnum(IReadOnlyList<string> values)
    {
        var enumTypeName = $"RuntimeEnum_{Guid.NewGuid():N}";
        var assemblyName = new System.Reflection.AssemblyName(enumTypeName);
        var assemblyBuilder = System.Reflection.Emit.AssemblyBuilder.DefineDynamicAssembly(
            assemblyName, System.Reflection.Emit.AssemblyBuilderAccess.Run);
        var moduleBuilder = assemblyBuilder.DefineDynamicModule("Module");
        var enumBuilder = moduleBuilder.DefineEnum(enumTypeName,
            System.Reflection.TypeAttributes.Public, typeof(int));

        for (int i = 0; i < values.Count; i++)
        {
            var sanitized = SanitizeIdentifier(values[i]);
            if (!string.IsNullOrEmpty(sanitized))
                enumBuilder.DefineLiteral(sanitized, i);
        }

        var created = enumBuilder.CreateType();
        if (created == null)
            throw new InvalidOperationException($"Failed to create enum type from values: {string.Join(", ", values)}");

        return created;
    }

    private static string SanitizeIdentifier(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty;

        var sb = new StringBuilder();
        foreach (var c in input)
        {
            if (char.IsLetterOrDigit(c) || c == '_')
                sb.Append(c);
        }

        var result = sb.ToString();
        if (result.Length == 0)
            return string.Empty;
        if (char.IsDigit(result[0]))
            result = "_" + result;

        return result;
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private static AutoIdStrategy ParseIdStrategy(string? strategy)
        => (strategy ?? "guid").ToLowerInvariant() switch
        {
            "sequential" => AutoIdStrategy.Sequential,
            "none" => AutoIdStrategy.None,
            _ => AutoIdStrategy.Sequential
        };

    private static IReadOnlyList<string> ParsePipeList(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return Array.Empty<string>();

        return value
            .Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    /// <summary>
    /// FNV-1a hash of field ordinals and type names, used for migration-change detection.
    /// </summary>
    private static string ComputeSchemaHash(IEnumerable<RuntimeFieldModel> fields)
    {
        uint hash = 2166136261u;
        foreach (var f in fields)
        {
            foreach (var c in f.Name)
            {
                hash ^= (byte)c;
                hash *= 16777619u;
            }

            hash ^= (uint)f.Ordinal;
            hash *= 16777619u;

            foreach (var c in f.FieldType.ToString())
            {
                hash ^= (byte)c;
                hash *= 16777619u;
            }
        }

        return hash.ToString("x8");
    }

    // ── Command compilation ────────────────────────────────────────────────────

    /// <summary>
    /// Recursively compiles a flat list of <see cref="ActionCommandDefinition"/> records
    /// (pre-filtered to the correct parent scope) into typed <see cref="ActionCommand"/> objects.
    /// </summary>
    private static IReadOnlyList<ActionCommand> CompileCommands(
        IReadOnlyList<ActionCommandDefinition> definitions,
        IReadOnlyList<ActionCommandDefinition> allCommands,
        List<string> warnings)
    {
        var result = new List<ActionCommand>(definitions.Count);

        foreach (var def in definitions)
        {
            var cmd = CompileCommand(def, allCommands, warnings);
            if (cmd != null)
                result.Add(cmd);
        }

        return result.AsReadOnly();
    }

    private static ActionCommand? CompileCommand(
        ActionCommandDefinition def,
        IReadOnlyList<ActionCommandDefinition> allCommands,
        List<string> warnings)
    {
        var defKey = def.Key.ToString();
        var type = (def.CommandType ?? string.Empty).Trim();

        switch (type.ToLowerInvariant())
        {
            case "assertif":
            {
                if (string.IsNullOrWhiteSpace(def.Condition))
                {
                    warnings.Add($"ActionCommand {defKey}: AssertIf has no Condition — skipped.");
                    return null;
                }

                var severity = ParseSeverity(def.Severity);
                return new AssertIfCommand(
                    Order: def.Order,
                    Condition: def.Condition!,
                    Code: def.ErrorCode ?? defKey,
                    Severity: severity,
                    Message: def.Message ?? string.Empty);
            }

            case "setif":
            {
                if (string.IsNullOrWhiteSpace(def.FieldId))
                {
                    warnings.Add($"ActionCommand {defKey}: SetIf has no FieldId — skipped.");
                    return null;
                }

                return new SetIfCommand(
                    Order: def.Order,
                    Condition: def.Condition ?? "true",
                    FieldId: def.FieldId!,
                    ValueExpression: def.ValueExpression ?? string.Empty);
            }

            case "calculateandsetif":
            {
                if (string.IsNullOrWhiteSpace(def.FieldId))
                {
                    warnings.Add($"ActionCommand {defKey}: CalculateAndSetIf has no FieldId — skipped.");
                    return null;
                }

                return new CalculateAndSetIfCommand(
                    Order: def.Order,
                    Condition: def.Condition ?? "true",
                    FieldId: def.FieldId!,
                    ValueExpression: def.ValueExpression ?? string.Empty);
            }

            case "forset":
            case "forsetsequential":
            {
                if (string.IsNullOrWhiteSpace(def.ListFieldId))
                {
                    warnings.Add($"ActionCommand {defKey}: {type} has no ListFieldId — skipped.");
                    return null;
                }

                // Load sub-commands
                var subDefs = new List<ActionCommandDefinition>();
                foreach (var c in allCommands)
                    if (string.Equals(c.ParentCommandId, defKey, StringComparison.OrdinalIgnoreCase))
                        subDefs.Add(c);
                subDefs.Sort((x, y) => x.Order.CompareTo(y.Order));

                var subCommands = CompileCommands(subDefs, allCommands, warnings);

                if (type.Equals("forsetsequential", StringComparison.OrdinalIgnoreCase))
                    return new ForSetSequentialCommand(
                        Order: def.Order,
                        ListFieldId: def.ListFieldId!,
                        ItemCondition: def.Condition ?? "true",
                        SubCommands: subCommands);

                return new ForSetCommand(
                    Order: def.Order,
                    ListFieldId: def.ListFieldId!,
                    ItemCondition: def.Condition ?? "true",
                    SubCommands: subCommands);
            }

            case "invokeif":
            {
                if (string.IsNullOrWhiteSpace(def.TargetActionId))
                {
                    warnings.Add($"ActionCommand {defKey}: InvokeIf has no TargetActionId — skipped.");
                    return null;
                }

                var paramMap = ParseJsonStringMap(def.ParameterMap, defKey, warnings);

                return new InvokeIfCommand(
                    Order: def.Order,
                    Condition: def.Condition ?? "true",
                    TargetEntityType: def.TargetEntityType ?? string.Empty,
                    TargetActionId: def.TargetActionId!,
                    ParameterMap: paramMap);
            }

            default:
                warnings.Add($"ActionCommand {defKey}: unknown CommandType '{type}' — skipped.");
                return null;
        }
    }

    private static AssertSeverity ParseSeverity(string? severity)
        => (severity ?? "error").ToLowerInvariant() switch
        {
            "warning" or "warn" => AssertSeverity.Warning,
            "info" or "information" => AssertSeverity.Info,
            _ => AssertSeverity.Error,
        };

    private static IReadOnlyDictionary<string, string> ParseJsonStringMap(
        string? json,
        string defKey,
        List<string> warnings)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var dict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            return dict ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            warnings.Add($"ActionCommand {defKey}: ParameterMap is not valid JSON — {ex.Message}");
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }
}
