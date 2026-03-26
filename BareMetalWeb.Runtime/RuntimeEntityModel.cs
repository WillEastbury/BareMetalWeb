using BareMetalWeb.Core;
using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Compiled, immutable representation of a runtime-defined entity.
/// Produced by <see cref="IRuntimeEntityCompiler"/> from persisted
/// <see cref="EntityDefinition"/>, <see cref="FieldDefinition"/>,
/// <see cref="IndexDefinition"/> and <see cref="ActionDefinition"/> records.
/// Registered in <see cref="RuntimeEntityRegistry"/> after startup compilation.
/// </summary>
public sealed class RuntimeEntityModel
{
    /// <param name="entityId">Stable GUID from <see cref="EntityDefinition.EntityId"/>.</param>
    /// <param name="name">Display name.</param>
    /// <param name="slug">URL slug (lower-case, hyphenated).</param>
    /// <param name="permissions">Comma-separated permission tokens.</param>
    /// <param name="showOnNav">Whether to include in the navigation menu.</param>
    /// <param name="navGroup">Navigation group label.</param>
    /// <param name="navOrder">Position within the group.</param>
    /// <param name="idStrategy">Auto-ID strategy.</param>
    /// <param name="version">Schema version number.</param>
    /// <param name="schemaHash">FNV-1a hash of field ordinals and types.</param>
    /// <param name="fields">Compiled field models ordered by ordinal.</param>
    /// <param name="indexes">Compiled index models.</param>
    /// <param name="actions">Compiled action models.</param>
    public RuntimeEntityModel(
        string entityId,
        string name,
        string slug,
        string permissions,
        bool showOnNav,
        string navGroup,
        int navOrder,
        AutoIdStrategy idStrategy,
        int version,
        string schemaHash,
        string formLayout,
        bool enableGetIngress,
        IReadOnlyList<RuntimeFieldModel> fields,
        IReadOnlyList<RuntimeIndexModel> indexes,
        IReadOnlyList<RuntimeActionModel> actions,
        string? rlsOwnerField = null)
    {
        EntityId = entityId;
        Name = name;
        Slug = slug;
        Permissions = permissions;
        ShowOnNav = showOnNav;
        NavGroup = navGroup;
        NavOrder = navOrder;
        IdStrategy = idStrategy;
        Version = version;
        SchemaHash = schemaHash;
        FormLayout = formLayout;
        EnableGetIngress = enableGetIngress;
        Fields = fields;
        Indexes = indexes;
        Actions = actions;
        RlsOwnerField = rlsOwnerField;
    }

    public string EntityId { get; }
    public string Name { get; }
    public string Slug { get; }
    public string Permissions { get; }
    public bool ShowOnNav { get; }
    public string NavGroup { get; }
    public int NavOrder { get; }
    public AutoIdStrategy IdStrategy { get; }
    public int Version { get; }

    /// <summary>FNV-1a hash of field ordinals and types — used for migration-change detection.</summary>
    public string SchemaHash { get; }

    /// <summary>Form layout: "Standard" or "Wizard".</summary>
    public string FormLayout { get; }

    /// <summary>When true, a GET ingress route is registered for this entity.</summary>
    public bool EnableGetIngress { get; }

    /// <summary>When set, names the field used for row-level security ownership checks.</summary>
    public string? RlsOwnerField { get; }

    public IReadOnlyList<RuntimeFieldModel> Fields { get; }
    public IReadOnlyList<RuntimeIndexModel> Indexes { get; }
    public IReadOnlyList<RuntimeActionModel> Actions { get; }

    /// <summary>
    /// Builds a <see cref="DataEntityMetadata"/> that uses <see cref="DataRecord"/> + WAL storage.
    /// Replaces <see cref="DataRecord"/> + JSON; all field access is ordinal-based (~1–2 ns).
    /// </summary>
    public DataEntityMetadata ToEntityMetadata(WalDataProvider walProvider, EntitySchema schema)
    {
        var entityTypeName = Name;
        var fields = new List<DataFieldMetadata>();

        foreach (var f in Fields)
        {
            var clrType = RuntimeEntityCompiler.MapClrType(f.FieldType, f.IsNullable, f.EnumValues);
            // Use schema's 0-based ordinal (not compiler's 1-based f.Ordinal)
            int schemaOrdinal = schema.TryGetOrdinal(f.Name, out var ord) ? ord : -1;

            DataLookupConfig? lookup = null;
            if (f.FieldType == Rendering.Models.FormFieldType.LookupList
                && !string.IsNullOrWhiteSpace(f.LookupEntitySlug)
                && DataScaffold.TryGetEntity(f.LookupEntitySlug!, out var targetMeta))
            {
                lookup = new DataLookupConfig(
                    TargetType: targetMeta.Type,
                    ValueField: f.LookupValueField ?? "Id",
                    DisplayField: f.LookupDisplayField ?? (f.LookupValueField ?? "Id"),
                    QueryField: null,
                    QueryOperator: QueryOperator.Contains,
                    QueryValue: null,
                    SortField: null,
                    SortDirection: SortDirection.Asc,
                    CacheTtl: TimeSpan.FromMinutes(5),
                    TargetSlug: f.LookupEntitySlug
                );
            }

            ValidationConfig? validation = null;
            if (f.MinLength.HasValue || f.MaxLength.HasValue || f.RangeMin.HasValue ||
                f.RangeMax.HasValue || !string.IsNullOrWhiteSpace(f.Pattern))
            {
                var validators = new List<ValidationAttribute>();
                if (f.MinLength.HasValue) validators.Add(new MinLengthAttribute(f.MinLength.Value));
                if (f.MaxLength.HasValue) validators.Add(new MaxLengthAttribute(f.MaxLength.Value));
                if (f.RangeMin.HasValue && f.RangeMax.HasValue)
                    validators.Add(new RangeAttribute(f.RangeMin.Value, f.RangeMax.Value));
                if (!string.IsNullOrWhiteSpace(f.Pattern))
                    validators.Add(new RegexPatternAttribute(f.Pattern!));

                validation = new ValidationConfig(f.MinLength, f.MaxLength, f.RangeMin, f.RangeMax,
                    f.Pattern, null, false, false, false,
                    validators, Array.Empty<ValidationRuleAttribute>());
            }

            fields.Add(new DataFieldMetadata(
                ClrType: clrType,
                Name: f.Name,
                Label: f.Label,
                FieldType: f.FieldType,
                Order: f.Ordinal,
                Required: f.Required,
                List: f.List,
                View: f.View,
                Edit: f.Edit,
                Create: f.Create,
                ReadOnly: f.ReadOnly,
                Placeholder: f.Placeholder,
                Lookup: lookup,
                IdGeneration: IdGenerationStrategy.None,
                Computed: null,
                Upload: null,
                Calculated: null,
                Validation: validation,
                ChildEntitySlug: f.ChildEntitySlug,
                LookupCopyFields: f.LookupCopyFields,
                CalculatedExpression: f.CalculatedExpression,
                CalculatedDisplayFormat: f.CalculatedDisplayFormat,
                CopyFromParentField: f.CopyFromParentField,
                CopyFromParentSlug: f.CopyFromParentSlug,
                CopyFromParentSourceField: f.CopyFromParentSourceField,
                CascadeFromField: f.CascadeFromField,
                CascadeFilterField: f.CascadeFilterField,
                FieldGroup: f.FieldGroup,
                ColumnSpan: f.ColumnSpan,
                RelatedDocument: !string.IsNullOrWhiteSpace(f.RelatedDocumentSlug)
                    && DataScaffold.TryGetEntity(f.RelatedDocumentSlug!, out var relMeta)
                    ? new RelatedDocumentConfig(relMeta.Type, f.RelatedDocumentDisplayField ?? "Id", f.RelatedDocumentSlug)
                    : null,
                EnumValues: f.FieldType == Rendering.Models.FormFieldType.Enum && f.EnumValues.Count > 0
                    ? f.EnumValues
                    : null,
                StorageOrdinal: schemaOrdinal
            ));
        }

        // Build action descriptors from RuntimeActionModel
        var commands = new List<RemoteCommandMetadata>(Actions.Count);
        for (int i = 0; i < Actions.Count; i++)
        {
            var a = Actions[i];
            commands.Add(new RemoteCommandMetadata(
                Invoker: null,
                Name: a.Name,
                Label: a.Label,
                Icon: a.Icon,
                ConfirmMessage: null,
                Destructive: false,
                Permission: a.Permission,
                OverrideEntityPermissions: false,
                Order: i
            ));
        }

        var handlers = new DataEntityHandlers(
            Create: () => schema.CreateRecord(),
            LoadAsync: async (id, ct) =>
            {
                var rec = await walProvider.LoadRecordAsync(id, schema, ct).ConfigureAwait(false);
                return rec;
            },
            SaveAsync: async (obj, ct) =>
            {
                if (obj is DataRecord rec)
                    await walProvider.SaveRecordAsync(rec, schema, ct).ConfigureAwait(false);
            },
            DeleteAsync: (id, ct) => walProvider.DeleteRecordAsync(id, schema, ct),
            QueryAsync: async (query, ct) =>
            {
                var items = await walProvider.QueryRecordsAsync(schema, query, ct).ConfigureAwait(false);
                var result = new List<BaseDataObject>();
                foreach (var item in items) result.Add((BaseDataObject)item);
                return result;
            },
            CountAsync: (query, ct) => walProvider.CountRecordsAsync(schema, query, ct)
        );

        // Detect self-referential lookup for ParentField (e.g. Employee.ManagerId → employees)
        DataFieldMetadata? parentField = null;
        foreach (var fm in fields)
        {
            if (fm.Lookup != null
                && string.Equals(fm.Lookup.TargetSlug, Slug, StringComparison.OrdinalIgnoreCase))
            {
                parentField = fm;
                break;
            }
        }

            var docRelFields = new List<DataFieldMetadata>();
            foreach (var f in fields)
                if (f.RelatedDocument != null) docRelFields.Add(f);

            return new DataEntityMetadata(
            Type: typeof(DataRecord),
            Name: Name,
            Slug: Slug,
            Permissions: Permissions,
            ShowOnNav: ShowOnNav,
            NavGroup: NavGroup,
            NavOrder: NavOrder,
            IdGeneration: IdStrategy,
            ViewType: ViewType.Table,
            ParentField: parentField,
            Fields: fields,
            Handlers: handlers,
            Commands: commands,
            DocumentRelationFields: docRelFields,
            EnableGetIngress: EnableGetIngress,
            RlsOwnerField: RlsOwnerField
        );
    }
}
