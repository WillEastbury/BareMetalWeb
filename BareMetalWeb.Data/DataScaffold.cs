using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using BareMetalWeb.Data;
using BareMetalWeb.Data.ExpressionEngine;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Core;

public sealed record DataFieldMetadata(
    Type ClrType,
    string Name,
    string Label,
    FormFieldType FieldType,
    int Order,
    bool Required,
    bool List,
    bool View,
    bool Edit,
    bool Create,
    bool ReadOnly,
    string? Placeholder,
    DataLookupConfig? Lookup,
    IdGenerationStrategy IdGeneration,
    ComputedFieldConfig? Computed,
    UploadFieldConfig? Upload,
    CalculatedFieldAttribute? Calculated,
    ValidationConfig? Validation,
    bool IsIndexed = false,
    RelatedDocumentConfig? RelatedDocument = null,
    string? ChildEntitySlug = null,
    string? LookupCopyFields = null,
    string? CalculatedExpression = null,
    string? CalculatedDisplayFormat = null,
    string? CopyFromParentField = null,
    string? CopyFromParentSlug = null,
    string? CopyFromParentSourceField = null,
    string? CascadeFromField = null,
    string? CascadeFilterField = null,
    string? FieldGroup = null,
    int ColumnSpan = 12,
    DataIndexAttribute? DataIndex = null,
    bool HasSingletonFlag = false,
    /// <summary>
    /// Ordered allowed values for Enum fields on virtual (gallery/runtime) entities.
    /// Null for compiled C# entities whose allowed values are derived from the CLR enum type.
    /// When set, rendering prefers this list over <see cref="ClrType"/> for enum option building
    /// and for converting integer ordinals to display names (e.g. timetable day headers).
    /// </summary>
    IReadOnlyList<string>? EnumValues = null,
    /// <summary>
    /// Storage ordinal in the entity's <c>_values[]</c> array.
    /// -1 means ordinal-indexed access is not available (entity must provide GetFieldMap).
    /// Set during entity compilation in DataScaffold.
    /// </summary>
    int StorageOrdinal = -1
)
{
    // Lazily compiled delegates — use ordinal-indexed _values[] when available,
    // Ordinal-indexed getter/setter via _values[].
    private Func<object, object?>? _getValueFn;
    private Action<object, object?>? _setValueFn;

    /// <summary>Reads this field's value from a boxed entity instance via ordinal-indexed _values access.</summary>
    public Func<object, object?> GetValueFn => _getValueFn ??= BuildGetter();

    /// <summary>Writes a value to this field on a boxed entity instance via ordinal-indexed _values access.</summary>
    public Action<object, object?> SetValueFn => _setValueFn ??= BuildSetter();

    private Func<object, object?> BuildGetter()
    {
        if (StorageOrdinal < 0)
            throw new InvalidOperationException(
                $"Field '{Name}' has no storage ordinal. All entity properties must be backed by _values[]. " +
                $"Ensure the entity class uses ordinal-indexed storage in BaseDataObject.");
        var ord = StorageOrdinal;
        return obj => ((BareMetalWeb.Data.BaseDataObject)obj).GetFieldValue(ord);
    }

    private Action<object, object?> BuildSetter()
    {
        if (StorageOrdinal < 0)
            throw new InvalidOperationException(
                $"Field '{Name}' has no storage ordinal. All entity properties must be backed by _values[]. " +
                $"Ensure the entity class uses ordinal-indexed storage in BaseDataObject.");
        var ord = StorageOrdinal;
        return (obj, val) => ((BareMetalWeb.Data.BaseDataObject)obj).SetFieldValue(ord, val);
    }
}

public sealed record DataEntityMetadata(
    [property: DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] Type Type,
    string Name,
    string Slug,
    string Permissions,
    bool ShowOnNav,
    string? NavGroup,
    int NavOrder,
    AutoIdStrategy IdGeneration,
    ViewType ViewType,
    DataFieldMetadata? ParentField,
    IReadOnlyList<DataFieldMetadata> Fields,
    DataEntityHandlers Handlers,
    IReadOnlyList<RemoteCommandMetadata> Commands,
    string? DefaultSortField = null,
    SortDirection DefaultSortDirection = SortDirection.Asc,
    IReadOnlyList<DataFieldMetadata>? DocumentRelationFields = null,
    IReadOnlyList<ValidationRuleAttribute>? EntityValidationRules = null,
    bool EnableGetIngress = false,
    string? RlsOwnerField = null
)
{
    private DataFieldMetadata[]? _listFields;
    private DataFieldMetadata[]? _viewFields;
    private DataFieldMetadata[]? _createFields;
    private DataFieldMetadata[]? _editFields;
    private Dictionary<string, DataFieldMetadata>? _fieldsByName;

    /// <summary>Fields visible in list views, pre-sorted by Order.</summary>
    public DataFieldMetadata[] ListFields => _listFields ??= BuildFilteredFields(f => f.List);

    /// <summary>Fields visible in detail views, pre-sorted by Order.</summary>
    public DataFieldMetadata[] ViewFields => _viewFields ??= BuildFilteredFields(f => f.View);

    /// <summary>Fields available during create, pre-sorted by Order.</summary>
    public DataFieldMetadata[] CreateFields => _createFields ??= BuildFilteredFields(f => f.Create);

    /// <summary>Fields available during edit, pre-sorted by Order.</summary>
    public DataFieldMetadata[] EditFields => _editFields ??= BuildFilteredFields(f => f.Edit);

    /// <summary>O(1) field lookup by name (case-insensitive). Lazy-built on first access.</summary>
    public Dictionary<string, DataFieldMetadata> FieldsByName =>
        _fieldsByName ??= BuildFieldsByName();

    private Dictionary<string, DataFieldMetadata> BuildFieldsByName()
    {
        var dict = new Dictionary<string, DataFieldMetadata>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in Fields)
            dict[f.Name] = f;
        return dict;
    }

    /// <summary>Try to find a field by name in O(1). Returns null if not found.</summary>
    public DataFieldMetadata? FindField(string name) =>
        FieldsByName.TryGetValue(name, out var field) ? field : null;

    /// <summary>
    /// Pre-computed flag: <c>true</c> when <see cref="RlsOwnerField"/> equals "CreatedBy"
    /// (case-insensitive). Used by <see cref="RowLevelSecurity"/> to avoid a per-record
    /// string comparison on the hot path.
    /// </summary>
    public bool RlsUsesCreatedBy { get; } =
        string.Equals(RlsOwnerField, "CreatedBy", StringComparison.OrdinalIgnoreCase);

    private DataFieldMetadata[] BuildFilteredFields(Func<DataFieldMetadata, bool> predicate)
    {
        int count = 0;
        foreach (var f in Fields) if (predicate(f)) count++;
        var result = new DataFieldMetadata[count];
        int idx = 0;
        foreach (var f in Fields) if (predicate(f)) result[idx++] = f;
        return result;
    }
}

public sealed record DataEntityHandlers(
    Func<BaseDataObject> Create,
    Func<uint, CancellationToken, ValueTask<BaseDataObject?>> LoadAsync,
    Func<BaseDataObject, CancellationToken, ValueTask> SaveAsync,
    Func<uint, CancellationToken, ValueTask> DeleteAsync,
    Func<QueryDefinition?, CancellationToken, ValueTask<IEnumerable<BaseDataObject>>> QueryAsync,
    Func<QueryDefinition?, CancellationToken, ValueTask<int>> CountAsync
);

public static class DataScaffold
{
    private static readonly ConcurrentDictionary<string, DataEntityMetadata> EntitiesBySlug = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, DataEntityMetadata> EntitiesByName = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<Type, DataEntityMetadata> EntitiesByType = new();
    private static readonly NullabilityInfoContext NullabilityContext = new();
    private static readonly ConcurrentDictionary<string, LookupCacheEntry> LookupCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Callback invoked when entity or field metadata changes.
    /// Used by the intelligence module to rebuild the trimmed model.
    /// </summary>
    public static Action? OnMetadataChanged;

    // Max number of entries in LookupCache before expired entries are pruned.
    private const int LookupCacheMaxSize = 500;
    // Hard upper bound — if the cache exceeds this after pruning, clear it entirely.
    private const int MaxLookupCacheEntries = 10_000;
    // Minimum ticks between successive LookupCache prune sweeps (60 seconds).
    private static readonly long LookupCachePruneCooldownTicks = TimeSpan.FromSeconds(60).Ticks;
    private static long _lastLookupCachePruneTicks;
    private static readonly IIdGenerator IdGenerator = new DefaultIdGenerator();
    // Cached compiled property accessor delegates — avoids per-call PropertyInfo.GetValue reflection.
    private static readonly ConcurrentDictionary<(string, string), Func<object, object?>?> PropertyAccessorCache = new();
    private static readonly ConcurrentDictionary<Type, Func<object>> ListFactoryCache = new();
    private static readonly ConcurrentDictionary<Type, Func<object>> InstanceFactoryCache = new();
    private static readonly ConcurrentDictionary<(Type, Type), Func<object>> DictFactoryCache = new();
    private static readonly ConcurrentDictionary<Type, Dictionary<string, object>> EnumLookupCache = new();

    /// <summary>
    /// Returns a cached case-insensitive name→value lookup for the given enum type.
    /// Avoids Enum.Parse() reflection on every call.
    /// </summary>
    public static Dictionary<string, object> GetEnumLookup(Type enumType)
    {
        return EnumLookupCache.GetOrAdd(enumType, static t =>
        {
            var names = Enum.GetNames(t);
            var underlyingValues = Enum.GetValuesAsUnderlyingType(t);
            var dict = new Dictionary<string, object>(names.Length, StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < names.Length; i++)
                dict[names[i]] = Enum.ToObject(t, underlyingValues.GetValue(i)!);
            return dict;
        });
    }

    /// <summary>Compile Expression.New for a type and return a cached factory delegate (no Activator.CreateInstance).</summary>
    private static Func<object> CompileFactory([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] Type type)
    {
        // AOT-safe: use Activator.CreateInstance instead of Expression.Lambda.Compile()
        return () => Activator.CreateInstance(type)!;
    }

    /// <summary>
    /// Fallback JSON AST (serialized) used when expression parsing fails.
    /// Evaluates to the literal 0, keeping the field blank rather than crashing.
    /// </summary>
    private const string FallbackAstJson = "{\"t\":\"lit\",\"v\":0}";

    /// <summary>
    /// Fallback JSON AST as an object for use in metadata dictionaries (avoids re-parsing the JSON string).
    /// </summary>
    private static readonly Dictionary<string, object?> FallbackAstObject = new() { ["t"] = "lit", ["v"] = 0 };

    /// <summary>
    /// Number of lookup records above which a search dialog is used instead of a full dropdown.
    /// Configurable via LookupSearch:LargeListThreshold in appsettings.json. Default: 20.
    /// </summary>
    public static int LargeListThreshold { get; set; } = 20;

    private sealed record LookupCacheEntry(IReadOnlyList<KeyValuePair<string, string>> Options, bool IsLarge, DateTime ExpiresUtc);

    internal static class DataEntityMetadataCache<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] T> where T : BaseDataObject, new()
    {
        public static readonly DataEntityMetadata? Metadata = Build();

        private static DataEntityMetadata? Build()
        {
            return BuildEntityMetadata<T>();
        }
    }

    private static volatile IReadOnlyList<DataEntityMetadata>? _cachedEntityList;

    public static IReadOnlyList<DataEntityMetadata> Entities
    {
        get
        {
            return _cachedEntityList ?? RebuildEntityList();
        }
    }

    private static IReadOnlyList<DataEntityMetadata> RebuildEntityList()
    {
        var list = new List<DataEntityMetadata>(EntitiesBySlug.Values);
        list.Sort((a, b) =>
        {
            int cmp = a.NavOrder.CompareTo(b.NavOrder);
            return cmp != 0 ? cmp : string.Compare(a.Name, b.Name, StringComparison.Ordinal);
        });
        _cachedEntityList = list;
        return list;
    }

    /// <summary>Invalidates the cached entity list. Called when entities are registered.</summary>
    private static void InvalidateEntityListCache() => _cachedEntityList = null;

    public static bool RegisterEntity<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] T>() where T : BaseDataObject, new()
    {
        var type = typeof(T);
        var metadata = DataEntityMetadataCache<T>.Metadata;
        if (metadata == null)
            return false;

        // Build EntitySchema for compiled entities so every instance carries its
        // entity name via BaseDataObject.Schema — eliminating .GetType() lookups.
        var schema = BuildSchemaFromMetadata(metadata);
        var originalCreate = metadata.Handlers.Create;
        var wrappedHandlers = metadata.Handlers with
        {
            Create = () =>
            {
                var instance = originalCreate();
                instance.Schema = schema;
                return instance;
            }
        };
        var enriched = metadata with { Handlers = wrappedHandlers };

        EntitiesBySlug[enriched.Slug] = enriched;
        EntitiesByName[enriched.Name] = enriched;
        EntitiesByType[type] = enriched;
        InvalidateEntityListCache();

        // Ensure the serializer can instantiate this type without reflection
        BinaryObjectSerializer.RegisterKnownType<T>();

        return true;
    }

    /// <summary>
    /// Registers a pre-built <see cref="DataEntityMetadata"/> directly.
    /// Used for virtual entities whose metadata is constructed from JSON rather than
    /// compiled C# attributes. The entity is indexed by slug only (not by CLR type).
    /// </summary>
    public static bool RegisterVirtualEntity(DataEntityMetadata metadata)
    {
        if (metadata == null)
            return false;

        EntitiesBySlug[metadata.Slug] = metadata;
        EntitiesByName[metadata.Name] = metadata;
        InvalidateEntityListCache();

        return true;
    }

    public static async ValueTask<object?> LoadAsync(DataEntityMetadata metadata, uint key, CancellationToken cancellationToken = default)
    {
        return await metadata.Handlers.LoadAsync(key, cancellationToken);
    }

    public static async ValueTask SaveAsync(DataEntityMetadata metadata, object instance, CancellationToken cancellationToken = default)
    {
        await metadata.Handlers.SaveAsync((BaseDataObject)instance, cancellationToken);

        var slug = metadata.Slug;
        if ((string.Equals(slug, "app-settings", StringComparison.OrdinalIgnoreCase)
             || string.Equals(slug, "settings", StringComparison.OrdinalIgnoreCase))
            && instance is BaseDataObject setting)
        {
            var settingIdField = metadata.FindField("SettingId");
            var settingId = settingIdField?.GetValueFn(setting)?.ToString();
            if (!string.IsNullOrWhiteSpace(settingId))
                SettingsService.InvalidateCache(settingId);
        }

        // Invalidate RBAC cache when security entities change
        if (string.Equals(slug, "security-groups", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(slug, "roles", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(slug, "permissions", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(slug, "users", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(slug, "system-principals", StringComparison.OrdinalIgnoreCase))
        {
            PermissionResolver.Invalidate();
        }

        // Invalidate domain event subscription cache
        if (string.Equals(slug, "domain-event-subscriptions", StringComparison.OrdinalIgnoreCase))
        {
            DomainEventDispatcher.Invalidate();
        }

        // Invalidate module registry cache
        if (string.Equals(slug, "modules", StringComparison.OrdinalIgnoreCase))
        {
            ModuleRegistry.Invalidate();
        }

        // Invalidate intelligence model when entity metadata changes
        if (string.Equals(slug, "entity-definitions", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(slug, "field-definitions", StringComparison.OrdinalIgnoreCase))
        {
            OnMetadataChanged?.Invoke();
        }
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> _sequenceSeeded = new(StringComparer.OrdinalIgnoreCase);

    public static async ValueTask ApplyAutoIdAsync(DataEntityMetadata metadata, BaseDataObject instance, CancellationToken cancellationToken = default)
    {
        switch (metadata.IdGeneration)
        {
            case AutoIdStrategy.Sequential:
            {
                // Seed the persistent counter from existing data on first use after startup
                // (migration path for deployments that pre-date the persistent counter).
                if (!_sequenceSeeded.ContainsKey(metadata.Name))
                {
                    var existing = await metadata.Handlers.QueryAsync(null, cancellationToken);
                    uint max = 0;
                    foreach (var obj in existing)
                    {
                        if (obj.Key > max)
                            max = obj.Key;
                    }
                    var provider = DataStoreProvider.PrimaryProvider;
                    if (provider != null)
                        provider.SeedSequentialKey(metadata.Type.Name, max);
                    else
                        IdSequenceProvider.SeedIfHigher(metadata.Name, max);
                    _sequenceSeeded[metadata.Name] = true;
                }
                var idProvider = DataStoreProvider.PrimaryProvider;
                instance.Key = idProvider != null
                    ? idProvider.NextSequentialKey(metadata.Type.Name)
                    : IdSequenceProvider.NextKey(metadata.Name);
                break;
            }

            case AutoIdStrategy.None:
            {
                // If any field uses field-level sequential generation, seed and assign here
                // to ensure the ID survives application restarts without duplicates.
                DataFieldMetadata? seqField = null;
                foreach (var f in metadata.Fields)
                {
                    if (f.IdGeneration == IdGenerationStrategy.Sequential &&
                        string.Equals(f.Name, nameof(BaseDataObject.Key), StringComparison.Ordinal))
                    {
                        seqField = f;
                        break;
                    }
                }

                if (seqField != null && !_sequenceSeeded.ContainsKey(metadata.Name))
                {
                    // One-time scan to seed the persistent counter from existing data
                    // (handles the upgrade migration case where the counter file is absent).
                    var existing = await metadata.Handlers.QueryAsync(null, cancellationToken);
                    uint max = 0;
                    foreach (var obj in existing)
                    {
                        if (obj.Key > max)
                            max = obj.Key;
                    }
                    var provider = DataStoreProvider.PrimaryProvider;
                    if (provider != null)
                    {
                        provider.SeedSequentialKey(metadata.Type.Name, max);
                        // Re-assign the Key so the seeded counter is used (overrides the
                        // temporary value that DefaultIdGenerator set from the un-seeded counter).
                        instance.Key = provider.NextSequentialKey(metadata.Type.Name);
                    }
                    else
                    {
                        IdSequenceProvider.SeedIfHigher(metadata.Name, max);
                        instance.Key = IdSequenceProvider.NextKey(metadata.Name);
                    }
                    _sequenceSeeded[metadata.Name] = true;
                }
                else if (instance.Key == 0)
                {
                    throw new InvalidOperationException($"Entity {metadata.Name} requires a manually specified Key (IdGeneration = None).");
                }
                break;
            }
        }
    }

    public static async ValueTask ApplyComputedFieldsAsync(DataEntityMetadata metadata, BaseDataObject instance, ComputedTrigger trigger, CancellationToken cancellationToken = default)
    {
        await ComputedFieldService.ApplyComputedValuesAsync(metadata, instance, trigger, cancellationToken);
    }

    public static async ValueTask DeleteAsync(DataEntityMetadata metadata, uint key, CancellationToken cancellationToken = default)
    {
        await metadata.Handlers.DeleteAsync(key, cancellationToken);
    }

    public static async ValueTask<IEnumerable> QueryAsync(DataEntityMetadata metadata, QueryDefinition? query = null, CancellationToken cancellationToken = default)
    {
        var payload = await metadata.Handlers.QueryAsync(query, cancellationToken);
        return payload;
    }

    public static async ValueTask<int> CountAsync(DataEntityMetadata metadata, QueryDefinition? query = null, CancellationToken cancellationToken = default)
    {
        return await metadata.Handlers.CountAsync(query, cancellationToken);
    }

    public static bool TryGetEntity(string slug, out DataEntityMetadata metadata)
    {
        return EntitiesBySlug.TryGetValue(slug, out metadata!);
    }

    public static DataEntityMetadata? GetEntityByType(Type type)
    {
        return EntitiesByType.TryGetValue(type, out var metadata) ? metadata : null;
    }

    /// <summary>
    /// Looks up entity metadata by entity name (e.g. "Orders", "Customer").
    /// Preferred over <see cref="GetEntityByType"/> — avoids runtime type detection.
    /// </summary>
    public static DataEntityMetadata? GetEntityByName(string name)
    {
        if (string.IsNullOrEmpty(name))
            return null;
        return EntitiesByName.TryGetValue(name, out var metadata) ? metadata : null;
    }

    /// <summary>
    /// Builds an <see cref="EntitySchema"/> from compiled entity metadata.
    /// Allows compiled entities to carry Schema on every instance,
    /// enabling name-based entity identification without .GetType().
    /// </summary>
    private static EntitySchema BuildSchemaFromMetadata(DataEntityMetadata metadata)
    {
        var builder = new EntitySchema.Builder(metadata.Name, metadata.Slug);
        foreach (var f in metadata.Fields)
        {
            var fieldType = MapClrTypeToFieldType(f.ClrType);
            builder.AddField(
                name: f.Name,
                type: fieldType,
                clrType: f.ClrType,
                nullable: Nullable.GetUnderlyingType(f.ClrType) != null,
                required: f.Required);
        }
        return builder.Build();
    }

    /// <summary>Maps a CLR type to the compact FieldType used in schemas.</summary>
    private static FieldType MapClrTypeToFieldType(Type clrType)
    {
        var effective = Nullable.GetUnderlyingType(clrType) ?? clrType;
        if (effective == typeof(bool)) return FieldType.Bool;
        if (effective == typeof(int)) return FieldType.Int32;
        if (effective == typeof(uint)) return FieldType.UInt32;
        if (effective == typeof(long)) return FieldType.Int64;
        if (effective == typeof(decimal)) return FieldType.Decimal;
        if (effective == typeof(DateTime)) return FieldType.DateTime;
        if (effective == typeof(DateOnly)) return FieldType.DateOnly;
        if (effective == typeof(TimeOnly)) return FieldType.TimeOnly;
        if (effective == typeof(double)) return FieldType.Float64;
        if (effective == typeof(float)) return FieldType.Float32;
        if (effective == typeof(Guid)) return FieldType.Guid;
        if (effective == typeof(byte)) return FieldType.Byte;
        if (effective == typeof(short)) return FieldType.Int16;
        if (effective.IsEnum) return FieldType.EnumInt32;
        return FieldType.StringUtf8;
    }

    private const int MaxPageSize = 10000;

    public static QueryDefinition BuildQueryDefinition(IDictionary<string, string?> query, DataEntityMetadata metadata)
    {
        var definition = new QueryDefinition();

        // Global search across all list fields
        if (query.TryGetValue("q", out var queryText) && !string.IsNullOrWhiteSpace(queryText))
        {
            var group = new QueryGroup { Logic = QueryGroupLogic.Or };
            foreach (var field in metadata.ListFields)
            {
                group.Clauses.Add(new QueryClause
                {
                    Field = field.Name,
                    Operator = QueryOperator.Contains,
                    Value = queryText
                });
            }
            definition.Groups.Add(group);
        }

        // Per-field filters using f_{fieldname}=value pattern
        foreach (var field in metadata.Fields)
        {
            var filterKey = $"f_{field.Name}";
            if (query.TryGetValue(filterKey, out var filterValue) && !string.IsNullOrWhiteSpace(filterValue))
            {
                var opKey = $"op_{field.Name}";
                var op = QueryOperator.Contains; // Default operator
                
                if (query.TryGetValue(opKey, out var opValue) && !string.IsNullOrWhiteSpace(opValue))
                {
                    op = ParseOperator(opValue);
                }
                else
                {
                    // Auto-select operator based on field type
                    op = GetDefaultOperatorForField(field);
                }

                definition.Clauses.Add(new QueryClause
                {
                    Field = field.Name,
                    Operator = op,
                    Value = filterValue
                });
            }
        }

        // Legacy single field filter support (backward compatibility)
        if (query.TryGetValue("field", out var fieldName) && query.TryGetValue("value", out var value) && !string.IsNullOrWhiteSpace(fieldName))
        {
            // Validate field name exists in entity schema to prevent injection
            if (metadata.FindField(fieldName) != null)
            {
                var op = QueryOperator.Equals;
                if (query.TryGetValue("op", out var opValue) && !string.IsNullOrWhiteSpace(opValue))
                {
                    op = ParseOperator(opValue);
                }

                definition.Clauses.Add(new QueryClause
                {
                    Field = fieldName,
                    Operator = op,
                    Value = value
                });
            }
        }

        if (query.TryGetValue("sort", out var sortField) && !string.IsNullOrWhiteSpace(sortField))
        {
            var direction = SortDirection.Asc;
            if (query.TryGetValue("dir", out var dir) && string.Equals(dir, "desc", StringComparison.OrdinalIgnoreCase))
                direction = SortDirection.Desc;

            definition.Sorts.Add(new SortClause
            {
                Field = sortField,
                Direction = direction
            });
        }
        else if (!string.IsNullOrWhiteSpace(metadata.DefaultSortField))
        {
            definition.Sorts.Add(new SortClause
            {
                Field = metadata.DefaultSortField,
                Direction = metadata.DefaultSortDirection
            });
        }

        if (query.TryGetValue("skip", out var skipStr) && int.TryParse(skipStr, out var skipVal))
            definition.Skip = skipVal;

        if (query.TryGetValue("top", out var topStr) && int.TryParse(topStr, out var topVal))
            definition.Top = Math.Min(Math.Max(1, topVal), MaxPageSize);

        return definition;
    }

    private static QueryOperator ParseOperator(string opValue)
    {
        return opValue.Trim().ToLowerInvariant() switch
        {
            "contains" => QueryOperator.Contains,
            "startswith" => QueryOperator.StartsWith,
            "endswith" => QueryOperator.EndsWith,
            "in" => QueryOperator.In,
            "notin" => QueryOperator.NotIn,
            "nin" => QueryOperator.NotIn,
            "gt" => QueryOperator.GreaterThan,
            "lt" => QueryOperator.LessThan,
            "gte" => QueryOperator.GreaterThanOrEqual,
            "lte" => QueryOperator.LessThanOrEqual,
            "ne" => QueryOperator.NotEquals,
            "neq" => QueryOperator.NotEquals,
            "notequals" => QueryOperator.NotEquals,
            "eq" => QueryOperator.Equals,
            "=" => QueryOperator.Equals,
            "equals" => QueryOperator.Equals,
            _ => QueryOperator.Equals
        };
    }

    private static QueryOperator GetDefaultOperatorForField(DataFieldMetadata field)
    {
        // For numeric and date fields, default to equals
        var fieldType = field.ClrType;
        var underlyingType = Nullable.GetUnderlyingType(fieldType) ?? fieldType;
        
        if (underlyingType == typeof(int) || underlyingType == typeof(long) || 
            underlyingType == typeof(decimal) || underlyingType == typeof(double) ||
            underlyingType == typeof(float) || underlyingType == typeof(DateTime) ||
            underlyingType == typeof(DateTimeOffset) || underlyingType == typeof(DateOnly) ||
            underlyingType == typeof(TimeOnly))
        {
            return QueryOperator.Equals;
        }

        // For strings and everything else, default to Contains for partial matching
        return QueryOperator.Contains;
    }

    /// <summary>
    /// Applies auto-generated ID values to an entity instance based on field metadata.
    /// Should be called after creating a new instance but before setting user-provided values.
    /// For new entities, always generates IDs for fields marked with IdGeneration attribute.
    /// </summary>
    /// <param name="metadata">The entity metadata containing field definitions.</param>
    /// <param name="instance">The entity instance to apply IDs to.</param>
    public static void ApplyAutoGeneratedIds(DataEntityMetadata metadata, object instance)
    {
        foreach (var field in metadata.Fields)
        {
            if (field.IdGeneration == IdGenerationStrategy.None)
                continue;

            // Always generate key for fields with IdGeneration attribute
            // This is called only for new entity creation
            var generatedKey = IdGenerator.GenerateKey(metadata.Type);
            field.SetValueFn(instance, generatedKey);
        }
    }

    public static IReadOnlyList<(string Label, string Value)> BuildViewRows(DataEntityMetadata metadata, object instance)
    {
        var rows = new List<(string Label, string Value)>();
        foreach (var field in metadata.ViewFields)
        {
            var value = field.GetValueFn(instance);
            if (field.Lookup != null)
            {
                var lookupOptions = GetLookupOptions(field.Lookup);
                var lookupMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var opt in lookupOptions)
                    lookupMap[opt.Key] = opt.Value;
                var key = value?.ToString() ?? string.Empty;
                var display = lookupMap.TryGetValue(key, out var resolved) ? resolved : key;
                rows.Add((field.Label, FormatLookupDisplay(key, display)));
                continue;
            }

            if (value is StoredFileData storedFile)
            {
                rows.Add((field.Label, storedFile.FileName));
                continue;
            }

            rows.Add((field.Label, ToDisplayString(value, field.ClrType)));
        }

        return rows;
    }

    public static IReadOnlyList<string> BuildListHeaders(DataEntityMetadata metadata, bool includeActions, bool includeBulkSelection = false)
    {
        var listFields = new List<DataFieldMetadata>();
        foreach (var f in metadata.Fields)
        {
            if (f.List)
                listFields.Add(f);
        }
        listFields.Sort((a, b) => a.Order.CompareTo(b.Order));
        var headers = new List<string>(listFields.Count);
        foreach (var f in listFields)
            headers.Add(f.Label);

        if (includeActions)
            headers.Insert(0, "Actions");
        
        if (includeBulkSelection)
            headers.Insert(0, "<input type=\"checkbox\" data-select-all-checkbox aria-label=\"Select all\" />");

        return headers;
    }

    /// <summary>
    /// Gets metadata about nested/embedded child lists in an entity
    /// </summary>
    public static IReadOnlyList<(DataFieldMetadata Field, Type ChildType)> GetNestedComponents(DataEntityMetadata metadata)
    {
        var nested = new List<(DataFieldMetadata, Type)>();
        foreach (var field in metadata.ViewFields)
        {
            if (IsChildListType(field.ClrType, out var childType))
            {
                nested.Add((field, childType));
            }
        }
        return nested;
    }

    /// <summary>
    /// Builds serialisable schema metadata for the child fields of a sub-list field.
    /// Returns null when the field is not a List&lt;T&gt; child-list type.
    /// Used by the VNext SPA metadata endpoint so the client can render proper
    /// modal-based editors with lookup / calculated / enum support.
    /// Does NOT load lookup options from the data store – the VNext client fetches
    /// those at runtime via the lookup API.
    /// </summary>
    public static IReadOnlyList<Dictionary<string, object?>>? BuildSubFieldSchemas(DataFieldMetadata field)
    {
        // Metadata-driven child list: virtual entity with ChildEntitySlug (no CLR List<T> type available)
        if (field.FieldType == FormFieldType.ChildList
            && !string.IsNullOrWhiteSpace(field.ChildEntitySlug)
            && TryGetEntity(field.ChildEntitySlug!, out var childMeta))
        {
            return BuildSubFieldSchemasFromEntity(childMeta, field);
        }

        if (!IsChildListType(field.ClrType, out var childType))
            return null;

        var result = new List<Dictionary<string, object?>>();

        var properties = childType.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        Array.Sort(properties, (a, b) => string.CompareOrdinal(a.Name, b.Name));

        foreach (var prop in properties)
        {
            if (!prop.CanRead || !prop.CanWrite) continue;

            var fieldAttr  = prop.GetCustomAttribute<DataFieldAttribute>();
            if (fieldAttr == null || (!fieldAttr.Create && !fieldAttr.Edit)) continue;

            var lookupAttr  = prop.GetCustomAttribute<DataLookupAttribute>();
            var calcAttr    = prop.GetCustomAttribute<CalculatedFieldAttribute>();
            var copyParAttr = prop.GetCustomAttribute<CopyFromParentAttribute>();

            var label      = fieldAttr.Label ?? DeCamelcaseWithId(prop.Name);
            var effectiveType = fieldAttr.FieldType == FormFieldType.Unknown
                ? MapFieldType(prop.PropertyType)
                : fieldAttr.FieldType;
            if (lookupAttr != null) effectiveType = FormFieldType.LookupList;

            var fd = new Dictionary<string, object?>
            {
                ["name"]     = prop.Name,
                ["label"]    = label,
                ["type"]     = effectiveType.ToString(),
                ["required"] = fieldAttr.Required,
                ["readOnly"] = calcAttr != null
            };

            // Lookup metadata (no DB call – just attribute data)
            if (lookupAttr != null)
            {
                var targetMeta = GetEntityByType(lookupAttr.TargetType);
                fd["lookup"] = new Dictionary<string, object?>
                {
                    ["targetSlug"]    = targetMeta?.Slug,
                    ["targetName"]    = targetMeta?.Name,
                    ["valueField"]    = lookupAttr.ValueField,
                    ["displayField"]  = lookupAttr.DisplayField,
                    ["queryField"]    = lookupAttr.QueryField,
                    ["queryValue"]    = lookupAttr.QueryValue,
                    ["sortField"]     = lookupAttr.SortField,
                    ["sortDirection"] = lookupAttr.SortDirection.ToString()
                };
                fd["enumValues"] = null;
                // CopyFields for inline copy when lookup selection changes
                fd["lookupCopyFields"] = string.IsNullOrEmpty(lookupAttr.CopyFields) ? null : (object)lookupAttr.CopyFields;
                fd["lookupTargetSlug"] = targetMeta?.Slug;
            }
            else if (effectiveType == FormFieldType.Enum)
            {
                fd["lookup"]     = null;
                var enumOpts = BuildEnumOptions(prop.PropertyType);
                var enumList = new List<object>(enumOpts.Count);
                foreach (var o in enumOpts)
                    enumList.Add((object)new Dictionary<string, object?> { ["value"] = o.Key, ["label"] = o.Value });
                fd["enumValues"] = enumList;
                fd["lookupCopyFields"] = null;
                fd["lookupTargetSlug"] = null;
            }
            else
            {
                fd["lookup"]          = null;
                fd["enumValues"]      = null;
                fd["lookupCopyFields"] = null;
                fd["lookupTargetSlug"] = null;
            }

            // Calculated field JSON AST (CSP-safe; no eval/new Function needed on client)
            if (calcAttr != null)
            {
                try
                {
                    var parser = new ExpressionParser();
                    var ast    = parser.Parse(calcAttr.Expression);
                    fd["calculated"] = new Dictionary<string, object?> { ["expression"] = ast.ToJsonAst() };
                }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"Calculated field expression parse failed for {field.Name}: {ex.Message}"); fd["calculated"] = new Dictionary<string, object?> { ["expression"] = FallbackAstObject }; }
            }
            else
            {
                fd["calculated"] = null;
            }

            // CopyFromParent support
            fd["copyFromParent"] = copyParAttr != null
                ? (object)new Dictionary<string, object?>
                {
                    ["parentField"] = copyParAttr.ParentFieldName,
                    ["entitySlug"]  = copyParAttr.EntitySlug,
                    ["sourceField"] = copyParAttr.SourceFieldName
                }
                : null;

            result.Add(fd);
        }

        return result;
    }

    /// <summary>
    /// Builds sub-field schemas for a metadata-driven (gallery/virtual entity) ChildList field.
    /// Mirrors the dictionary structure of <see cref="BuildSubFieldSchemas"/> for CLR-based entities
    /// so the VNext SPA receives a consistent schema regardless of whether the child is a
    /// compiled C# type or a runtime-registered virtual entity.
    /// </summary>
    private static IReadOnlyList<Dictionary<string, object?>> BuildSubFieldSchemasFromEntity(DataEntityMetadata childMeta, DataFieldMetadata parentField)
    {
        var result = new List<Dictionary<string, object?>>();
        var sortedFields = new List<DataFieldMetadata>(childMeta.Fields);
        sortedFields.Sort((a, b) => a.Order.CompareTo(b.Order));

        foreach (var cf in sortedFields)
        {
            if (!cf.Create && !cf.Edit) continue;

            var effectiveType = cf.Lookup != null ? FormFieldType.LookupList : cf.FieldType;

            var fd = new Dictionary<string, object?>
            {
                ["name"]     = cf.Name,
                ["label"]    = cf.Label,
                ["type"]     = effectiveType.ToString(),
                ["required"] = cf.Required,
                ["readOnly"] = cf.ReadOnly
            };

            if (cf.Lookup != null)
            {
                var targetMeta = cf.Lookup.TargetSlug != null
                    && TryGetEntity(cf.Lookup.TargetSlug, out var bySlug) ? bySlug
                    : GetEntityByType(cf.Lookup.TargetType);
                fd["lookup"] = new Dictionary<string, object?>
                {
                    ["targetSlug"]    = targetMeta?.Slug,
                    ["targetName"]    = targetMeta?.Name,
                    ["valueField"]    = cf.Lookup.ValueField,
                    ["displayField"]  = cf.Lookup.DisplayField,
                    ["queryField"]    = cf.Lookup.QueryField,
                    ["queryValue"]    = cf.Lookup.QueryValue,
                    ["sortField"]     = cf.Lookup.SortField,
                    ["sortDirection"] = cf.Lookup.SortDirection.ToString()
                };
                fd["enumValues"]       = null;
                fd["lookupCopyFields"] = string.IsNullOrEmpty(cf.LookupCopyFields) ? null : (object)cf.LookupCopyFields;
                fd["lookupTargetSlug"] = targetMeta?.Slug;
            }
            else if (effectiveType == FormFieldType.Enum)
            {
                fd["lookup"] = null;
                var enumOpts = cf.EnumValues != null && cf.EnumValues.Count > 0
                    ? BuildEnumOptionsFromValues(cf.EnumValues)
                    : BuildEnumOptions(cf.ClrType);
                var enumList = new List<object>(enumOpts.Count);
                foreach (var o in enumOpts)
                    enumList.Add((object)new Dictionary<string, object?> { ["value"] = o.Key, ["label"] = o.Value });
                fd["enumValues"]       = enumList;
                fd["lookupCopyFields"] = null;
                fd["lookupTargetSlug"] = null;
            }
            else
            {
                fd["lookup"]           = null;
                fd["enumValues"]       = null;
                fd["lookupCopyFields"] = null;
                fd["lookupTargetSlug"] = null;
            }

            if (!string.IsNullOrWhiteSpace(cf.CalculatedExpression))
            {
                try
                {
                    var parser = new ExpressionParser();
                    var ast    = parser.Parse(cf.CalculatedExpression!);
                    fd["calculated"] = new Dictionary<string, object?> { ["expression"] = ast.ToJsonAst() };
                }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"Calculated expression parse failed for sub-field {cf.Name}: {ex.Message}"); fd["calculated"] = new Dictionary<string, object?> { ["expression"] = FallbackAstObject }; }
            }
            else
            {
                fd["calculated"] = null;
            }

            fd["copyFromParent"] = (!string.IsNullOrWhiteSpace(cf.CopyFromParentField))
                ? (object)new Dictionary<string, object?>
                {
                    ["parentField"] = cf.CopyFromParentField,
                    ["entitySlug"]  = cf.CopyFromParentSlug,
                    ["sourceField"] = cf.CopyFromParentSourceField
                }
                : null;

            result.Add(fd);
        }

        return result;
    }


    public static IReadOnlyList<(string FieldName, string[] Headers, string[][] Rows)> ExtractNestedData(DataEntityMetadata metadata, object instance)
    {
        var result = new List<(string, string[], string[][])>();
        
        foreach (var field in metadata.ViewFields)
        {
            if (!IsChildListType(field.ClrType, out var childType))
                continue;
                
            var value = field.GetValueFn(instance);
            if (value is not IEnumerable enumerable)
                continue;
            var childFields = GetChildFieldMetadataSimple(childType);
            var headers = new string[childFields.Count];
            for (int hi = 0; hi < childFields.Count; hi++)
                headers[hi] = childFields[hi].Label;
            var rows = new List<string[]>();
            
            foreach (var item in enumerable)
            {
                if (item == null)
                    continue;
                    
                var row = new string[childFields.Count];
                for (int i = 0; i < childFields.Count; i++)
                {
                    var childField = childFields[i];
                    var rawValue = childField.Getter(item);
                    var displayText = ToDisplayString(rawValue, childField.FieldType);
                    row[i] = displayText;
                }
                rows.Add(row);
            }
            
            result.Add((field.Name, headers, rows.ToArray()));
        }
        
        return result;
    }

    public static TableRowActions? BuildRowActionsMetadata(BaseDataObject? dataObject, string rowBasePath, string? cloneToken = null, string? cloneReturnUrl = null)
    {
        if (dataObject == null)
            return null;

        var id = GetIdValue(dataObject);
        var safeId = Uri.EscapeDataString(id ?? string.Empty);
        var actionBasePath = $"{rowBasePath}/{safeId}";
        var actions = new List<TableRowAction>
        {
            new TableRowAction(actionBasePath, "Open", "bi-search", "btn-outline-info"),
            new TableRowAction($"{actionBasePath}/edit", "Edit", "bi-pencil", "btn-outline-warning"),
        };

        if (!string.IsNullOrWhiteSpace(cloneToken))
        {
            actions.Add(new TableRowAction($"{actionBasePath}/clone", "Clone row", "bi-files", "btn-outline-primary", RequiresCsrf: true, CsrfReturnUrl: cloneReturnUrl));
            actions.Add(new TableRowAction($"{actionBasePath}/clone-edit", "Clone and edit", "bi-pencil-square", "btn-outline-warning", RequiresCsrf: true, CsrfReturnUrl: cloneReturnUrl));
        }

        actions.Add(new TableRowAction($"{actionBasePath}/delete", "Delete", "bi-x-lg", "btn-outline-danger"));

        return new TableRowActions(actions);
    }

    public static IReadOnlyList<string[]> BuildListRows(DataEntityMetadata metadata, IEnumerable items, string basePath, bool includeActions, Func<DataEntityMetadata, bool>? canRenderLookupLink = null, string? cloneToken = null, string? cloneReturnUrl = null, bool includeBulkSelection = false)
    {
        var rows = new List<string[]>();
        // Pre-build lookup maps once per field (not per row)
        var listFields = metadata.ListFields;
        var lookupMaps = new Dictionary<string, string>?[listFields.Length];
        for (int fi = 0; fi < listFields.Length; fi++)
        {
            if (listFields[fi].Lookup != null)
            {
                var opts = GetLookupOptions(listFields[fi].Lookup!);
                var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var opt in opts)
                    map[opt.Key] = opt.Value;
                lookupMaps[fi] = map;
            }
        }

        foreach (var item in items)
        {
            if (item == null)
                continue;

            var values = new List<string>(listFields.Length);
            for (int fi = 0; fi < listFields.Length; fi++)
            {
                var field = listFields[fi];
                var rawValue = field.GetValueFn(item);
                if (lookupMaps[fi] != null)
                {
                    var lookupMap = lookupMaps[fi]!;
                    var key = rawValue?.ToString() ?? string.Empty;
                    var display = lookupMap.TryGetValue(key, out var resolved) ? resolved : key;
                    values.Add(WebUtility.HtmlEncode(FormatLookupDisplay(key, display)));
                    continue;
                }

                // Render boolean values as plain text
                if (rawValue is bool boolValue)
                {
                    values.Add(boolValue ? "true" : "false");
                    continue;
                }
                // Handle string representation of bool (from DataRecord / virtual entities)
                if (rawValue is string boolStr && field.ClrType == typeof(bool) && bool.TryParse(boolStr, out var parsedBool))
                {
                    values.Add(parsedBool ? "true" : "false");
                    continue;
                }

                values.Add(WebUtility.HtmlEncode(ToDisplayString(rawValue, field.ClrType)));
            }

            if (includeActions && item is BaseDataObject dataObject)
            {
                var id = GetIdValue(dataObject);
                var safeId = Uri.EscapeDataString(id ?? string.Empty);
                var viewUrl = $"{basePath}/{safeId}";
                var editUrl = $"{basePath}/{safeId}/edit";
                var deleteUrl = $"{basePath}/{safeId}/delete";
                var cloneHtml = string.Empty;
                if (!string.IsNullOrWhiteSpace(cloneToken))
                {
                    cloneHtml = "<form class=\"d-inline\" method=\"post\" action=\"" + WebUtility.HtmlEncode($"{basePath}/{safeId}/clone") + "\"><input type=\"hidden\" name=\"csrf_token\" value=\"" + WebUtility.HtmlEncode(cloneToken) + "\" /><input type=\"hidden\" name=\"returnUrl\" value=\"" + WebUtility.HtmlEncode(cloneReturnUrl ?? string.Empty) + "\" /><button type=\"submit\" class=\"btn btn-sm btn-outline-primary me-1\" title=\"Clone row\" aria-label=\"Clone row\"><i class=\"bi bi-files\" aria-hidden=\"true\"></i></button></form>"
                        + "<form class=\"d-inline\" method=\"post\" action=\"" + WebUtility.HtmlEncode($"{basePath}/{safeId}/clone-edit") + "\"><input type=\"hidden\" name=\"csrf_token\" value=\"" + WebUtility.HtmlEncode(cloneToken) + "\" /><input type=\"hidden\" name=\"returnUrl\" value=\"" + WebUtility.HtmlEncode(cloneReturnUrl ?? string.Empty) + "\" /><button type=\"submit\" class=\"btn btn-sm btn-outline-warning me-1\" title=\"Clone and edit\" aria-label=\"Clone and edit\"><i class=\"bi bi-pencil-square\" aria-hidden=\"true\"></i></button></form>";
                }

                values.Insert(0, $"<a class=\"btn btn-sm btn-outline-info me-1\" href=\"{viewUrl}\" title=\"Open\" aria-label=\"Open\"><i class=\"bi bi-search\" aria-hidden=\"true\"></i></a><a class=\"btn btn-sm btn-outline-warning me-1\" href=\"{editUrl}\" title=\"Edit\" aria-label=\"Edit\"><i class=\"bi bi-pencil\" aria-hidden=\"true\"></i></a>{cloneHtml}<a class=\"btn btn-sm btn-outline-danger\" href=\"{deleteUrl}\" title=\"Delete\" aria-label=\"Delete\"><i class=\"bi bi-x-lg\" aria-hidden=\"true\"></i></a>");
            }
            
            if (includeBulkSelection && item is BaseDataObject selectionDataObject)
            {
                var id = GetIdValue(selectionDataObject);
                var safeId = WebUtility.HtmlEncode(id ?? string.Empty);
                values.Insert(0, $"<input type=\"checkbox\" data-row-checkbox data-row-id=\"{safeId}\" aria-label=\"Select row\" />");
            }

            rows.Add(values.ToArray());
        }

        return rows;
    }

    private static void RenderTreeNode(
        StringBuilder html,
        DataEntityMetadata metadata,
        BaseDataObject item,
        List<BaseDataObject> allItems,
        string? selectedId,
        string basePath,
        int depth)
    {
        const int maxDepth = 10; // Prevent infinite recursion
        if (depth > maxDepth)
            return;

        var itemId = GetIdValue(item) ?? string.Empty;
        var safeId = Uri.EscapeDataString(itemId);
        var display = WebUtility.HtmlEncode(GetDisplayValue(metadata, item));
        var isActive = string.Equals(itemId, selectedId, StringComparison.OrdinalIgnoreCase);
        var activeClass = isActive ? " bm-data-tree-active" : string.Empty;
        var viewUrl = $"{basePath}?view=tree&selected={safeId}";

        // Find children
        var children = new List<BaseDataObject>();
        if (metadata.ParentField != null)
        {
            foreach (var child in allItems)
            {
                var parentId = metadata.ParentField.GetValueFn(child)?.ToString();
                if (string.Equals(parentId, itemId, StringComparison.OrdinalIgnoreCase))
                    children.Add(child);
            }
            children.Sort((a, b) => string.Compare(GetDisplayValue(metadata, a), GetDisplayValue(metadata, b), StringComparison.Ordinal));
        }

        var hasChildren = children.Count > 0;
        var isExpanded = hasChildren && (isActive || (metadata.ParentField != null && IsAncestorSelected(item, allItems, metadata.ParentField, selectedId)));
        var expandClass = isExpanded ? "bm-tree-expanded" : "bm-tree-collapsed";

        html.Append("<li class=\"bm-tree-item\">");
        html.Append("<div class=\"bm-tree-node\">");
        
        // Add expand/collapse toggle for nodes with children
        if (hasChildren)
        {
            var toggleIcon = isExpanded
                ? "<i class=\"bi bi-chevron-down\"></i>"
                : "<i class=\"bi bi-chevron-right\"></i>";
            html.Append($"<span class=\"bm-tree-toggle {expandClass}\" data-item-id=\"{WebUtility.HtmlEncode(itemId)}\">{toggleIcon}</span>");
        }
        else
        {
            html.Append("<span class=\"bm-tree-toggle bm-tree-spacer\"></span>");
        }
        
        html.Append($"<a class=\"bm-data-tree-link{activeClass}\" href=\"{viewUrl}\">{display}</a>");
        html.Append("</div>");

        if (hasChildren)
        {
            var childrenVisibility = isExpanded ? "" : " d-none";
            html.Append($"<ul class=\"bm-data-tree-list{childrenVisibility}\">");
            foreach (var child in children)
            {
                RenderTreeNode(html, metadata, child, allItems, selectedId, basePath, depth + 1);
            }
            html.Append("</ul>");
        }

        html.Append("</li>");
    }

    private static bool IsAncestorSelected(BaseDataObject item, List<BaseDataObject> allItems, DataFieldMetadata parentField, string? selectedId)
    {
        if (string.IsNullOrWhiteSpace(selectedId))
            return false;

        var itemsById = new Dictionary<string, BaseDataObject>(StringComparer.OrdinalIgnoreCase);
        foreach (var i in allItems)
            itemsById[GetIdValue(i) ?? string.Empty] = i;
        var itemId = GetIdValue(item) ?? string.Empty;

        // Check if selectedId is a descendant of itemId
        if (!itemsById.TryGetValue(selectedId, out var current))
            return false;

        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (current != null)
        {
            var currentId = GetIdValue(current) ?? string.Empty;
            if (visited.Contains(currentId))
                break; // Circular reference

            visited.Add(currentId);

            var parentId = parentField.GetValueFn(current)?.ToString();
            if (string.Equals(parentId, itemId, StringComparison.OrdinalIgnoreCase))
                return true;

            if (string.IsNullOrWhiteSpace(parentId) || !itemsById.TryGetValue(parentId, out current))
                break;
        }

        return false;
    }

    private static void RenderOrgChartNode(
        StringBuilder html,
        DataEntityMetadata metadata,
        BaseDataObject item,
        List<BaseDataObject> allItems,
        string selectedId,
        string basePath,
        int depth)
    {
        const int maxDepth = 5; // Limit depth for org chart
        if (depth > maxDepth)
            return;

        var itemId = GetIdValue(item) ?? string.Empty;
        var safeId = Uri.EscapeDataString(itemId);
        var display = WebUtility.HtmlEncode(GetDisplayValue(metadata, item));
        var isSelected = string.Equals(itemId, selectedId, StringComparison.OrdinalIgnoreCase);
        var selectedClass = isSelected ? " bm-orgchart-card-selected" : string.Empty;
        
        // Find a field that might represent title/role (look for common names)
        DataFieldMetadata? titleField = null;
        foreach (var f in metadata.Fields)
        {
            if (f.Name.Contains("Title", StringComparison.OrdinalIgnoreCase) ||
                f.Name.Contains("Role", StringComparison.OrdinalIgnoreCase) ||
                f.Name.Contains("Position", StringComparison.OrdinalIgnoreCase))
            {
                titleField = f;
                break;
            }
        }
        var titleValue = titleField != null ? titleField.GetValueFn(item)?.ToString() : null;
        
        // Render the current node
        html.Append("<div class=\"bm-orgchart-node\">");
        html.Append($"<div class=\"bm-orgchart-card{selectedClass}\">");
        html.Append($"<div class=\"bm-orgchart-name\">{display}</div>");
        
        if (!string.IsNullOrWhiteSpace(titleValue))
        {
            html.Append($"<div class=\"bm-orgchart-title\">{WebUtility.HtmlEncode(titleValue)}</div>");
        }
        
        html.Append("<div class=\"bm-orgchart-actions\">");
        html.Append($"<a class=\"btn btn-sm btn-outline-info me-1\" href=\"{basePath}/{safeId}\" title=\"View\"><i class=\"bi bi-search\" aria-hidden=\"true\"></i></a>");
        html.Append($"<a class=\"btn btn-sm btn-outline-warning me-1\" href=\"{basePath}/{safeId}/edit\" title=\"Edit\"><i class=\"bi bi-pencil\" aria-hidden=\"true\"></i></a>");
        html.Append($"<a class=\"btn btn-sm btn-outline-primary\" href=\"{basePath}?view=orgchart&selected={safeId}\" title=\"Focus\"><i class=\"bi bi-diagram-3\" aria-hidden=\"true\"></i></a>");
        html.Append("</div>");
        html.Append("</div>");
        html.Append("</div>");

        // Find children
        if (metadata.ParentField != null)
        {
            var children = new List<BaseDataObject>();
            foreach (var child in allItems)
            {
                var parentId = metadata.ParentField.GetValueFn(child)?.ToString();
                if (string.Equals(parentId, itemId, StringComparison.OrdinalIgnoreCase))
                    children.Add(child);
            }
            children.Sort((a, b) => string.Compare(GetDisplayValue(metadata, a), GetDisplayValue(metadata, b), StringComparison.Ordinal));

            if (children.Count > 0)
            {
                html.Append("<div class=\"bm-orgchart-connector\"></div>");
                html.Append("<div class=\"bm-orgchart-level\">");
                foreach (var child in children)
                {
                    RenderOrgChartNode(html, metadata, child, allItems, selectedId, basePath, depth + 1);
                }
                html.Append("</div>");
            }
        }
    }

    private static DataFieldMetadata? FindDayEnumField(DataEntityMetadata metadata)
    {
        // Prefer enum fields whose name or label contains "day" (e.g. Day, DayOfWeek, WeekDay)
        DataFieldMetadata? dayField = null;
        DataFieldMetadata? anyEnum = null;
        foreach (var f in metadata.Fields)
        {
            if (f.FieldType != FormFieldType.Enum) continue;
            anyEnum ??= f;
            if (f.Name.Contains("day", StringComparison.OrdinalIgnoreCase))
            {
                dayField = f;
                break;
            }
        }
        return dayField ?? anyEnum;
    }

    public static bool CanShowTimetableView(DataEntityMetadata metadata)
    {
        // Check for an enum field, preferring one whose name contains "day"
        var dayField = FindDayEnumField(metadata);

        // Check for TimeOnly or DateTime field
        DataFieldMetadata? timeField = null;
        foreach (var f in metadata.Fields)
        {
            if (f.FieldType == FormFieldType.TimeOnly || f.FieldType == FormFieldType.DateTime)
            {
                timeField = f;
                break;
            }
        }

        return dayField != null && timeField != null;
    }

    public static bool CanShowTimelineView(DataEntityMetadata metadata)
    {
        foreach (var f in metadata.Fields)
        {
            if (f.FieldType == FormFieldType.DateOnly || f.FieldType == FormFieldType.DateTime)
                return true;
        }
        return false;
    }

    /// <summary>
    /// Returns true when the entity has at least one <see cref="RelatedDocumentAttribute"/>
    /// field, making it a candidate for Sankey and document-chain tree views.
    /// </summary>
    public static bool CanShowSankeyView(DataEntityMetadata metadata)
    {
        return metadata.DocumentRelationFields is { Count: > 0 };
    }

    public static bool CanShowCalendarView(DataEntityMetadata metadata)
    {
        foreach (var f in metadata.Fields)
        {
            if (f.FieldType == FormFieldType.DateOnly || f.FieldType == FormFieldType.DateTime)
                return true;
        }
        return false;
    }

    private static string GetDisplayValue(DataEntityMetadata metadata, BaseDataObject item)
    {
        // Try to find a Name field
        DataFieldMetadata? nameField = null;
        foreach (var f in metadata.Fields)
        {
            if (string.Equals(f.Name, "Name", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(f.Name, "Title", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(f.Name, "DisplayName", StringComparison.OrdinalIgnoreCase))
            {
                nameField = f;
                break;
            }
        }

        if (nameField != null)
        {
            var value = nameField.GetValueFn(item)?.ToString();
            if (!string.IsNullOrWhiteSpace(value))
                return value;
        }

        // Fall back to ID
        return GetIdValue(item) ?? "Unknown";
    }

    private static string FormatLookupDisplay(string key, string display)
    {
        if (string.IsNullOrWhiteSpace(key) && string.IsNullOrWhiteSpace(display))
            return "—";

        if (string.IsNullOrWhiteSpace(key))
            return display;

        if (string.IsNullOrWhiteSpace(display) || string.Equals(key, display, StringComparison.OrdinalIgnoreCase))
            return key;

        return display;
    }



    public static List<string> ApplyValuesFromForm(DataEntityMetadata metadata, object instance, IDictionary<string, string?> values, bool forCreate)
    {
        var errors = new List<string>();
        var sortedFields = new List<DataFieldMetadata>(metadata.Fields);
        sortedFields.Sort((a, b) => a.Order.CompareTo(b.Order));
        foreach (var field in sortedFields)
        {
            if (field.ReadOnly)
                continue;
            if (forCreate && !field.Create)
                continue;
            if (!forCreate && !field.Edit)
                continue;

            // Skip auto-generated ID fields during form binding
            if (field.IdGeneration != IdGenerationStrategy.None)
                continue;

            if (IsChildListType(field.ClrType, out var childType))
            {
                if (!TryGetFormValue(values, field.Name, out var rawList) || rawList == null)
                {
                    if (field.Required)
                        errors.Add($"{field.Label} is required.");
                    continue;
                }

                if (!TryParseChildList(rawList, childType, out var listValue) || listValue == null)
                {
                    errors.Add($"{field.Label} is invalid.");
                    continue;
                }

                field.SetValueFn(instance, listValue);
                continue;
            }

            if (IsDictionaryType(field.ClrType, out var dictValueType))
            {
                if (!TryGetFormValue(values, field.Name, out var rawDict) || rawDict == null)
                {
                    if (field.Required)
                        errors.Add($"{field.Label} is required.");
                    continue;
                }

                if (!TryParseDictionary(rawDict, dictValueType, out var dictValue) || dictValue == null)
                {
                    errors.Add($"{field.Label} is invalid.");
                    continue;
                }

                field.SetValueFn(instance, dictValue);
                continue;
            }

            if (!TryGetFormValue(values, field.Name, out var rawValue) || rawValue == null)
            {
                // For Money fields, also try the {fieldName}_amount form key as a fallback
                if (field.FieldType == FormFieldType.Money && TryGetFormValue(values, field.Name + "_amount", out rawValue) && rawValue != null)
                {
                    // Found amount via _amount suffix; fall through to conversion below
                }
                else
                {
                    if (field.FieldType == FormFieldType.File || field.FieldType == FormFieldType.Image)
                        continue;

                    if (IsBooleanField(field, field.ClrType))
                    {
                        field.SetValueFn(instance, false);
                        if (field.Required)
                            errors.Add($"{field.Label} is required.");
                        continue;
                    }

                    if (field.Required)
                        errors.Add($"{field.Label} is required.");
                    continue;
                }
            }

            if (field.Required && string.IsNullOrWhiteSpace(rawValue))
            {
                errors.Add($"{field.Label} is required.");
                continue;
            }

            if (!TryConvertValue(rawValue, field.ClrType, out var converted))
            {
                if (!TryFallbackConvert(rawValue, field.ClrType, out converted))
                {
                    errors.Add($"{field.Label} is invalid.");
                    continue;
                }
            }

            field.SetValueFn(instance, converted);

            // Run field-level validators
            var fieldErrors = ValidationService.ValidateField(field, converted);
            errors.AddRange(fieldErrors);
        }

        return errors;
    }

    public static List<string> ApplyValuesFromJson(DataEntityMetadata metadata, object instance, IDictionary<string, JsonElement> values, bool forCreate, bool allowMissing)
    {
        var errors = new List<string>();
        var sortedFields = new List<DataFieldMetadata>(metadata.Fields);
        sortedFields.Sort((a, b) => a.Order.CompareTo(b.Order));
        foreach (var field in sortedFields)
        {
            if (field.ReadOnly)
                continue;
            if (forCreate && !field.Create)
                continue;
            if (!forCreate && !field.Edit)
                continue;

            // Skip auto-generated ID fields during JSON binding
            if (field.IdGeneration != IdGenerationStrategy.None)
                continue;

            if (!values.TryGetValue(field.Name, out var rawElement))
            {
                if (!allowMissing && field.Required)
                    errors.Add($"{field.Label} is required.");
                continue;
            }

            if (!TryConvertJson(rawElement, field.ClrType, out var converted))
            {
                // For Money fields, if the JSON is an object with an "amount" property, extract it as a decimal
                if (field.FieldType == FormFieldType.Money
                    && rawElement.ValueKind == JsonValueKind.Object
                    && rawElement.TryGetProperty("amount", out var amountElement)
                    && TryConvertJson(amountElement, field.ClrType, out converted))
                {
                    // Successfully extracted amount from Money JSON object; fall through to SetValue
                }
                else
                {
                    errors.Add($"{field.Label} is invalid.");
                    continue;
                }
            }

            field.SetValueFn(instance, converted);

            // Run field-level validators
            var fieldErrors = ValidationService.ValidateField(field, converted);
            errors.AddRange(fieldErrors);
        }

        return errors;
    }

    public static string ToDisplayString(object? value, Type type)
    {
        if (value == null)
            return string.Empty;

        if (value is DateTime dateTime)
            return dateTime.ToString("u", CultureInfo.InvariantCulture);

        if (value is DateTimeOffset dateTimeOffset)
            return dateTimeOffset.ToString("u", CultureInfo.InvariantCulture);

        if (value is DateOnly dateOnly)
            return dateOnly.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

        if (value is TimeOnly timeOnly)
            return timeOnly.ToString("HH:mm", CultureInfo.InvariantCulture);

        if (value is IEnumerable enumerable && value is not string)
        {
            var parts = new List<string>();
            foreach (var item in enumerable)
            {
                if (item == null)
                    continue;
                parts.Add(item.ToString() ?? string.Empty);
            }
            return string.Join(", ", parts);
        }

        return value.ToString() ?? string.Empty;
    }

    public static IReadOnlyList<KeyValuePair<string, string>> BuildEnumOptions(Type type)
    {
        var effectiveType = Nullable.GetUnderlyingType(type) ?? type;
        if (!effectiveType.IsEnum)
            return Array.Empty<KeyValuePair<string, string>>();

        var names = Enum.GetNames(effectiveType);
        var result = new KeyValuePair<string, string>[names.Length];
        for (int i = 0; i < names.Length; i++)
            result[i] = new KeyValuePair<string, string>(names[i], DeCamelcaseWithId(names[i]));
        return result;
    }

    /// <summary>
    /// Builds enum options for a field, preferring <see cref="DataFieldMetadata.EnumValues"/> (used
    /// for virtual/gallery entities whose CLR type is <see cref="string"/>) over CLR enum reflection.
    /// </summary>
    public static IReadOnlyList<KeyValuePair<string, string>> BuildEnumOptions(DataFieldMetadata field)
    {
        if (field.EnumValues != null && field.EnumValues.Count > 0)
            return BuildEnumOptionsFromValues(field.EnumValues);
        return BuildEnumOptions(field.ClrType);
    }

    /// <summary>
    /// Builds enum options from an explicit list of value names (used for virtual/gallery entities
    /// whose enum values are stored as strings rather than a CLR enum type).
    /// </summary>
    private static IReadOnlyList<KeyValuePair<string, string>> BuildEnumOptionsFromValues(IReadOnlyList<string> values)
    {
        var result = new KeyValuePair<string, string>[values.Count];
        for (int i = 0; i < values.Count; i++)
            result[i] = new KeyValuePair<string, string>(values[i], DeCamelcaseWithId(values[i]));
        return result;
    }

    private static IReadOnlyList<KeyValuePair<string, string>> GetLookupOptions(DataLookupConfig lookup)
    {
        var cacheKey = BuildLookupCacheKey(lookup);
        var now = DateTime.UtcNow;

        if (LookupCache.TryGetValue(cacheKey, out var cached) && cached.ExpiresUtc > now)
            return cached.Options;

        // Single-flight: compute and cache atomically per key
        var entry = LookupCache.AddOrUpdate(cacheKey,
            _ => BuildLookupCacheEntry(lookup),
            (_, existing) => existing.ExpiresUtc > DateTime.UtcNow ? existing : BuildLookupCacheEntry(lookup));

        // Prune expired entries when the cache grows beyond its size cap, subject to cooldown.
        if (LookupCache.Count > LookupCacheMaxSize)
        {
            var nowTicks = DateTime.UtcNow.Ticks;
            var last = Interlocked.Read(ref _lastLookupCachePruneTicks);
            if (nowTicks - last > LookupCachePruneCooldownTicks &&
                Interlocked.CompareExchange(ref _lastLookupCachePruneTicks, nowTicks, last) == last)
            {
                PruneExpiredLookupCache(now);
            }
        }

        return entry.Options;
    }

    private static LookupCacheEntry BuildLookupCacheEntry(DataLookupConfig lookup)
    {
        var query = BuildLookupQuery(lookup);
        var items = QueryByType(lookup.TargetType, query, lookup.TargetSlug);
        var options = BuildLookupOptions(items, lookup.ValueField, lookup.DisplayField);
        var count = options.Count;
        var isLarge = count > LargeListThreshold;
        return new LookupCacheEntry(options, isLarge, DateTime.UtcNow.Add(lookup.CacheTtl));
    }

    private static string BuildLookupCacheKey(DataLookupConfig lookup)
    {
        return string.Join('|',
            lookup.TargetSlug ?? lookup.TargetType.FullName ?? lookup.TargetType.Name,
            lookup.ValueField,
            lookup.DisplayField,
            lookup.QueryField ?? string.Empty,
            lookup.QueryOperator,
            lookup.QueryValue ?? string.Empty,
            lookup.SortField ?? string.Empty,
            lookup.SortDirection,
            lookup.CacheTtl.TotalSeconds.ToString(CultureInfo.InvariantCulture));
    }

    private static void PruneExpiredLookupCache(DateTime now)
    {
        // ConcurrentDictionary enumeration is safe under concurrent modification (no exceptions,
        // no corruption). Missed or extra entries are acceptable for best-effort pruning.
        foreach (var kv in LookupCache)
        {
            if (kv.Value.ExpiresUtc <= now)
                LookupCache.TryRemove(kv.Key, out _);
        }

        // Hard size limit — if still over capacity after expiry pruning, clear entirely.
        // The cache will repopulate on demand.
        if (LookupCache.Count > MaxLookupCacheEntries)
            LookupCache.Clear();
    }

    /// <summary>
    /// Invalidates the entire lookup options cache, forcing fresh reads on next access.
    /// Call after bulk writes that change lookup source data.
    /// </summary>
    public static void InvalidateLookupCache() => LookupCache.Clear();

    private static QueryDefinition? BuildLookupQuery(DataLookupConfig lookup)
    {
        var query = new QueryDefinition();
        if (!string.IsNullOrWhiteSpace(lookup.QueryField) && !string.IsNullOrWhiteSpace(lookup.QueryValue))
        {
            query.Clauses.Add(new QueryClause
            {
                Field = lookup.QueryField!,
                Operator = lookup.QueryOperator,
                Value = lookup.QueryValue
            });
        }

        if (!string.IsNullOrWhiteSpace(lookup.SortField))
        {
            query.Sorts.Add(new SortClause
            {
                Field = lookup.SortField!,
                Direction = lookup.SortDirection
            });
        }

        return query.Clauses.Count == 0 && query.Sorts.Count == 0 ? null : query;
    }

    private static DataEntityMetadata? ResolveMeta(Type type, string? slug)
    {
        // Prefer slug-based resolution (exact match) over type-based
        // because all virtual entities share typeof(DataRecord).
        if (slug != null && TryGetEntity(slug, out var metaBySlug))
            return metaBySlug;

        var meta = GetEntityByType(type);
        if (meta != null) return meta;

        // Derive slug from [DataEntity] attribute on compiled types
        var attr = type.GetCustomAttribute(typeof(DataEntityAttribute)) as DataEntityAttribute;
        if (attr != null)
        {
            var derivedSlug = !string.IsNullOrWhiteSpace(attr.Slug) ? attr.Slug! : ToSlug(attr.Name);
            TryGetEntity(derivedSlug, out meta);
        }
        return meta;
    }

    private static IEnumerable QueryByType(Type type, QueryDefinition? query, string? slug = null)
    {
        var meta = ResolveMeta(type, slug);
        if (meta != null)
        {
            var vt = meta.Handlers.QueryAsync(query, CancellationToken.None);
            // TODO: convert to async
            return vt.IsCompleted ? (IEnumerable)vt.Result : (IEnumerable)vt.AsTask().GetAwaiter().GetResult();
        }

        // AOT-safe: all entities should be registered via metadata handlers.
        throw new InvalidOperationException(
            $"Entity type '{type.Name}' is not registered. Register it via DataEntityRegistry or RuntimeEntityRegistry before querying.");
    }

    private static IReadOnlyList<KeyValuePair<string, string>> BuildLookupOptions(IEnumerable items, string valueField, string displayField)
    {
        var options = new List<KeyValuePair<string, string>>();
        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Func<object, object?>? valueGetter = null;
        Func<object, object?>? displayGetter = null;
        string? cachedType = null;

        // Normalize "Id" → "Key" for DataRecord compatibility
        var effectiveValueField = valueField;
        if (string.Equals(effectiveValueField, "Id", StringComparison.OrdinalIgnoreCase))
            effectiveValueField = nameof(BaseDataObject.Key);

        foreach (var item in items)
        {
            if (item == null)
                continue;

            // DataRecord: use schema-based ordinal access for virtual fields
            if (item is DataRecord dr && dr.Schema != null)
            {
                object? value;
                if (string.Equals(effectiveValueField, nameof(BaseDataObject.Key), StringComparison.OrdinalIgnoreCase))
                    value = dr.Key;
                else
                    value = dr.GetField(dr.Schema, effectiveValueField);

                if (value == null) continue;
                var valueStr = value.ToString() ?? string.Empty;
                if (!seenKeys.Add(valueStr)) continue;

                var display = dr.GetField(dr.Schema, displayField);
                var displayText = display?.ToString() ?? valueStr;
                options.Add(new KeyValuePair<string, string>(valueStr, displayText));
                continue;
            }

            // Compiled entities: use cached compiled delegates
            var itemEntityName = (item is BaseDataObject bdoItem) ? bdoItem.EntityTypeName : string.Empty;
            if (string.IsNullOrEmpty(itemEntityName)) continue;
            if (itemEntityName != cachedType)
            {
                cachedType = itemEntityName;
                valueGetter = PropertyAccessorCache.GetOrAdd((itemEntityName, effectiveValueField),
                    static key =>
                    {
                        var m = DataScaffold.GetEntityByName(key.Item1);
                        if (m == null) return null;
                        var f = m.FindField(key.Item2);
                        return f?.GetValueFn;
                    });
                displayGetter = PropertyAccessorCache.GetOrAdd((itemEntityName, displayField),
                    static key =>
                    {
                        var m = DataScaffold.GetEntityByName(key.Item1);
                        if (m == null) return null;
                        var f = m.FindField(key.Item2);
                        return f?.GetValueFn;
                    });
            }
            if (valueGetter == null || displayGetter == null)
                continue;

            var val = valueGetter(item);
            if (val == null)
                continue;

            var valStr = val.ToString() ?? string.Empty;
            if (!seenKeys.Add(valStr))
                continue;

            var disp = displayGetter(item);
            var dispText = disp?.ToString() ?? valStr;

            options.Add(new KeyValuePair<string, string>(valStr, dispText));
        }

        return options;
    }

    private static bool IsDefaultValue(object? value, Type type)
    {
        if (value == null)
            return true;

        var effectiveType = Nullable.GetUnderlyingType(type) ?? type;
        if (!effectiveType.IsValueType)
            return false;

        // AOT-safe default comparisons for known value types.
        if (effectiveType == typeof(int)) return (int)value == 0;
        if (effectiveType == typeof(uint)) return (uint)value == 0u;
        if (effectiveType == typeof(long)) return (long)value == 0L;
        if (effectiveType == typeof(decimal)) return (decimal)value == 0m;
        if (effectiveType == typeof(double)) return (double)value == 0.0;
        if (effectiveType == typeof(float)) return MathF.Abs((float)value) < 1e-7f;
        if (effectiveType == typeof(bool)) return (bool)value == false;
        if (effectiveType == typeof(DateTime)) return (DateTime)value == default;
        if (effectiveType == typeof(DateTimeOffset)) return (DateTimeOffset)value == default;
        if (effectiveType == typeof(Guid)) return (Guid)value == Guid.Empty;
        if (effectiveType == typeof(byte)) return (byte)value == 0;
        if (effectiveType == typeof(short)) return (short)value == 0;

        // All persistable value types are covered above.  For anything else,
        // assume the value is non-default — safe because unknown value types
        // cannot appear in the metadata-driven field system.
        return false;
    }

    public static string? GetIdValue(BaseDataObject instance)
        => instance.Key.ToString();

    public static bool IsTruthy(object? value)
    {
        if (value == null)
            return false;

        if (value is bool b)
            return b;

        if (value is string s)
            return string.Equals(s, "true", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "on", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "yes", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "1", StringComparison.OrdinalIgnoreCase);

        if (value is int i)
            return i != 0;

        return false;
    }

    private static bool IsBooleanField(DataFieldMetadata field, Type propertyType)
    {
        if (field.FieldType == FormFieldType.YesNo)
            return true;

        var effectiveType = Nullable.GetUnderlyingType(propertyType) ?? propertyType;
        return effectiveType == typeof(bool);
    }

    private static bool TryGetFormValue(IDictionary<string, string?> values, string name, out string? rawValue)
    {
        if (values.TryGetValue(name, out rawValue))
            return true;

        var camel = ToCamelCase(name);
        if (!string.Equals(camel, name, StringComparison.Ordinal) && values.TryGetValue(camel, out rawValue))
            return true;

        var lower = name.ToLowerInvariant();
        if (!string.Equals(lower, name, StringComparison.Ordinal) && values.TryGetValue(lower, out rawValue))
            return true;

        rawValue = null;
        return false;
    }

    private sealed record ChildFieldMeta(
        string Name,
        string Label,
        Type FieldType,
        bool Required,
        FormFieldType FormFieldType,
        IReadOnlyList<KeyValuePair<string, string>>? LookupOptions,
        CalculatedFieldAttribute? Calculated,
        string? LookupTargetSlug,
        string? LookupCopyFields,
        string? CopyFromParentField,
        string? CopyFromParentSlug,
        string? CopyFromParentSourceField,
        Func<object, object?> Getter,
        Action<object, object?> Setter
    );

    private static bool IsChildListType(Type type, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] out Type childType)
    {
        childType = typeof(object);
        if (!type.IsGenericType || type.GetGenericTypeDefinition() != typeof(List<>))
            return false;

        childType = type.GetGenericArguments()[0];
        return childType.IsClass && childType != typeof(string);
    }

    /// <summary>
    /// Gets child field metadata without resolving lookups (for export scenarios where we don't need lookup data)
    /// </summary>
    private static IReadOnlyList<ChildFieldMeta> GetChildFieldMetadataSimple([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties)] Type childType)
    {
        var fields = new List<ChildFieldMeta>();
        var properties = childType.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        Array.Sort(properties, (a, b) => string.CompareOrdinal(a.Name, b.Name));

        foreach (var prop in properties)
        {
            if (!prop.CanRead || !prop.CanWrite)
                continue;

            var fieldAttribute = prop.GetCustomAttribute<DataFieldAttribute>();
            if (fieldAttribute == null)
                continue;

            if (!fieldAttribute.Create && !fieldAttribute.Edit)
                continue;

            var label = fieldAttribute.Label ?? DeCamelcaseWithId(prop.Name);
            var required = fieldAttribute.Required;
            var effectiveFieldType = fieldAttribute.FieldType == FormFieldType.Unknown
                ? MapFieldType(prop.PropertyType)
                : fieldAttribute.FieldType;

            // Don't resolve lookups in this simplified version
            fields.Add(new ChildFieldMeta(prop.Name, label, prop.PropertyType, required, effectiveFieldType, null, null, null, null, null, null, null,
                obj => prop.GetValue(obj),
                (obj, val) => prop.SetValue(obj, val)));
        }

        return fields;
    }

    // Cached child field metadata — avoids re-reflecting on every form render.
    private static readonly ConcurrentDictionary<Type, IReadOnlyList<ChildFieldMeta>> ChildFieldMetadataCache = new();

    private static IReadOnlyList<ChildFieldMeta> GetChildFieldMetadata([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties)] Type childType)
    {
        return ChildFieldMetadataCache.GetOrAdd(childType, static type => BuildChildFieldMetadata(type));
    }

    private static IReadOnlyList<ChildFieldMeta> BuildChildFieldMetadata([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties)] Type childType)
    {
        var fields = new List<ChildFieldMeta>();
        var properties = childType.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        Array.Sort(properties, (a, b) => string.CompareOrdinal(a.Name, b.Name));

        foreach (var prop in properties)
        {
            if (!prop.CanRead || !prop.CanWrite)
                continue;

            var fieldAttribute = prop.GetCustomAttribute<DataFieldAttribute>();
            var lookupAttribute = prop.GetCustomAttribute<DataLookupAttribute>();
            if (fieldAttribute == null)
                continue;

            if (!fieldAttribute.Create && !fieldAttribute.Edit)
                continue;

            var label = fieldAttribute.Label ?? DeCamelcaseWithId(prop.Name);
            var required = fieldAttribute.Required;
            var effectiveFieldType = fieldAttribute.FieldType == FormFieldType.Unknown
                ? MapFieldType(prop.PropertyType)
                : fieldAttribute.FieldType;

            IReadOnlyList<KeyValuePair<string, string>>? lookupOptions = null;
            string? lookupTargetSlug = null;
            string? lookupCopyFields = null;
            if (lookupAttribute != null)
            {
                var lookup = new DataLookupConfig(
                    lookupAttribute.TargetType,
                    lookupAttribute.ValueField,
                    lookupAttribute.DisplayField,
                    lookupAttribute.QueryField,
                    lookupAttribute.QueryOperator,
                    lookupAttribute.QueryValue,
                    lookupAttribute.SortField,
                    lookupAttribute.SortDirection,
                    TimeSpan.FromSeconds(Math.Max(0, lookupAttribute.CacheSeconds))
                );
                lookupOptions = GetLookupOptions(lookup);
                effectiveFieldType = FormFieldType.LookupList;
                if (!string.IsNullOrEmpty(lookupAttribute.CopyFields))
                {
                    var targetMeta = GetEntityByType(lookupAttribute.TargetType);
                    lookupTargetSlug = targetMeta?.Slug;
                    lookupCopyFields = lookupAttribute.CopyFields;
                }
            }
            else if (effectiveFieldType == FormFieldType.Enum)
            {
                lookupOptions = BuildEnumOptions(prop.PropertyType);
            }

            var calculatedAttr = prop.GetCustomAttribute<CalculatedFieldAttribute>();

            var copyFromParentAttr = prop.GetCustomAttribute<CopyFromParentAttribute>();

            fields.Add(new ChildFieldMeta(
                Name: prop.Name,
                Label: label,
                FieldType: prop.PropertyType,
                Required: required,
                FormFieldType: effectiveFieldType,
                LookupOptions: lookupOptions,
                Calculated: calculatedAttr,
                LookupTargetSlug: lookupTargetSlug,
                LookupCopyFields: lookupCopyFields,
                CopyFromParentField: copyFromParentAttr?.ParentFieldName,
                CopyFromParentSlug: copyFromParentAttr?.EntitySlug,
                CopyFromParentSourceField: copyFromParentAttr?.SourceFieldName,
                Getter: obj => prop.GetValue(obj),
                Setter: (obj, val) => prop.SetValue(obj, val)));
        }

        return fields;
    }

    /// <summary>
    /// Converts a registered child entity's DataEntityMetadata fields into ChildFieldMeta
    /// for the child list editor, using metadata from the parent field for calculated/copy features.
    /// </summary>
    private static IReadOnlyList<ChildFieldMeta> GetChildFieldMetadataFromEntity(DataEntityMetadata childMeta, DataFieldMetadata parentField)
    {
        var fields = new List<ChildFieldMeta>();
        foreach (var cf in childMeta.Fields)
        {
            if (!cf.Create && !cf.Edit) continue;

            IReadOnlyList<KeyValuePair<string, string>>? lookupOptions = null;
            string? lookupTargetSlug = null;
            string? lookupCopyFields = null;
            var formFieldType = cf.FieldType;

            if (cf.Lookup != null)
            {
                lookupOptions = GetLookupOptions(cf.Lookup);
                formFieldType = FormFieldType.LookupList;
                lookupTargetSlug = cf.Lookup.TargetSlug;
                lookupCopyFields = cf.LookupCopyFields;
            }

            CalculatedFieldAttribute? calculated = null;
            if (!string.IsNullOrWhiteSpace(cf.CalculatedExpression))
            {
                calculated = new CalculatedFieldAttribute { Expression = cf.CalculatedExpression! };
                if (!string.IsNullOrWhiteSpace(cf.CalculatedDisplayFormat))
                    calculated.DisplayFormat = cf.CalculatedDisplayFormat;
            }

            var clrType = formFieldType switch
            {
                FormFieldType.YesNo => typeof(bool),
                FormFieldType.Integer => typeof(int),
                FormFieldType.Decimal or FormFieldType.Money => typeof(decimal),
                FormFieldType.DateTime => typeof(DateTime),
                FormFieldType.DateOnly => typeof(DateOnly),
                FormFieldType.TimeOnly => typeof(TimeOnly),
                _ => typeof(string)
            };

            fields.Add(new ChildFieldMeta(
                Name: cf.Name,
                Label: cf.Label,
                FieldType: clrType,
                Required: cf.Required,
                FormFieldType: formFieldType,
                LookupOptions: lookupOptions,
                Calculated: calculated,
                LookupTargetSlug: lookupTargetSlug,
                LookupCopyFields: lookupCopyFields,
                CopyFromParentField: cf.CopyFromParentField,
                CopyFromParentSlug: cf.CopyFromParentSlug,
                CopyFromParentSourceField: cf.CopyFromParentSourceField,
                Getter: obj => null,
                Setter: (obj, val) => { }));
        }
        return fields;
    }

    [RequiresDynamicCode("Creating List<T> instances for child types requires dynamic code generation.")]
    [RequiresUnreferencedCode("Child list parsing requires compiled entity types to be preserved.")]
    private static bool TryParseChildList(string rawValue, [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] Type childType, out object? list)
    {
        list = null;
        var listFactory = ListFactoryCache.GetOrAdd(childType, static t =>
            CompileFactory(typeof(List<>).MakeGenericType(t)));
        var instanceFactory = InstanceFactoryCache.GetOrAdd(childType, CompileFactory);

        if (string.IsNullOrWhiteSpace(rawValue))
        {
            list = listFactory();
            return true;
        }

        try
        {
            var rows = DataJsonWriter.ParseListOfStringDicts(rawValue);
            var typedList = (IList)listFactory();
            var childFields = GetChildFieldMetadata(childType);

            foreach (var row in rows)
            {
                var instance = instanceFactory();
                if (instance == null)
                    continue;

                foreach (var child in childFields)
                {
                    if (!row.TryGetValue(child.Name, out var raw))
                        continue;

                    if (TryConvertValue(raw, child.FieldType, out var converted) && converted != null)
                    {
                        child.Setter(instance, converted);
                    }
                    else if ((Nullable.GetUnderlyingType(child.FieldType) ?? child.FieldType) == typeof(string))
                    {
                        child.Setter(instance, raw);
                    }
                }

                typedList.Add(instance);
            }

            list = typedList;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsDictionaryType(Type type, out Type valueType)
    {
        valueType = typeof(string);
        var effectiveType = Nullable.GetUnderlyingType(type) ?? type;
        if (effectiveType.IsGenericType)
        {
            var generic = effectiveType.GetGenericTypeDefinition();
            if (generic == typeof(Dictionary<,>) || generic == typeof(IDictionary<,>) || generic == typeof(IReadOnlyDictionary<,>))
            {
                var args = effectiveType.GetGenericArguments();
                if (args.Length == 2 && args[0] == typeof(string))
                {
                    valueType = args[1];
                    return true;
                }
            }
        }

        foreach (var iface in effectiveType.GetInterfaces())
        {
            if (!iface.IsGenericType)
                continue;
            var generic = iface.GetGenericTypeDefinition();
            if (generic != typeof(IDictionary<,>) && generic != typeof(IReadOnlyDictionary<,>))
                continue;
            var args = iface.GetGenericArguments();
            if (args.Length == 2 && args[0] == typeof(string))
            {
                valueType = args[1];
                return true;
            }
        }

        return false;
    }

    [RequiresDynamicCode("Creating Dictionary<string,T> instances for value types requires dynamic code generation.")]
    [RequiresUnreferencedCode("Dictionary parsing requires compiled entity types to be preserved.")]
    private static bool TryParseDictionary(string rawValue, Type valueType, out object? dictionary)
    {
        dictionary = null;
        var dictFactory = DictFactoryCache.GetOrAdd((typeof(string), valueType), static key =>
            CompileFactory(typeof(Dictionary<,>).MakeGenericType(key.Item1, key.Item2)));

        if (string.IsNullOrWhiteSpace(rawValue))
        {
            dictionary = dictFactory();
            return true;
        }

        try
        {
            var list = DataJsonWriter.ParseListOfStringDicts(rawValue);
            var result = (IDictionary)dictFactory();

            foreach (var row in list)
            {
                if (!row.TryGetValue("key", out var key) || string.IsNullOrWhiteSpace(key))
                    continue;
                row.TryGetValue("value", out var raw);
                if (!TryConvertValue(raw ?? string.Empty, valueType, out var converted))
                {
                    if ((Nullable.GetUnderlyingType(valueType) ?? valueType) == typeof(string))
                    {
                        converted = raw ?? string.Empty;
                    }
                    else
                    {
                        continue;
                    }
                }

                result[key] = converted ?? string.Empty;
            }

            dictionary = result;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string[] ParseStringList(string rawValue)
    {
        return rawValue.Split(new[] { '\r', '\n', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static bool IsStringListType(Type type)
    {
        if (type == typeof(string[]))
            return true;

        return type.IsGenericType
            && type.GetGenericTypeDefinition() == typeof(List<>)
            && type.GetGenericArguments()[0] == typeof(string);
    }

    private static string ToCamelCase(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return input;
        if (input.Length == 1)
            return input.ToLowerInvariant();
        return char.ToLowerInvariant(input[0]) + input[1..];
    }

    private static bool TryFallbackConvert(string rawValue, Type targetType, out object? converted)
    {
        converted = null;
        var effectiveType = Nullable.GetUnderlyingType(targetType) ?? targetType;

        if (effectiveType == typeof(string))
        {
            converted = rawValue;
            return true;
        }

        if (effectiveType == typeof(bool))
        {
            converted = IsTruthy(rawValue);
            return true;
        }

        if (effectiveType == typeof(string[]))
        {
            converted = ParseStringList(rawValue);
            return true;
        }

        if (effectiveType == typeof(List<string>))
        {
            converted = new List<string>(ParseStringList(rawValue));
            return true;
        }

        return false;
    }

    public static bool TryConvertValue(string rawValue, Type targetType, out object? converted)
    {
        converted = null;
        var effectiveType = Nullable.GetUnderlyingType(targetType) ?? targetType;

        if (IsStringListType(effectiveType))
        {
            var list = ParseStringList(rawValue);
            converted = effectiveType == typeof(string[])
                ? list
                : new List<string>(list);
            return true;
        }

        if (effectiveType == typeof(int))
        {
            if (int.TryParse(rawValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var intValue))
            {
                converted = intValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(long))
        {
            if (long.TryParse(rawValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var longValue))
            {
                converted = longValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(decimal))
        {
            if (decimal.TryParse(rawValue, NumberStyles.Number, CultureInfo.InvariantCulture, out var decValue))
            {
                converted = decValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(double))
        {
            if (double.TryParse(rawValue, NumberStyles.Number, CultureInfo.InvariantCulture, out var dblValue))
            {
                converted = dblValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(float))
        {
            if (float.TryParse(rawValue, NumberStyles.Number, CultureInfo.InvariantCulture, out var fltValue))
            {
                converted = fltValue;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(DateTime))
        {
            if (DateTime.TryParse(rawValue, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out var dateValue))
            {
                converted = DateTime.SpecifyKind(dateValue, DateTimeKind.Utc);
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(DateTimeOffset))
        {
            if (DateTimeOffset.TryParse(rawValue, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out var dateValue))
            {
                converted = dateValue.ToUniversalTime();
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(DateOnly))
        {
            if (DateOnly.TryParse(rawValue, CultureInfo.InvariantCulture, DateTimeStyles.None, out var dateOnly))
            {
                converted = dateOnly;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(TimeOnly))
        {
            if (TimeOnly.TryParse(rawValue, CultureInfo.InvariantCulture, DateTimeStyles.None, out var timeOnly))
            {
                converted = timeOnly;
                return true;
            }
            return false;
        }
        if (effectiveType == typeof(string[]))
        {
            converted = ParseStringList(rawValue);
            return true;
        }

        if (effectiveType.IsEnum)
        {
            var lookup = GetEnumLookup(effectiveType);
            if (lookup.TryGetValue(rawValue, out var enumVal))
            {
                converted = enumVal;
                return true;
            }
            return false;
        }

        return false;
    }

    public static bool TryConvertJson(JsonElement element, Type targetType, out object? converted)
    {
        converted = null;
        var effectiveType = Nullable.GetUnderlyingType(targetType) ?? targetType;

        try
        {
            if (effectiveType == typeof(string))
            {
                converted = element.ValueKind == JsonValueKind.Null ? null : element.ToString();
                return true;
            }

            if (effectiveType == typeof(bool))
            {
                converted = element.ValueKind switch
                {
                    JsonValueKind.True => true,
                    JsonValueKind.False => false,
                    JsonValueKind.String => IsTruthy(element.GetString()),
                    _ => false
                };
                return true;
            }

            if (effectiveType == typeof(int) && element.TryGetInt32(out var intValue))
            {
                converted = intValue;
                return true;
            }

            if (effectiveType == typeof(long) && element.TryGetInt64(out var longValue))
            {
                converted = longValue;
                return true;
            }

            if (effectiveType == typeof(decimal) && element.TryGetDecimal(out var decValue))
            {
                converted = decValue;
                return true;
            }

            if (effectiveType == typeof(double) && element.TryGetDouble(out var dblValue))
            {
                converted = dblValue;
                return true;
            }

            if (effectiveType == typeof(DateTime) && element.ValueKind == JsonValueKind.String && DateTime.TryParse(element.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out var dateValue))
            {
                converted = DateTime.SpecifyKind(dateValue, DateTimeKind.Utc);
                return true;
            }

            if (effectiveType == typeof(DateTimeOffset) && element.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(element.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal | DateTimeStyles.AdjustToUniversal, out var dateValue2))
            {
                converted = dateValue2.ToUniversalTime();
                return true;
            }

            if (effectiveType == typeof(DateOnly) && element.ValueKind == JsonValueKind.String && DateOnly.TryParse(element.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.None, out var dateOnly))
            {
                converted = dateOnly;
                return true;
            }

            if (effectiveType == typeof(TimeOnly) && element.ValueKind == JsonValueKind.String && TimeOnly.TryParse(element.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.None, out var timeOnly))
            {
                converted = timeOnly;
                return true;
            }

            if (effectiveType == typeof(string[]))
            {
                if (element.ValueKind == JsonValueKind.Null)
                {
                    converted = Array.Empty<string>();
                    return true;
                }
                if (element.ValueKind == JsonValueKind.String)
                {
                    converted = ParseStringList(element.GetString() ?? string.Empty);
                    return true;
                }
                if (element.ValueKind == JsonValueKind.Array)
                {
                    var list = new List<string>();
                    foreach (var item in element.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                            list.Add(item.GetString() ?? string.Empty);
                    }
                    converted = list.ToArray();
                    return true;
                }
            }

            if (effectiveType == typeof(List<string>))
            {
                if (element.ValueKind == JsonValueKind.Null)
                {
                    converted = new List<string>();
                    return true;
                }
                if (element.ValueKind == JsonValueKind.String)
                {
                    converted = new List<string>(ParseStringList(element.GetString() ?? string.Empty));
                    return true;
                }
                if (element.ValueKind == JsonValueKind.Array)
                {
                    var list = new List<string>();
                    foreach (var item in element.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                            list.Add(item.GetString() ?? string.Empty);
                    }
                    converted = list;
                    return true;
                }
            }

            if (effectiveType.IsEnum && element.ValueKind == JsonValueKind.String)
            {
                var enumStr = element.GetString() ?? string.Empty;
                var lookup = GetEnumLookup(effectiveType);
                if (lookup.TryGetValue(enumStr, out var enumVal))
                {
                    converted = enumVal;
                    return true;
                }
            }

            // Child list: List<T> where T is a complex class (e.g. List<OrderRow>)
            if (IsChildListType(effectiveType, out var childType)
                && (element.ValueKind == JsonValueKind.Array || element.ValueKind == JsonValueKind.Null))
            {
                if (TryConvertJsonChildList(element, childType, out converted))
                    return true;
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    /// <summary>
    /// Deserialises a JSON array of objects into a <c>List&lt;T&gt;</c> where T is a child entity type.
    /// Uses cached child field metadata with pre-compiled setter delegates (no per-call reflection).
    /// </summary>
    [RequiresDynamicCode("Creating List<T> instances for child types requires dynamic code generation.")]
    [RequiresUnreferencedCode("JSON child list deserialization requires compiled entity types to be preserved.")]
    private static bool TryConvertJsonChildList(JsonElement element, Type childType, out object? list)
    {
        list = null;
        var listFactory = ListFactoryCache.GetOrAdd(childType, static t =>
            CompileFactory(typeof(List<>).MakeGenericType(t)));
        var instanceFactory = InstanceFactoryCache.GetOrAdd(childType, CompileFactory);

        if (element.ValueKind == JsonValueKind.Null)
        {
            list = listFactory();
            return true;
        }

        try
        {
            var typedList = (IList)listFactory();
            var childFields = GetChildFieldMetadata(childType);

            foreach (var row in element.EnumerateArray())
            {
                if (row.ValueKind != JsonValueKind.Object)
                    continue;

                var instance = instanceFactory();
                if (instance == null)
                    continue;

                foreach (var prop in row.EnumerateObject())
                {
                    // Find matching child field by name (case-insensitive)
                    ChildFieldMeta? match = null;
                    foreach (var cf in childFields)
                    {
                        if (string.Equals(cf.Name, prop.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            match = cf;
                            break;
                        }
                    }
                    if (match == null) continue;

                    if (TryConvertJson(prop.Value, match.FieldType, out var val))
                        match.Setter(instance, val);
                }

                typedList.Add(instance);
            }

            list = typedList;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static FormFieldType MapFieldType(Type type)
    {
        var effectiveType = Nullable.GetUnderlyingType(type) ?? type;

        if (IsStringListType(effectiveType))
            return FormFieldType.Tags;
        if (IsChildListType(effectiveType, out _))
            return FormFieldType.CustomHtml;
        if (effectiveType == typeof(bool))
            return FormFieldType.YesNo;
        if (effectiveType.IsEnum)
            return FormFieldType.Enum;
        if (effectiveType == typeof(DateOnly))
            return FormFieldType.DateOnly;
        if (effectiveType == typeof(TimeOnly))
            return FormFieldType.TimeOnly;
        if (effectiveType == typeof(DateTime) || effectiveType == typeof(DateTimeOffset))
            return FormFieldType.DateTime;
        if (effectiveType == typeof(int) || effectiveType == typeof(long) || effectiveType == typeof(short))
            return FormFieldType.Integer;
        if (effectiveType == typeof(decimal) || effectiveType == typeof(double) || effectiveType == typeof(float))
            return FormFieldType.Decimal;
        if (effectiveType == typeof(string))
            return FormFieldType.String;

        return FormFieldType.String;
    }

    private static DataEntityMetadata? BuildEntityMetadata<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] T>() where T : BaseDataObject, new()
    {
        var type = typeof(T);
        if (type.IsAbstract)
            return null;

        var entityAttribute = type.GetCustomAttribute<DataEntityAttribute>();
        if (entityAttribute == null)
            return null;

        // Read entity-level validation rules at registration time (no runtime reflection)
        List<ValidationRuleAttribute>? entityValidationRules = null;
        foreach (var attr in type.GetCustomAttributes(false))
        {
            if (attr is ValidationRuleAttribute vr)
            {
                entityValidationRules ??= new List<ValidationRuleAttribute>();
                entityValidationRules.Add(vr);
            }
        }

        var fields = new List<DataFieldMetadata>();
        var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        Array.Sort(properties, (a, b) => string.CompareOrdinal(a.Name, b.Name));

        // Read ordinal mapping from entity's field lookup table (zero reflection)
        var ordinalMap = new Dictionary<string, int>(32, StringComparer.Ordinal);
        var probe = new T();
        foreach (var slot in probe.GetFieldMap())
            ordinalMap[slot.Name] = slot.Ordinal;

        for (int i = 0; i < properties.Length; i++)
        {
            var prop = properties[i];
            if (!prop.CanRead || !prop.CanWrite)
                continue;

            // Batch-read all custom attributes once per property (avoids 10+ individual reflection calls)
            var allAttrs = prop.GetCustomAttributes(false);
            DataFieldAttribute? fieldAttribute = null;
            FileFieldAttribute? fileFieldAttribute = null;
            ImageFieldAttribute? imageFieldAttribute = null;
            DataLookupAttribute? lookupAttribute = null;
            IdGenerationAttribute? idGenAttribute = null;
            ComputedFieldAttribute? computedAttribute = null;
            CalculatedFieldAttribute? calculatedAttribute = null;
            DataIndexAttribute? dataIndexAttribute = null;
            RelatedDocumentAttribute? relatedDocAttribute = null;
            SingletonFlagAttribute? singletonFlagAttribute = null;
            List<ValidationAttribute>? validationAttrs = null;
            List<ValidationRuleAttribute>? fieldExprRules = null;
            for (int j = 0; j < allAttrs.Length; j++)
            {
                switch (allAttrs[j])
                {
                    case DataFieldAttribute a: fieldAttribute = a; break;
                    case FileFieldAttribute a: fileFieldAttribute = a; break;
                    case ImageFieldAttribute a: imageFieldAttribute = a; break;
                    case DataLookupAttribute a: lookupAttribute = a; break;
                    case IdGenerationAttribute a: idGenAttribute = a; break;
                    case ComputedFieldAttribute a: computedAttribute = a; break;
                    case CalculatedFieldAttribute a: calculatedAttribute = a; break;
                    case DataIndexAttribute a: dataIndexAttribute = a; break;
                    case RelatedDocumentAttribute a: relatedDocAttribute = a; break;
                    case SingletonFlagAttribute a: singletonFlagAttribute = a; break;
                    case ValidationAttribute va:
                        validationAttrs ??= new List<ValidationAttribute>();
                        validationAttrs.Add(va);
                        break;
                    case ValidationRuleAttribute vr:
                        fieldExprRules ??= new List<ValidationRuleAttribute>();
                        fieldExprRules.Add(vr);
                        break;
                }
            }

            if (IsCoreDataObjectProperty(prop))
            {
                // Allow core properties if they have DataField or IdGeneration attributes
                if (fieldAttribute == null && idGenAttribute == null)
                    continue;
            }

            var hasSingletonFlag = prop.PropertyType == typeof(bool) && singletonFlagAttribute != null;
            if (fieldAttribute == null && imageFieldAttribute == null && fileFieldAttribute == null)
                continue;

            var fieldType = imageFieldAttribute != null
                ? FormFieldType.Image
                : fileFieldAttribute != null
                    ? FormFieldType.File
                    : fieldAttribute?.FieldType == FormFieldType.Unknown || fieldAttribute == null
                        ? MapFieldType(prop.PropertyType)
                        : fieldAttribute.FieldType;
            var label = imageFieldAttribute?.Label
                ?? fileFieldAttribute?.Label
                ?? fieldAttribute?.Label
                ?? DeCamelcaseWithId(prop.Name);
            var required = imageFieldAttribute?.Required
                ?? fileFieldAttribute?.Required
                ?? fieldAttribute?.Required
                ?? (!IsNullable(prop) || !HasDefaultValue(probe, prop));
            var order = imageFieldAttribute?.Order
                ?? fileFieldAttribute?.Order
                ?? fieldAttribute?.Order
                ?? (i + 1);
            DataLookupConfig? lookup = null;
            if (lookupAttribute != null)
            {
                lookup = new DataLookupConfig(
                    lookupAttribute.TargetType,
                    lookupAttribute.ValueField,
                    lookupAttribute.DisplayField,
                    lookupAttribute.QueryField,
                    lookupAttribute.QueryOperator,
                    lookupAttribute.QueryValue,
                    lookupAttribute.SortField,
                    lookupAttribute.SortDirection,
                    TimeSpan.FromSeconds(Math.Max(0, lookupAttribute.CacheSeconds))
                );
            }

            ComputedFieldConfig? computed = null;
            if (computedAttribute != null)
            {
                computed = new ComputedFieldConfig(
                    computedAttribute.SourceEntity,
                    computedAttribute.SourceField,
                    computedAttribute.ForeignKeyField,
                    computedAttribute.ChildCollectionProperty,
                    computedAttribute.Strategy,
                    computedAttribute.Trigger,
                    computedAttribute.Aggregate,
                    TimeSpan.FromSeconds(Math.Max(0, computedAttribute.CacheSeconds))
                );
            }

            UploadFieldConfig? upload = null;
            if (imageFieldAttribute != null)
            {
                upload = new UploadFieldConfig(
                    imageFieldAttribute.MaxFileSizeBytes,
                    imageFieldAttribute.AllowedMimeTypes,
                    imageFieldAttribute.MaxWidth > 0 ? imageFieldAttribute.MaxWidth : null,
                    imageFieldAttribute.MaxHeight > 0 ? imageFieldAttribute.MaxHeight : null,
                    imageFieldAttribute.GenerateThumbnail
                );
            }
            else if (fileFieldAttribute != null)
            {
                upload = new UploadFieldConfig(
                    fileFieldAttribute.MaxFileSizeBytes,
                    fileFieldAttribute.AllowedMimeTypes,
                    null,
                    null,
                    false
                );
            }

            RelatedDocumentConfig? relatedDoc = relatedDocAttribute != null
                ? new RelatedDocumentConfig(relatedDocAttribute.TargetType, relatedDocAttribute.DisplayField)
                : null;

            fields.Add(new DataFieldMetadata(
                prop.PropertyType,
                prop.Name,
                label,
                fieldType,
                order,
                required,
                imageFieldAttribute?.List ?? fileFieldAttribute?.List ?? fieldAttribute?.List ?? true,
                imageFieldAttribute?.View ?? fileFieldAttribute?.View ?? fieldAttribute?.View ?? true,
                imageFieldAttribute?.Edit ?? fileFieldAttribute?.Edit ?? fieldAttribute?.Edit ?? true,
                imageFieldAttribute?.Create ?? fileFieldAttribute?.Create ?? fieldAttribute?.Create ?? true,
                (imageFieldAttribute?.ReadOnly ?? fileFieldAttribute?.ReadOnly ?? fieldAttribute?.ReadOnly ?? false) || (computed != null) || (calculatedAttribute != null), // Computed and calculated fields are always readonly
                imageFieldAttribute?.Placeholder ?? fileFieldAttribute?.Placeholder ?? fieldAttribute?.Placeholder,
                lookup,
                idGenAttribute?.Strategy ?? IdGenerationStrategy.None,
                computed,
                upload,
                calculatedAttribute,
                BuildValidationConfigInline(validationAttrs, fieldExprRules),
                dataIndexAttribute != null,
                relatedDoc,
                DataIndex: dataIndexAttribute,
                HasSingletonFlag: hasSingletonFlag,
                StorageOrdinal: ordinalMap.TryGetValue(prop.Name, out var storageOrd) ? storageOrd : -1
            ));
        }

        var name = entityAttribute?.Name ?? Pluralize(DeCamelcaseWithId(type.Name));
        var slug = string.IsNullOrWhiteSpace(entityAttribute?.Slug)
            ? ToSlug(name)
            : entityAttribute!.Slug!.Trim().ToLowerInvariant();
        var permissions = string.IsNullOrWhiteSpace(entityAttribute?.Permissions)
            ? name
            : entityAttribute!.Permissions;
        var showOnNav = entityAttribute?.ShowOnNav ?? false;
        var navGroup = entityAttribute?.NavGroup ?? "Admin";
        var navOrder = entityAttribute?.NavOrder ?? 0;
        var idGeneration = entityAttribute?.IdGeneration ?? AutoIdStrategy.Sequential;
        var defaultSortField = string.IsNullOrWhiteSpace(entityAttribute?.DefaultSortField) ? null : entityAttribute.DefaultSortField;
        var defaultSortDirection = entityAttribute?.DefaultSortDirection ?? SortDirection.Asc;
        var rlsOwnerField = string.IsNullOrWhiteSpace(entityAttribute?.RlsOwnerField) ? null : entityAttribute.RlsOwnerField;

        // Detect view type and self-referencing parent field
        var viewTypeAttribute = type.GetCustomAttribute<DataViewTypeAttribute>();
        var viewType = viewTypeAttribute?.ViewType ?? ViewType.Table;
        DataFieldMetadata? parentField = null;
        
        // Find self-referencing lookup field (for tree/org chart views)
        foreach (var field in fields)
        {
            if (field.Lookup != null && field.Lookup.TargetType == type)
            {
                parentField = field;
                break;
            }
        }

        var handlers = new DataEntityHandlers(
            static () => new T(),
            LoadTypedAsync<T>,
            SaveTypedAsync<T>,
            DeleteTypedAsync<T>,
            QueryTypedAsync<T>,
            CountTypedAsync<T>
        );

        // Discover [RemoteCommand] methods and pre-compile typed invoker delegates.
        // Using Delegate.CreateDelegate at startup avoids per-request MethodInfo.Invoke overhead
        // and is NativeAOT-safe because T is a concrete type with [DynamicallyAccessedMembers].
        var commands = new List<RemoteCommandMetadata>();
        var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
        foreach (var method in methods)
        {
            var cmdAttr = method.GetCustomAttribute<RemoteCommandAttribute>();
            if (cmdAttr == null) continue;
            var returnType = method.ReturnType;

            Func<object, ValueTask<RemoteCommandResult>> invoker;
            if (returnType == typeof(RemoteCommandResult))
            {
                var d = (Func<T, RemoteCommandResult>)Delegate.CreateDelegate(typeof(Func<T, RemoteCommandResult>), method);
                invoker = obj => new ValueTask<RemoteCommandResult>(d((T)obj));
            }
            else if (returnType == typeof(Task<RemoteCommandResult>))
            {
                var d = (Func<T, Task<RemoteCommandResult>>)Delegate.CreateDelegate(typeof(Func<T, Task<RemoteCommandResult>>), method);
                invoker = obj => new ValueTask<RemoteCommandResult>(d((T)obj));
            }
            else if (returnType == typeof(ValueTask<RemoteCommandResult>))
            {
                var d = (Func<T, ValueTask<RemoteCommandResult>>)Delegate.CreateDelegate(typeof(Func<T, ValueTask<RemoteCommandResult>>), method);
                invoker = obj => d((T)obj);
            }
            else
            {
                continue;
            }

            commands.Add(new RemoteCommandMetadata(
                invoker,
                method.Name,
                cmdAttr.Label ?? DeCamelcaseWithId(method.Name),
                cmdAttr.Icon,
                cmdAttr.ConfirmMessage,
                cmdAttr.Destructive,
                cmdAttr.Permission,
                cmdAttr.OverrideEntityPermissions,
                cmdAttr.Order
            ));
        }

        fields.Sort((a, b) => a.Order.CompareTo(b.Order));
        commands.Sort((a, b) => a.Order.CompareTo(b.Order));
        var docRelFields = new List<DataFieldMetadata>();
        foreach (var f in fields)
        {
            if (f.RelatedDocument != null)
                docRelFields.Add(f);
        }

        return new DataEntityMetadata(
            type,
            name,
            slug,
            permissions,
            showOnNav,
            navGroup,
            navOrder,
            idGeneration,
            viewType,
            parentField,
            fields,
            handlers,
            commands,
            defaultSortField,
            defaultSortDirection,
            docRelFields,
            entityValidationRules,
            RlsOwnerField: rlsOwnerField
        );
    }

    private static bool IsCoreDataObjectProperty(PropertyInfo property)
    {
        return property.DeclaringType == typeof(BaseDataObject)
            || property.Name == nameof(BaseDataObject.Key)
            || property.Name == nameof(BaseDataObject.CreatedOnUtc)
            || property.Name == nameof(BaseDataObject.UpdatedOnUtc)
            || property.Name == nameof(BaseDataObject.CreatedBy)
            || property.Name == nameof(BaseDataObject.UpdatedBy)
            || property.Name == nameof(BaseDataObject.ETag);
    }

    private static ValidationConfig? BuildValidationConfigInline(
        List<ValidationAttribute>? validators, List<ValidationRuleAttribute>? expressionRules)
    {
        if ((validators == null || validators.Count == 0) && (expressionRules == null || expressionRules.Count == 0))
            return null;

        int? minLength = null;
        int? maxLength = null;
        double? rangeMin = null;
        double? rangeMax = null;
        string? regexPattern = null;
        string? regexMessage = null;
        bool isEmail = false;
        bool isUrl = false;
        bool isPhone = false;

        if (validators != null)
        {
            foreach (var v in validators)
            {
                switch (v)
                {
                    case MinLengthAttribute ml: minLength = ml.Length; break;
                    case MaxLengthAttribute mx: maxLength = mx.Length; break;
                    case RangeAttribute r: rangeMin = r.Min; rangeMax = r.Max; break;
                    case RegexPatternAttribute rp: regexPattern = rp.Pattern; regexMessage = rp.ErrorMessage; break;
                    case EmailAddressAttribute: isEmail = true; break;
                    case UrlAttribute: isUrl = true; break;
                    case PhoneAttribute: isPhone = true; break;
                }
            }
        }

        return new ValidationConfig(
            minLength, maxLength, rangeMin, rangeMax,
            regexPattern, regexMessage,
            isEmail, isUrl, isPhone,
            (IReadOnlyList<ValidationAttribute>?)validators ?? Array.Empty<ValidationAttribute>(),
            (IReadOnlyList<ValidationRuleAttribute>?)expressionRules ?? Array.Empty<ValidationRuleAttribute>()
        );
    }

    private static bool IsNullable(PropertyInfo property)
    {
        if (Nullable.GetUnderlyingType(property.PropertyType) != null)
            return true;
        if (property.PropertyType.IsValueType)
            return false;

        var nullability = NullabilityContext.Create(property);
        return nullability.ReadState == NullabilityState.Nullable
            || nullability.WriteState == NullabilityState.Nullable;
    }

    private static bool HasDefaultValue(object defaultInstance, PropertyInfo property)
    {
        object? value;
        try
        {
            value = property.GetValue(defaultInstance);
        }
        catch
        {
            return false;
        }

        return !IsDefaultValue(value, property.PropertyType);
    }

    internal static string DeCamelcase(string name) => DeCamelcaseWithId(name);

    private static string DeCamelcaseWithId(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return string.Empty;

        // Capacity hint: average CamelCase word is ~4 chars; +1 avoids empty-list corner case
        var words = new List<string>(name.Length / 4 + 1);
        var buffer = new List<char>(name.Length);
        for (int i = 0; i < name.Length; i++)
        {
            var c = name[i];
            var isBoundary = i > 0
                && char.IsUpper(c)
                && (char.IsLower(name[i - 1]) || (i + 1 < name.Length && char.IsLower(name[i + 1])));
            if (isBoundary)
            {
                words.Add(new string(buffer.ToArray()));
                buffer.Clear();
            }
            buffer.Add(c);
        }

        if (buffer.Count > 0)
            words.Add(new string(buffer.ToArray()));

        for (int i = 0; i < words.Count; i++)
        {
            if (string.Equals(words[i], "Id", StringComparison.OrdinalIgnoreCase))
                words[i] = "ID";
        }

        return string.Join(" ", words);
    }

    internal static string Pluralize(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return string.Empty;

        if (name.EndsWith("y", StringComparison.OrdinalIgnoreCase) && name.Length > 1)
        {
            var before = name[^2];
            if (!"aeiou".Contains(char.ToLowerInvariant(before)))
                return name[..^1] + "ies";
        }

        if (name.EndsWith("s", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("x", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("z", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("ch", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith("sh", StringComparison.OrdinalIgnoreCase))
        {
            return name + "es";
        }

        return name + "s";
    }

    internal static string ToSlug(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return string.Empty;

        var chars = new List<char>(name.Length);
        foreach (var c in name)
        {
            if (char.IsLetterOrDigit(c))
                chars.Add(char.ToLowerInvariant(c));
            else if (char.IsWhiteSpace(c) || c == '_' || c == '-')
                chars.Add('-');
        }

        var slug = new string(chars.ToArray());
        while (slug.Contains("--", StringComparison.Ordinal))
            slug = slug.Replace("--", "-", StringComparison.Ordinal);

        return slug.Trim('-');
    }

    private static async ValueTask<BaseDataObject?> LoadTypedAsync<T>(uint key, CancellationToken cancellationToken) where T : BaseDataObject
        => await DataStoreProvider.Current.LoadAsync<T>(key, cancellationToken);

    private static async ValueTask SaveTypedAsync<T>(BaseDataObject instance, CancellationToken cancellationToken) where T : BaseDataObject
        => await DataStoreProvider.Current.SaveAsync((T)instance, cancellationToken);

    private static async ValueTask DeleteTypedAsync<T>(uint key, CancellationToken cancellationToken) where T : BaseDataObject
        => await DataStoreProvider.Current.DeleteAsync<T>(key, cancellationToken);

    private static async ValueTask<IEnumerable<BaseDataObject>> QueryTypedAsync<T>(QueryDefinition? query, CancellationToken cancellationToken) where T : BaseDataObject
    {
        var results = await DataStoreProvider.Current.QueryAsync<T>(query, cancellationToken);
        var list = new List<BaseDataObject>();
        foreach (var item in results)
            list.Add(item);
        return list;
    }

    private static async ValueTask<int> CountTypedAsync<T>(QueryDefinition? query, CancellationToken cancellationToken) where T : BaseDataObject
        => await DataStoreProvider.Current.CountAsync<T>(query, cancellationToken);

    /// <summary>
    /// Evaluates all calculated fields on an entity instance server-side.
    /// Call this before saving to ensure calculated values match server-side evaluation.
    /// </summary>
    public static void ApplyCalculatedFields(DataEntityMetadata metadata, BaseDataObject instance)
    {
        CalculatedFieldService.EvaluateCalculatedFields(instance);
    }

    /// <summary>
    /// Validate an entity instance using attribute-based and expression-based validation rules.
    /// Call after ApplyValuesFromForm/ApplyValuesFromJson and before SaveAsync.
    /// </summary>
    public static ValidationResult ValidateEntity(DataEntityMetadata metadata, object instance)
    {
        return ValidationService.ValidateEntity(metadata, instance);
    }

}
