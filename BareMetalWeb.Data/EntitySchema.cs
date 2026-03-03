using System.Collections.Frozen;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// Parallel-array schema descriptor for an entity type. Shared across all
/// <see cref="DataRecord"/> instances of the same entity — one allocation
/// per type, not per row.
/// <para>
/// All arrays are indexed by field ordinal. Scanning operations (e.g. "find
/// all indexed fields") touch only the relevant <c>bool[]</c> or <c>FieldType[]</c>,
/// giving excellent cache locality (one cache line per ~64 fields).
/// </para>
/// </summary>
public sealed class EntitySchema
{
    /// <summary>Entity type name (e.g. "Customer").</summary>
    public string EntityName { get; }

    /// <summary>URL slug (e.g. "customers").</summary>
    public string Slug { get; }

    /// <summary>Number of fields in this schema.</summary>
    public int FieldCount { get; }

    // ── Parallel arrays — all indexed by ordinal ───────────────────────────

    /// <summary>Field names. <c>Names[ord]</c> = "Email".</summary>
    public string[] Names { get; }

    /// <summary>Field types. <c>Types[ord]</c> = <see cref="FieldType.StringUtf8"/>.</summary>
    public FieldType[] Types { get; }

    /// <summary>CLR types for deserialization. <c>ClrTypes[ord]</c> = <c>typeof(string)</c>.</summary>
    public Type[] ClrTypes { get; }

    /// <summary>Nullable flags. <c>Nullable[ord]</c> = true if the field allows null.</summary>
    public bool[] IsNullable { get; }

    /// <summary>Required flags. <c>Required[ord]</c> = true if the field must be set.</summary>
    public bool[] IsRequired { get; }

    /// <summary>Indexed flags. <c>Indexed[ord]</c> = true if the field has a search index.</summary>
    public bool[] IsIndexed { get; }

    /// <summary>Max lengths. <c>MaxLengths[ord]</c> = 255, or 0 for unlimited/non-string.</summary>
    public int[] MaxLengths { get; }

    /// <summary>Field flags (combined). <c>Flags[ord]</c> = <see cref="FieldFlags.Nullable"/> | …</summary>
    public FieldFlags[] Flags { get; }

    // ── Boundary lookup ────────────────────────────────────────────────────

    /// <summary>
    /// Name → ordinal lookup. Used at API/form boundaries only — hot paths
    /// capture the ordinal in a closure and never touch this dictionary.
    /// </summary>
    public FrozenDictionary<string, int> NameToOrdinal { get; }

    /// <summary>FNV-1a hash of field names + types for schema migration detection.</summary>
    public ulong SchemaHash { get; }

    /// <summary>
    /// Private constructor — use <see cref="Builder"/> to create instances.
    /// </summary>
    private EntitySchema(
        string entityName,
        string slug,
        int fieldCount,
        string[] names,
        FieldType[] types,
        Type[] clrTypes,
        bool[] isNullable,
        bool[] isRequired,
        bool[] isIndexed,
        int[] maxLengths,
        FieldFlags[] flags,
        FrozenDictionary<string, int> nameToOrdinal,
        ulong schemaHash)
    {
        EntityName = entityName;
        Slug = slug;
        FieldCount = fieldCount;
        Names = names;
        Types = types;
        ClrTypes = clrTypes;
        IsNullable = isNullable;
        IsRequired = isRequired;
        IsIndexed = isIndexed;
        MaxLengths = maxLengths;
        Flags = flags;
        NameToOrdinal = nameToOrdinal;
        SchemaHash = schemaHash;
    }

    // ── Accessors ──────────────────────────────────────────────────────────

    /// <summary>Resolve a field name to its ordinal. Boundary path only.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryGetOrdinal(string name, out int ordinal)
        => NameToOrdinal.TryGetValue(name, out ordinal);

    /// <summary>Get the field name at an ordinal.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public string NameAt(int ordinal) => Names[ordinal];

    /// <summary>Get the field type at an ordinal.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public FieldType TypeAt(int ordinal) => Types[ordinal];

    /// <summary>Creates a new <see cref="DataRecord"/> sized for this schema.</summary>
    public DataRecord CreateRecord() => new(this);

    // ── FieldPlan builder (AOT-safe closures) ──────────────────────────────

    /// <summary>
    /// Builds <see cref="MetadataWireSerializer.FieldPlanDescriptor"/> entries
    /// for this schema. Getters/setters are simple ordinal closures — no
    /// <c>Expression.Compile</c>, no reflection, fully AOT-safe.
    /// </summary>
    public MetadataWireSerializer.FieldPlanDescriptor[] BuildFieldPlanDescriptors()
    {
        var descriptors = new MetadataWireSerializer.FieldPlanDescriptor[FieldCount];
        for (int i = 0; i < FieldCount; i++)
        {
            int ord = i; // capture for closure
            var (wireType, wireNullable, enumUnderlying) =
                MetadataWireSerializer.ResolveWireType(ClrTypes[i]);
            descriptors[i] = new MetadataWireSerializer.FieldPlanDescriptor
            {
                Name = Names[i],
                WireType = wireType,
                IsNullable = wireNullable || IsNullable[i],
                Getter = obj => ((DataRecord)obj).GetValue(ord),
                Setter = (obj, val) => ((DataRecord)obj).SetValue(ord, val),
                ClrType = ClrTypes[i],
                EnumUnderlying = enumUnderlying,
            };
        }
        return descriptors;
    }

    // ── Builder ────────────────────────────────────────────────────────────

    /// <summary>
    /// Fluent builder for <see cref="EntitySchema"/>. Add fields in ordinal
    /// order, then call <see cref="Build"/> to freeze the schema.
    /// </summary>
    public sealed class Builder
    {
        private readonly string _entityName;
        private readonly string _slug;
        private readonly List<string> _names = new();
        private readonly List<FieldType> _types = new();
        private readonly List<Type> _clrTypes = new();
        private readonly List<bool> _nullable = new();
        private readonly List<bool> _required = new();
        private readonly List<bool> _indexed = new();
        private readonly List<int> _maxLengths = new();
        private readonly List<FieldFlags> _flags = new();

        public Builder(string entityName, string slug)
        {
            _entityName = entityName;
            _slug = slug;
        }

        /// <summary>Adds a field to the schema at the next ordinal position.</summary>
        public Builder AddField(
            string name,
            FieldType type,
            Type clrType,
            bool nullable = false,
            bool required = false,
            bool indexed = false,
            int maxLength = 0,
            FieldFlags extraFlags = FieldFlags.None)
        {
            var flags = extraFlags;
            if (nullable) flags |= FieldFlags.Nullable;
            if (required) flags |= FieldFlags.Required;
            if (indexed) flags |= FieldFlags.Indexed;

            _names.Add(name);
            _types.Add(type);
            _clrTypes.Add(clrType);
            _nullable.Add(nullable);
            _required.Add(required);
            _indexed.Add(indexed);
            _maxLengths.Add(maxLength);
            _flags.Add(flags);
            return this;
        }

        /// <summary>The number of fields added so far.</summary>
        public int Count => _names.Count;

        /// <summary>Freezes the builder into an immutable <see cref="EntitySchema"/>.</summary>
        public EntitySchema Build()
        {
            var count = _names.Count;
            var names = _names.ToArray();
            var types = _types.ToArray();

            // Build frozen name→ordinal dictionary
            var dict = new Dictionary<string, int>(count, StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < count; i++)
                dict[names[i]] = i;

            // Compute FNV-1a schema hash
            ulong hash = 14695981039346656037UL;
            for (int i = 0; i < count; i++)
            {
                foreach (char c in names[i])
                {
                    hash ^= (byte)c;
                    hash *= 1099511628211UL;
                }
                hash ^= (byte)types[i];
                hash *= 1099511628211UL;
            }

            return new EntitySchema(
                entityName: _entityName,
                slug: _slug,
                fieldCount: count,
                names: names,
                types: types,
                clrTypes: _clrTypes.ToArray(),
                isNullable: _nullable.ToArray(),
                isRequired: _required.ToArray(),
                isIndexed: _indexed.ToArray(),
                maxLengths: _maxLengths.ToArray(),
                flags: _flags.ToArray(),
                nameToOrdinal: dict.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase),
                schemaHash: hash);
        }
    }
}
