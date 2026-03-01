using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Reflection;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Compiles DataEntityMetadata into dense, ordinal-indexed EntityLayout at startup.
/// All reflection happens here — hot paths use only the compiled result.
/// </summary>
public static class EntityLayoutCompiler
{
    private static readonly ConcurrentDictionary<string, EntityLayout> _cache = new(StringComparer.Ordinal);

    /// <summary>Get or compile a layout for the given entity metadata. Thread-safe, cached.</summary>
    public static EntityLayout GetOrCompile(DataEntityMetadata meta)
    {
        return _cache.GetOrAdd(meta.Slug, _ =>
        {
            IReadOnlyList<string> w;
            return Compile(meta, out w);
        });
    }

    /// <summary>Get or compile a layout, also returning validation warnings.</summary>
    public static EntityLayout GetOrCompile(DataEntityMetadata meta, out IReadOnlyList<string> warnings)
    {
        if (_cache.TryGetValue(meta.Slug, out var cached))
        {
            warnings = Array.Empty<string>();
            return cached;
        }
        var layout = Compile(meta, out warnings);
        _cache.TryAdd(meta.Slug, layout);
        return layout;
    }

    /// <summary>
    /// Compile DataEntityMetadata → EntityLayout.
    /// Maps all public read/write properties to FieldRuntime with dense ordinals,
    /// fixed offsets, var indices, and codec IDs.
    /// </summary>
    public static EntityLayout Compile(DataEntityMetadata meta, out IReadOnlyList<string> warnings)
    {
        var warns = new List<string>();
        var metaFieldsByName = meta.Fields.ToDictionary(f => f.Name, StringComparer.Ordinal);

        var props = meta.Type
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.CanRead && p.CanWrite)
            .OrderBy(p => p.Name, StringComparer.Ordinal)
            .ToArray();

        if (props.Length == 0)
            warns.Add($"Entity '{meta.Name}' has no public read/write properties.");

        bool hasKey = props.Any(p => p.Name == "Key" && p.PropertyType == typeof(uint));
        if (!hasKey)
            warns.Add($"Entity '{meta.Name}' is missing a uint Key property.");

        var fields = new FieldRuntime[props.Length];
        var nameToOrd = new Dictionary<string, int>(props.Length, StringComparer.OrdinalIgnoreCase);
        int fixedOffset = 0;
        ushort varIndex = 0;

        for (int i = 0; i < props.Length; i++)
        {
            var prop = props[i];
            var fieldType = ResolveFieldType(prop.PropertyType);
            bool isNullable = IsNullableType(prop.PropertyType);
            var codecId = CodecTable.CodecIdFor(fieldType);
            var codec = CodecTable.Get(codecId);
            int fixedSize = codec.FixedSize;
            bool isVar = fixedSize == 0;

            // Build flags
            var flags = FieldFlags.None;
            if (isNullable) flags |= FieldFlags.Nullable;
            if (metaFieldsByName.TryGetValue(prop.Name, out var fieldMeta))
            {
                if (fieldMeta.Required) flags |= FieldFlags.Required;
                if (fieldMeta.ReadOnly) flags |= FieldFlags.ReadOnly;
                if (fieldMeta.IsIndexed) flags |= FieldFlags.Indexed;
                if (fieldMeta.Lookup is not null) flags |= FieldFlags.Lookup;
                if (fieldMeta.Computed is not null) flags |= FieldFlags.Computed;
            }

            // Reuse compiled delegates from metadata where available
            Func<object, object?> getter;
            Action<object, object?> setter;
            if (fieldMeta is not null)
            {
                getter = fieldMeta.GetValueFn;
                setter = fieldMeta.SetValueFn;
            }
            else
            {
                getter = PropertyAccessorFactory.BuildGetter(prop);
                setter = PropertyAccessorFactory.BuildSetter(prop);
            }

            fields[i] = new FieldRuntime
            {
                Ordinal = i,
                Name = prop.Name,
                NameHash = EntityLayout.Fnv1aHash(prop.Name),
                Type = fieldType,
                Flags = flags,
                FixedSizeBytes = (ushort)(isVar ? 0 : fixedSize),
                FixedOffset = isVar ? -1 : fixedOffset,
                VarIndex = isVar ? varIndex : (ushort)0,
                CodecId = codecId,
                ClrType = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType,
                Getter = getter,
                Setter = setter,
            };

            nameToOrd[prop.Name] = i;

            if (isVar)
                varIndex++;
            else
                fixedOffset += fixedSize;
        }

        // Validate: check for duplicate ordinals (shouldn't happen with dense assignment)
        var seen = new HashSet<int>();
        foreach (var f in fields)
        {
            if (!seen.Add(f.Ordinal))
                warns.Add($"Duplicate ordinal {f.Ordinal} in entity '{meta.Name}'.");
        }

        int nullBitmapBytes = (fields.Length + 7) / 8;

        // Compute schema hash (FNV-1a over field names + types + ordinals)
        ulong schemaHash = 14695981039346656037UL;
        foreach (var f in fields)
        {
            foreach (char c in f.Name)
            {
                schemaHash ^= (byte)c;
                schemaHash *= 1099511628211UL;
            }
            schemaHash ^= (byte)f.Type;
            schemaHash *= 1099511628211UL;
            schemaHash ^= (byte)f.Ordinal;
            schemaHash *= 1099511628211UL;
        }

        warnings = warns;
        return new EntityLayout
        {
            EntityName = meta.Name,
            Slug = meta.Slug,
            ClrType = meta.Type,
            Fields = fields,
            NullBitmapBytes = nullBitmapBytes,
            FixedRegionBytes = fixedOffset,
            VarFieldCount = varIndex,
            SchemaHash = schemaHash,
            NameToOrdinal = nameToOrd.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase),
        };
    }

    /// <summary>Map CLR type to FieldType enum. Called once at compile time.</summary>
    public static FieldType ResolveFieldType(Type clrType)
    {
        var underlying = Nullable.GetUnderlyingType(clrType) ?? clrType;

        if (underlying.IsEnum) return FieldType.EnumInt32;
        if (underlying == typeof(IdentifierValue)) return FieldType.Identifier;

        return Type.GetTypeCode(underlying) switch
        {
            TypeCode.Boolean  => FieldType.Bool,
            TypeCode.Byte     => FieldType.Byte,
            TypeCode.SByte    => FieldType.SByte,
            TypeCode.Int16    => FieldType.Int16,
            TypeCode.UInt16   => FieldType.UInt16,
            TypeCode.Int32    => FieldType.Int32,
            TypeCode.UInt32   => FieldType.UInt32,
            TypeCode.Int64    => FieldType.Int64,
            TypeCode.UInt64   => FieldType.UInt64,
            TypeCode.Single   => FieldType.Float32,
            TypeCode.Double   => FieldType.Float64,
            TypeCode.Decimal  => FieldType.Decimal,
            TypeCode.Char     => FieldType.Char,
            TypeCode.String   => FieldType.StringUtf8,
            TypeCode.DateTime => FieldType.DateTime,
            _ when underlying == typeof(DateOnly)       => FieldType.DateOnly,
            _ when underlying == typeof(TimeOnly)       => FieldType.TimeOnly,
            _ when underlying == typeof(DateTimeOffset) => FieldType.DateTimeOffset,
            _ when underlying == typeof(TimeSpan)       => FieldType.TimeSpan,
            _ when underlying == typeof(Guid)           => FieldType.Guid,
            _ when underlying == typeof(byte[])         => FieldType.Bytes,
            _ => FieldType.StringUtf8, // fallback: serialize as string
        };
    }

    private static bool IsNullableType(Type type)
        => !type.IsValueType || Nullable.GetUnderlyingType(type) is not null;
}
