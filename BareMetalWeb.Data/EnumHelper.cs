using System;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// AOT-safe, allocation-free enum conversion helpers.
/// Replaces <c>Enum.ToObject</c> and <c>Convert.ChangeType</c> on hot paths by using
/// per-type caches built once at startup.
/// </summary>
public static class EnumHelper
{
    // Maps enum Type → (long → boxed enum value) built once per type.
    private static readonly ConcurrentDictionary<Type, Dictionary<long, object>> IntToEnumCache = new();

    // Maps enum Type → TypeCode of its underlying integer type.
    private static readonly ConcurrentDictionary<Type, TypeCode> UnderlyingTypeCodeCache = new();

    /// <summary>
    /// Converts a boxed integral value to the boxed enum value of <paramref name="enumType"/>.
    /// Equivalent to <c>Enum.ToObject(enumType, value)</c> but uses a cached lookup so no
    /// runtime reflection occurs after the first call per type.
    /// Falls back to <c>Enum.ToObject</c> only for values not present in the enum definition.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static object FromLong(Type enumType, long raw)
    {
        var cache = IntToEnumCache.GetOrAdd(enumType, BuildIntCache);
        return cache.TryGetValue(raw, out var v) ? v : Enum.ToObject(enumType, raw);
    }

    /// <summary>
    /// Converts a boxed <see cref="int"/> value to the boxed enum value.
    /// Common fast-path: most enums have <c>int</c> as the underlying type.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static object FromInt32(Type enumType, int raw)
        => FromLong(enumType, raw);

    /// <summary>
    /// Returns the <see cref="TypeCode"/> of the enum's underlying integer type,
    /// cached per enum type to avoid repeated reflection.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static TypeCode GetUnderlyingTypeCode(Type enumType)
        => UnderlyingTypeCodeCache.GetOrAdd(enumType,
            static t => Type.GetTypeCode(Enum.GetUnderlyingType(t)));

    /// <summary>
    /// Extracts the underlying integral value from a boxed enum as a boxed value of
    /// <paramref name="underlyingTypeCode"/>.  Replaces
    /// <c>Convert.ChangeType(value, underlying)</c> for the serialization write path —
    /// no dynamic dispatch or TypeConverter overhead.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static object ToUnderlyingValue(object enumValue, TypeCode underlyingTypeCode)
    {
        if (enumValue is not IConvertible ic)
            return 0;
        return underlyingTypeCode switch
        {
            TypeCode.Int32  => (object)ic.ToInt32(null),
            TypeCode.Byte   => ic.ToByte(null),
            TypeCode.SByte  => ic.ToSByte(null),
            TypeCode.Int16  => ic.ToInt16(null),
            TypeCode.UInt16 => ic.ToUInt16(null),
            TypeCode.UInt32 => ic.ToUInt32(null),
            TypeCode.Int64  => ic.ToInt64(null),
            TypeCode.UInt64 => ic.ToUInt64(null),
            _               => ic.ToInt32(null),
        };
    }

    // ── Private helpers ─────────────────────────────────────────────────

    /// <summary>
    /// Returns a boxed zero value of the underlying integer type.
    /// Used during enum serialization when the enum value is <c>null</c>.
    /// Avoids <c>Enum.ToObject</c> on the write path.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static object GetZeroUnderlying(TypeCode underlyingTypeCode) => underlyingTypeCode switch
    {
        TypeCode.Int32  => (object)0,
        TypeCode.Byte   => (byte)0,
        TypeCode.SByte  => (sbyte)0,
        TypeCode.Int16  => (short)0,
        TypeCode.UInt16 => (ushort)0,
        TypeCode.UInt32 => 0u,
        TypeCode.Int64  => 0L,
        TypeCode.UInt64 => 0UL,
        _               => (object)0,
    };

    private static Dictionary<long, object> BuildIntCache(Type enumType)
    {
        var values = Enum.GetValues(enumType);
        var dict = new Dictionary<long, object>(values.Length);
        foreach (var v in values)
        {
            var key = ((IConvertible)v!).ToInt64(null);
            dict.TryAdd(key, v!);
        }
        return dict;
    }
}
