using System;
using System.Globalization;
using System.Reflection;

namespace BareMetalWeb.Data;

/// <summary>
/// A <see cref="PropertyInfo"/> implementation for virtual entity fields.
/// Supports both legacy <see cref="DynamicDataObject"/> (string dictionary) and
/// <see cref="DataRecord"/> (ordinal-indexed <c>object?[]</c>) storage.
/// When an ordinal is provided, <see cref="DataRecord"/> access is ~1–2 ns via array index.
/// </summary>
internal sealed class DynamicPropertyInfo : PropertyInfo
{
    private readonly string _fieldName;
    private readonly Type _propertyType;
    private readonly int _ordinal;

    /// <summary>Creates a property backed by dictionary lookup (legacy path).</summary>
    public DynamicPropertyInfo(string fieldName, Type propertyType)
        : this(fieldName, propertyType, -1) { }

    /// <summary>Creates a property backed by ordinal index on <see cref="DataRecord"/>.</summary>
    public DynamicPropertyInfo(string fieldName, Type propertyType, int ordinal)
    {
        _fieldName = fieldName ?? throw new ArgumentNullException(nameof(fieldName));
        _propertyType = propertyType ?? throw new ArgumentNullException(nameof(propertyType));
        _ordinal = ordinal;
    }

    // ── MemberInfo ──────────────────────────────────────────────────────────

    public override string Name => _fieldName;
    public override Type? DeclaringType => typeof(DynamicDataObject);
    public override Type? ReflectedType => typeof(DynamicDataObject);
    public override MemberTypes MemberType => MemberTypes.Property;

    // ── PropertyInfo ────────────────────────────────────────────────────────

    public override Type PropertyType => _propertyType;
    public override PropertyAttributes Attributes => PropertyAttributes.None;
    public override bool CanRead => true;
    public override bool CanWrite => true;

    public override ParameterInfo[] GetIndexParameters() => Array.Empty<ParameterInfo>();
    public override MethodInfo[] GetAccessors(bool nonPublic) => Array.Empty<MethodInfo>();
    public override MethodInfo? GetGetMethod(bool nonPublic) => null;
    public override MethodInfo? GetSetMethod(bool nonPublic) => null;

    /// <summary>
    /// Returns the field value. For <see cref="DataRecord"/>, uses ordinal array access (~1–2 ns).
    /// For <see cref="DynamicDataObject"/>, falls back to dictionary lookup.
    /// </summary>
    public override object? GetValue(object? obj, BindingFlags invokeAttr, Binder? binder, object?[]? index, CultureInfo? culture)
    {
        if (obj is DataRecord dr)
        {
            if (_ordinal >= 0) return dr.GetValue(_ordinal);
            if (dr.Schema != null) return dr.GetField(dr.Schema, _fieldName);
        }
        if (obj is DynamicDataObject dynamicObj)
            return dynamicObj.GetField(_fieldName);
        return null;
    }

    /// <summary>
    /// Stores a value. For <see cref="DataRecord"/>, stores the native CLR value by ordinal.
    /// For <see cref="DynamicDataObject"/>, converts to string and stores in dictionary.
    /// </summary>
    public override void SetValue(object? obj, object? value, BindingFlags invokeAttr, Binder? binder, object?[]? index, CultureInfo? culture)
    {
        if (obj is DataRecord dr)
        {
            if (_ordinal >= 0) { dr.SetValue(_ordinal, value); return; }
            if (dr.Schema != null) { dr.SetField(dr.Schema, _fieldName, value); return; }
        }
        if (obj is not DynamicDataObject dynamicObj)
            return;

        dynamicObj.SetField(_fieldName, ConvertToString(value));
    }

    // ── Attribute stubs ─────────────────────────────────────────────────────

    public override object[] GetCustomAttributes(bool inherit) => Array.Empty<object>();
    public override object[] GetCustomAttributes(Type attributeType, bool inherit) => Array.Empty<object>();
    public override bool IsDefined(Type attributeType, bool inherit) => false;

    // ── Helpers ─────────────────────────────────────────────────────────────

    /// <summary>Converts a CLR value to its string representation for dictionary storage.</summary>
    internal static string? ConvertToString(object? value)
    {
        if (value == null)
            return null;

        return value switch
        {
            bool b => b ? "true" : "false",
            DateTime dt => dt.ToString("O", CultureInfo.InvariantCulture),
            DateTimeOffset dto => dto.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
            DateOnly d => d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            TimeOnly t => t.ToString("HH:mm:ss", CultureInfo.InvariantCulture),
            _ => value.ToString()
        };
    }
}
