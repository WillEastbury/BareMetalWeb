using System;
using System.Globalization;
using System.Reflection;

namespace BareMetalWeb.Data;

/// <summary>
/// A <see cref="PropertyInfo"/> implementation for virtual entity fields.
/// Uses <see cref="DataRecord"/> (ordinal-indexed <c>object?[]</c>) storage
/// for ~1–2 ns field access.
/// </summary>
internal sealed class DynamicPropertyInfo : PropertyInfo
{
    private readonly string _fieldName;
    private readonly Type _propertyType;
    private readonly int _ordinal;

    /// <summary>Creates a property backed by ordinal index on <see cref="DataRecord"/>.</summary>
    public DynamicPropertyInfo(string fieldName, Type propertyType, int ordinal = -1)
    {
        _fieldName = fieldName ?? throw new ArgumentNullException(nameof(fieldName));
        _propertyType = propertyType ?? throw new ArgumentNullException(nameof(propertyType));
        _ordinal = ordinal;
    }

    // ── MemberInfo ──────────────────────────────────────────────────────────

    public override string Name => _fieldName;
    public override Type? DeclaringType => typeof(DataRecord);
    public override Type? ReflectedType => typeof(DataRecord);
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
    /// Returns the field value using ordinal array access (~1–2 ns).
    /// </summary>
    public override object? GetValue(object? obj, BindingFlags invokeAttr, Binder? binder, object?[]? index, CultureInfo? culture)
    {
        if (obj is DataRecord dr)
        {
            if (_ordinal >= 0) return dr.GetValue(_ordinal);
            if (dr.Schema != null) return dr.GetField(dr.Schema, _fieldName);
        }
        return null;
    }

    /// <summary>
    /// Stores a native CLR value by ordinal.
    /// </summary>
    public override void SetValue(object? obj, object? value, BindingFlags invokeAttr, Binder? binder, object?[]? index, CultureInfo? culture)
    {
        if (obj is not DataRecord dr) return;
        if (_ordinal >= 0) { dr.SetValue(_ordinal, value); return; }
        if (dr.Schema != null) { dr.SetField(dr.Schema, _fieldName, value); return; }
    }

    // ── Attribute stubs ─────────────────────────────────────────────────────

    public override object[] GetCustomAttributes(bool inherit) => Array.Empty<object>();
    public override object[] GetCustomAttributes(Type attributeType, bool inherit) => Array.Empty<object>();
    public override bool IsDefined(Type attributeType, bool inherit) => false;
}
