using System;
using System.Globalization;
using System.Reflection;

namespace BareMetalWeb.Data;

/// <summary>
/// A <see cref="PropertyInfo"/> implementation for virtual entity fields.
/// Reads field values from and writes field values to a <see cref="DynamicDataObject"/>
/// string-keyed dictionary. All values are stored as strings to avoid serialization
/// complexity; the CLR <see cref="PropertyType"/> carries type metadata for form rendering.
/// </summary>
internal sealed class DynamicPropertyInfo : PropertyInfo
{
    private readonly string _fieldName;
    private readonly Type _propertyType;

    public DynamicPropertyInfo(string fieldName, Type propertyType)
    {
        _fieldName = fieldName ?? throw new ArgumentNullException(nameof(fieldName));
        _propertyType = propertyType ?? throw new ArgumentNullException(nameof(propertyType));
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
    /// Returns the field's string value from the <see cref="DynamicDataObject"/> dictionary,
    /// or <c>null</c> if the object is not a <see cref="DynamicDataObject"/>.
    /// </summary>
    public override object? GetValue(object? obj, BindingFlags invokeAttr, Binder? binder, object?[]? index, CultureInfo? culture)
    {
        if (obj is DynamicDataObject dynamicObj)
            return dynamicObj.GetField(_fieldName);
        return null;
    }

    /// <summary>
    /// Stores the value in the <see cref="DynamicDataObject"/> dictionary as a string.
    /// Handles common CLR types (bool, DateTime, DateOnly, TimeOnly, enums, numerics).
    /// </summary>
    public override void SetValue(object? obj, object? value, BindingFlags invokeAttr, Binder? binder, object?[]? index, CultureInfo? culture)
    {
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
