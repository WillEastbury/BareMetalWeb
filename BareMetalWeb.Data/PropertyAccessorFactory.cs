using System.Reflection;

namespace BareMetalWeb.Data;

/// <summary>
/// Builds getter and setter delegates from <see cref="PropertyInfo"/> instances.
/// Uses direct <see cref="PropertyInfo.GetValue"/>/<see cref="PropertyInfo.SetValue"/>
/// which is AOT-safe (no Expression tree compilation required).
/// <para>
/// For <see cref="DataRecord"/> fields, <see cref="DynamicPropertyInfo"/> provides
/// ordinal-indexed O(1) access with zero reflection overhead.
/// </para>
/// </summary>
public static class PropertyAccessorFactory
{
    /// <summary>
    /// Returns a delegate that reads the property value from a boxed instance.
    /// </summary>
    public static Func<object, object?> BuildGetter(PropertyInfo property)
    {
        return obj => property.GetValue(obj);
    }

    /// <summary>
    /// Returns a delegate that writes a value to the property on a boxed instance.
    /// </summary>
    public static Action<object, object?> BuildSetter(PropertyInfo property)
    {
        return (obj, val) => property.SetValue(obj, val);
    }
}
