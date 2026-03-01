using System.Linq.Expressions;
using System.Reflection;

namespace BareMetalWeb.Data;

/// <summary>
/// Builds compiled getter and setter delegates from <see cref="PropertyInfo"/> instances using
/// <see cref="Expression"/> trees, eliminating per-call <see cref="PropertyInfo.GetValue"/> /
/// <see cref="PropertyInfo.SetValue"/> reflection overhead.
/// </summary>
public static class PropertyAccessorFactory
{
    /// <summary>
    /// Returns a compiled <see cref="Func{Object, Object}"/> that reads the property value from a
    /// boxed instance without going through <see cref="PropertyInfo.GetValue"/>.
    /// Falls back to <see cref="PropertyInfo.GetValue"/> when the property has no public getter
    /// (e.g. <see cref="DynamicPropertyInfo"/>).
    /// </summary>
    public static Func<object, object?> BuildGetter(PropertyInfo property)
    {
        if (property.GetGetMethod(nonPublic: false) == null)
            return obj => property.GetValue(obj);

        var instanceParam = Expression.Parameter(typeof(object), "instance");
        var declaringType = property.DeclaringType ?? typeof(object);
        var castInstance = Expression.Convert(instanceParam, declaringType);
        var propertyAccess = Expression.Property(castInstance, property);
        var boxed = Expression.Convert(propertyAccess, typeof(object));
        return Expression.Lambda<Func<object, object?>>(boxed, instanceParam).Compile();
    }

    /// <summary>
    /// Returns a compiled <see cref="Action{Object, Object}"/> that writes a value to the property
    /// on a boxed instance without going through <see cref="PropertyInfo.SetValue"/>.
    /// Falls back to <see cref="PropertyInfo.SetValue"/> when the property has no public setter.
    /// </summary>
    public static Action<object, object?> BuildSetter(PropertyInfo property)
    {
        if (property.GetSetMethod(nonPublic: false) == null)
            return (obj, val) => property.SetValue(obj, val);

        var instanceParam = Expression.Parameter(typeof(object), "instance");
        var valueParam = Expression.Parameter(typeof(object), "value");
        var declaringType = property.DeclaringType ?? typeof(object);
        var castInstance = Expression.Convert(instanceParam, declaringType);
        Expression castValue = Expression.Convert(valueParam, property.PropertyType);
        var propertyAccess = Expression.Property(castInstance, property);
        var assign = Expression.Assign(propertyAccess, castValue);
        return Expression.Lambda<Action<object, object?>>(assign, instanceParam, valueParam).Compile();
    }
}
