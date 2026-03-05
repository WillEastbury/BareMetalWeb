using System.Diagnostics.CodeAnalysis;
using System.Linq.Expressions;
using System.Reflection;

namespace BareMetalWeb.Data;

// IsExternalInit is the compiler-synthesised modreq placed on the return parameter of every
// init-only setter.  Expression-tree compilation rejects these setters with BadImageFormatException
// because the JIT cannot verify the modreq at compile time.  Detecting it allows us to fall back to
// PropertyInfo.SetValue, which honours the restriction correctly through reflection.
file static class IsExternalInitDetector
{
    private const string ModreqFullName = "System.Runtime.CompilerServices.IsExternalInit";

    internal static bool IsInitOnlySetter(MethodInfo setter)
    {
        foreach (var t in setter.ReturnParameter.GetRequiredCustomModifiers())
        {
            if (t.FullName == ModreqFullName)
                return true;
        }
        return false;
    }
}

/// <summary>
/// Builds compiled getter and setter delegates from <see cref="PropertyInfo"/> instances using
/// <see cref="Expression"/> trees, eliminating per-call <see cref="PropertyInfo.GetValue"/> /
/// <see cref="PropertyInfo.SetValue"/> reflection overhead.
/// <para>
/// <b>AOT note:</b> <c>Expression.Lambda.Compile()</c> is not supported under Native AOT.
/// For AOT-safe access, use <see cref="DataRecord"/> with ordinal-indexed storage and
/// <see cref="EntitySchema.BuildFieldPlanDescriptors"/> — no Expression compilation needed.
/// </para>
/// </summary>
public static class PropertyAccessorFactory
{
    /// <summary>
    /// Returns a compiled <see cref="Func{Object, Object}"/> that reads the property value from a
    /// boxed instance without going through <see cref="PropertyInfo.GetValue"/>.
    /// Falls back to <see cref="PropertyInfo.GetValue"/> when the property has no public getter
    /// (e.g. <see cref="DynamicPropertyInfo"/>).
    /// </summary>
    [RequiresUnreferencedCode("Expression.Lambda.Compile() is not AOT-safe. Use DataRecord ordinal access instead.")]
    public static Func<object, object?> BuildGetter(PropertyInfo property)
    {
        // DynamicPropertyInfo has no GetGetMethod — use its overridden GetValue directly (AOT-safe)
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
    [RequiresUnreferencedCode("Expression.Lambda.Compile() is not AOT-safe. Use DataRecord ordinal access instead.")]
    public static Action<object, object?> BuildSetter(PropertyInfo property)
    {
        var setter = property.GetSetMethod(nonPublic: false);

        // Fall back to PropertyInfo.SetValue when there is no public setter, or when the setter is
        // init-only.  Init-only setters carry the IsExternalInit modreq which causes the expression-tree
        // compiler to throw BadImageFormatException (Bad binary signature, 0x80131192).
        // DynamicPropertyInfo returns null here — uses its overridden SetValue directly (AOT-safe).
        if (setter == null || IsExternalInitDetector.IsInitOnlySetter(setter))
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
