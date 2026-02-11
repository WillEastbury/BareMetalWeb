using System.Reflection;
using BareMetalWeb.Core;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Data;

public static class DataEntityRegistry
{
    public static void RegisterAllEntities()
    {
        foreach (var type in GetDataEntityTypes())
            RegisterEntity(type);
    }

    private static IEnumerable<Type> GetDataEntityTypes()
    {
        var assemblies = AppDomain.CurrentDomain.GetAssemblies();
        foreach (var assembly in assemblies)
        {
            foreach (var type in GetTypesSafely(assembly))
            {
                if (type is null)
                    continue;

                if (type.IsAbstract || !typeof(BaseDataObject).IsAssignableFrom(type))
                    continue;

                if (type == typeof(RenderableDataObject))
                    continue;

                if (type.GetCustomAttribute<DataEntityAttribute>(inherit: false) is null
                    && !typeof(RenderableDataObject).IsAssignableFrom(type))
                    continue;

                if (type.GetConstructor(Type.EmptyTypes) is null)
                    continue;

                yield return type;
            }
        }
    }

    private static IEnumerable<Type?> GetTypesSafely(Assembly assembly)
    {
        try
        {
            return assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            return ex.Types;
        }
    }

    private static void RegisterEntity(Type type)
    {
        var method = typeof(DataScaffold).GetMethod(nameof(DataScaffold.RegisterEntity))!;
        var generic = method.MakeGenericMethod(type);
        generic.Invoke(null, null);
    }
}
