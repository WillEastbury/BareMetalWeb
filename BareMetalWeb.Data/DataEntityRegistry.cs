using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using BareMetalWeb.Core;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Data;

public static class DataEntityRegistry
{
    [RequiresUnreferencedCode("Assembly scanning and MakeGenericMethod require all entity types to be preserved via TrimmerRootAssembly.")]
    public static void RegisterAllEntities()
    {
        foreach (var type in GetDataEntityTypes())
            RegisterEntity(type);
    }

    /// <summary>
    /// Loads virtual entity definitions from <paramref name="filePath"/> and registers
    /// them with <see cref="DataScaffold"/>. If the file does not exist, the call is a no-op.
    /// </summary>
    /// <param name="filePath">Path to the JSON virtual-entities definition file.</param>
    /// <param name="dataRootPath">Root path for JSON data storage.</param>
    public static void RegisterVirtualEntitiesFromFile(string filePath, string dataRootPath)
    {
        VirtualEntityLoader.LoadFromFile(filePath, dataRootPath);
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

                // Exclude DynamicDataObject — virtual entities are registered separately
                if (type == typeof(DynamicDataObject))
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

    [RequiresUnreferencedCode("Assembly.GetTypes() may not return all types when trimming is enabled.")]
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

    [RequiresUnreferencedCode("MakeGenericMethod requires the target type to be preserved.")]
    private static void RegisterEntity(Type type)
    {
        var method = typeof(DataScaffold).GetMethod(nameof(DataScaffold.RegisterEntity))!;
        var generic = method.MakeGenericMethod(type);
        generic.Invoke(null, null);
    }
}
