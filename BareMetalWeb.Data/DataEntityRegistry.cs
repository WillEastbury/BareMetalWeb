using BareMetalWeb.Core;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Data;

public static class DataEntityRegistry
{
    /// <summary>
    /// Registers a single entity type without reflection or assembly scanning.
    /// AOT-safe alternative to reflection-based registration.
    /// </summary>
    public static bool RegisterEntity<T>() where T : BaseDataObject, new()
        => DataScaffold.RegisterEntity<T>();

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
}
