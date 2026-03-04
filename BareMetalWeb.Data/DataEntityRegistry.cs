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


}
