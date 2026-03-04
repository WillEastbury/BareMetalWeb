namespace BareMetalWeb.Data;

/// <summary>
/// Legacy loader for virtual entity definitions from a JSON config file.
/// Superseded by the gallery package system (RuntimeEntityRegistry + WalDataProvider).
/// Retained as a no-op stub for backward compatibility.
/// </summary>
public static class VirtualEntityLoader
{
    /// <summary>
    /// Previously loaded virtual entities from a JSON config file.
    /// Now a no-op — entities are deployed via gallery packages and loaded
    /// by RuntimeEntityRegistry.
    /// </summary>
    public static void LoadFromFile(string filePath, string dataRootPath)
    {
        // No-op: virtual entity JSON config files are superseded by gallery packages.
    }
}
