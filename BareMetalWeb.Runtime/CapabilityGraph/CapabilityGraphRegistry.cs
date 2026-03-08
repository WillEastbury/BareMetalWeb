namespace BareMetalWeb.Runtime.CapabilityGraph;

/// <summary>
/// Global singleton holder for the built capability graph.
/// Set once at startup after <see cref="CapabilityGraphBuilder.BuildAsync"/>.
/// </summary>
public static class CapabilityGraphRegistry
{
    private static MetadataCapabilityGraph? _current;

    /// <summary>
    /// The current capability graph. Null before startup completes.
    /// </summary>
    public static MetadataCapabilityGraph? Current
    {
        get => Volatile.Read(ref _current);
        set => Volatile.Write(ref _current, value);
    }
}
