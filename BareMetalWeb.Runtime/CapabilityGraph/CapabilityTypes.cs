namespace BareMetalWeb.Runtime.CapabilityGraph;

/// <summary>
/// The type of capability a node represents in the metadata graph.
/// </summary>
public enum CapabilityType : byte
{
    QueryEntity,
    CreateEntity,
    UpdateEntity,
    DeleteEntity,
    RunAction,
    RunWorkflow,
    NavigateView,
    TraverseRelationship
}

/// <summary>
/// Compact node in the capability graph. Uses integer IDs for
/// cache-friendly adjacency-list traversal.
/// </summary>
public readonly struct CapabilityNode
{
    public readonly int Id;
    public readonly CapabilityType Type;
    /// <summary>Index into <see cref="MetadataCapabilityGraph.Entities"/> (-1 if not entity-scoped).</summary>
    public readonly int EntityIndex;
    /// <summary>Display label (e.g. "QueryCustomer", "RunWorkflow(send_discount_email)").</summary>
    public readonly string Label;
    /// <summary>Optional detail — action name, workflow schedule, view name, etc.</summary>
    public readonly string? Detail;

    public CapabilityNode(int id, CapabilityType type, int entityIndex, string label, string? detail = null)
    {
        Id = id;
        Type = type;
        EntityIndex = entityIndex;
        Label = label;
        Detail = detail;
    }

    public override string ToString() => $"[{Id}] {Type}: {Label}";
}

/// <summary>
/// Directed edge between two capability nodes.
/// </summary>
public readonly struct CapabilityEdge
{
    public readonly int FromNode;
    public readonly int ToNode;

    public CapabilityEdge(int fromNode, int toNode)
    {
        FromNode = fromNode;
        ToNode = toNode;
    }

    public override string ToString() => $"{FromNode} → {ToNode}";
}

/// <summary>
/// Minimal entity descriptor stored alongside the graph for label resolution.
/// </summary>
public readonly struct EntityDescriptor
{
    public readonly string EntityId;
    public readonly string Name;
    public readonly string Slug;

    public EntityDescriptor(string entityId, string name, string slug)
    {
        EntityId = entityId;
        Name = name;
        Slug = slug;
    }
}
