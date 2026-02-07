using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Data;

public static class DataStoreProvider
{
    public static IDataObjectStore Current { get; set; } = new DataObjectStore();
    public static object IndexLeaderSync { get; } = new();
    public static IndexLeader? IndexLeader { get; set; }
    public static IndexHeartbeatMonitor? IndexHeartbeatMonitor { get; set; }
    public static IndexLeaderElection? IndexLeaderElection { get; set; }
    public static IReadOnlyList<IndexStore.IndexLease> IndexLeases { get; set; } = Array.Empty<IndexStore.IndexLease>();
    public static ClusteredCheckpointScheduler? ClusteredCheckpointScheduler { get; set; }
}
