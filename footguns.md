# Footguns

- High: Index reads are unlocked, so readers can observe partially written pages or inconsistent snapshot/log state during concurrent AppendEntry writes. Affects ReadIndex, ReadLatestValueIndex, and TryGetLatestValue in Data/IndexStore.cs#L60-L116.
- Medium: Heartbeat writes open the file with FileShare.Read, so concurrent timer ticks or a second leader attempt will throw IO exceptions and can cause false "stale" detection loops. See Data/IndexLeadership.cs#L44-L52 and Data/IndexLeadership.cs#L212-L236.
- Medium: EnsureEntityLeader is called on every save/delete; if leadership is enabled but not acquired (or stale), write/delete operations throw and return 500s rather than retrying or queuing. See Data/LocalFolderBinaryDataProvider.cs#L188-L207 and Data/LocalFolderBinaryDataProvider.cs#L448-L466, rooted in Data/DataStoreProvider.cs#L49-L71.
- Medium: Clustered checkpoint compaction uses IsEntityLeader; when leadership is disabled, that returns true for all nodes, so compaction can run concurrently across instances sharing storage. See Data/DataStoreProvider.cs#L36-L47 and Data/ClusteredCheckpointScheduler.cs#L35-L69.
- Low: Heartbeat monitor does a single File.ReadAllText with no retry/backoff. Transient IO failures flip state to "error"/"stale" and may spam logs. See Data/IndexLeadership.cs#L212-L236.
