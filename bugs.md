# Bugs

- High: SearchIndexManager.IndexObject builds tokens outside the lock, but BuildTokens mutates index.WarnedKinds (a HashSet) without synchronization; concurrent indexing can corrupt the set or throw. See Data/SearchIndexing.cs#L87-L95 and Data/SearchIndexing.cs#L239-L258.

- High: Clustered index updates are not crash-atomic. In SaveAsync, the flow logs a delete for the old location before logging the add for the new location; a crash between those writes leaves the index missing the record and the new payload orphaned. See Data/LocalFolderBinaryDataProvider.cs#L220-L244.

- Medium: Index reads are not lock-protected. ReadIndex, ReadLatestValueIndex, and TryGetLatestValue read paged files without taking the same index lock used by AppendEntry, so readers can see partially written pages or inconsistent snapshots. See Data/IndexStore.cs#L60-L132.

- Medium: Schema cache dictionaries are mutated without synchronization; concurrent SaveAsync calls can race on SchemaCache.Versions and SchemaCache.HashToVersion, causing inconsistent schema versions or corrupt state. See Data/LocalFolderBinaryDataProvider.cs#L32-L41 and Data/LocalFolderBinaryDataProvider.cs#L206-L237.

- Medium: The in-memory clustered location map can go stale and never self-heal. TryGetClusteredLocation trusts the map and LoadAsync does not evict on missing payloads, so a stale location can lead to persistent null reads until restart. See Data/LocalFolderBinaryDataProvider.cs#L504-L533 and Data/LocalFolderBinaryDataProvider.cs#L246-L254.

- Low/Medium: Query comparisons can throw on type mismatch. ConvertToType returns the original value on failed conversion, then Compare uses IComparable.CompareTo with a mismatched type, which can throw for some types during GreaterThan/LessThan queries. See Data/DataQuery.cs#L302-L327 and Data/DataQuery.cs#L404-L433.
