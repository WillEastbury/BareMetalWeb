# Footguns that we need to fix later 

## 1. Lookup metadata is cached in memory intentionally for certain items, but this can lead to stale data if the underlying metadata changes. We should implement a cache invalidation strategy to ensure that the cached metadata is refreshed when necessary.