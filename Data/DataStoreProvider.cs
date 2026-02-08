using System;
using System.Collections.Generic;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Data;

public static class DataStoreProvider
{
    public static IDataObjectStore Current { get; set; } = new DataObjectStore();
    public static LocalFolderBinaryDataProvider? PrimaryProvider { get; set; }
    public static bool EntityLeadershipEnabled { get; set; }
    public static ClusteredCheckpointScheduler? ClusteredCheckpointScheduler { get; set; }

    private static readonly object EntityLeaderSync = new();
    private static readonly Dictionary<string, IndexLeader> EntityLeaders = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, IndexLeaderElection> EntityLeaderElections = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Dictionary<string, IndexHeartbeatMonitor> EntityHeartbeatMonitors = new(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> EntityLeadershipInitialized = new(StringComparer.OrdinalIgnoreCase);
    private static EntityLeadershipConfig? EntityLeadershipSettings;

    private sealed record EntityLeadershipConfig(
        string StorageKey,
        string NodeId,
        TimeSpan HeartbeatInterval,
        TimeSpan StaleThreshold,
        TimeSpan RetryInterval,
        IBufferedLogger? Logger);

    public static string BuildEntityLeaseKey(string storageKey, string entityName)
    {
        if (string.IsNullOrWhiteSpace(storageKey) || string.IsNullOrWhiteSpace(entityName))
            return string.Empty;

        return string.Concat(storageKey, ".", entityName);
    }

    public static bool IsEntityLeader(string storageKey, string entityName)
    {
        if (!EntityLeadershipEnabled)
            return true;

        var key = BuildEntityLeaseKey(storageKey, entityName);
        if (string.IsNullOrWhiteSpace(key))
            return false;

        lock (EntityLeaderSync)
        {
            return EntityLeaders.ContainsKey(key);
        }
    }

    public static void EnsureEntityLeader(string storageKey, string entityName)
    {
        if (!EntityLeadershipEnabled)
            return;

        if (PrimaryProvider == null)
            throw new InvalidOperationException("Entity leadership requested but no primary data provider is configured.");

        var settings = EntityLeadershipSettings ?? throw new InvalidOperationException("Entity leadership settings are not configured.");
        if (IsEntityLeader(storageKey, entityName))
            return;

        EnsureEntityLeadershipInitialized(storageKey, entityName, settings, PrimaryProvider);

        if (!IsEntityLeader(storageKey, entityName))
        {
            var leaseKey = BuildEntityLeaseKey(storageKey, entityName);
            var leader = IndexLeadership.TryAcquireLeader(PrimaryProvider, leaseKey, settings.NodeId, settings.HeartbeatInterval, settings.Logger);
            if (leader != null && !TrySetEntityLeader(storageKey, entityName, leader))
                leader.Dispose();
        }

        if (!IsEntityLeader(storageKey, entityName))
            throw new InvalidOperationException($"Entity leader not held for {entityName} (storage={storageKey}).");
    }

    public static bool TryGetEntityLeader(string storageKey, string entityName, out IndexLeader leader)
    {
        leader = null!;
        var key = BuildEntityLeaseKey(storageKey, entityName);
        if (string.IsNullOrWhiteSpace(key))
            return false;

        lock (EntityLeaderSync)
        {
            return EntityLeaders.TryGetValue(key, out leader!);
        }
    }

    public static void ConfigureEntityLeadership(string storageKey, string nodeId, TimeSpan heartbeatInterval, TimeSpan staleThreshold, TimeSpan retryInterval, IBufferedLogger? logger)
    {
        if (string.IsNullOrWhiteSpace(storageKey))
            throw new ArgumentException("Storage key cannot be empty.", nameof(storageKey));
        if (string.IsNullOrWhiteSpace(nodeId))
            throw new ArgumentException("Node id cannot be empty.", nameof(nodeId));
        if (heartbeatInterval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(heartbeatInterval), "Heartbeat interval must be positive.");
        if (staleThreshold <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(staleThreshold), "Stale threshold must be positive.");
        if (retryInterval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(retryInterval), "Retry interval must be positive.");

        EntityLeadershipEnabled = true;
        EntityLeadershipSettings = new EntityLeadershipConfig(storageKey, nodeId, heartbeatInterval, staleThreshold, retryInterval, logger);
    }

    private static void EnsureEntityLeadershipInitialized(string storageKey, string entityName, EntityLeadershipConfig settings, LocalFolderBinaryDataProvider provider)
    {
        var leaseKey = BuildEntityLeaseKey(storageKey, entityName);
        if (string.IsNullOrWhiteSpace(leaseKey))
            return;

        lock (EntityLeaderSync)
        {
            if (EntityLeadershipInitialized.Contains(leaseKey))
                return;

            EntityLeadershipInitialized.Add(leaseKey);
        }

        var monitor = IndexLeadership.StartHeartbeatMonitor(provider, leaseKey, settings.HeartbeatInterval, settings.StaleThreshold, settings.Logger);
        RegisterEntityHeartbeatMonitor(storageKey, entityName, monitor);

        var election = IndexLeadership.StartLeaderElectionLoop(
            provider,
            leaseKey,
            settings.NodeId,
            settings.HeartbeatInterval,
            settings.RetryInterval,
            isLeader: () => IsEntityLeader(storageKey, entityName),
            onLeaderAcquired: acquired =>
            {
                if (!TrySetEntityLeader(storageKey, entityName, acquired))
                    acquired.Dispose();
            },
            logger: settings.Logger);
        RegisterEntityLeaderElection(storageKey, entityName, election);
    }

    public static bool TrySetEntityLeader(string storageKey, string entityName, IndexLeader leader)
    {
        if (leader == null)
            throw new ArgumentNullException(nameof(leader));

        var key = BuildEntityLeaseKey(storageKey, entityName);
        if (string.IsNullOrWhiteSpace(key))
            return false;

        lock (EntityLeaderSync)
        {
            if (EntityLeaders.ContainsKey(key))
                return false;

            EntityLeaders[key] = leader;
            return true;
        }
    }

    public static void RegisterEntityLeaderElection(string storageKey, string entityName, IndexLeaderElection election)
    {
        if (election == null)
            throw new ArgumentNullException(nameof(election));

        var key = BuildEntityLeaseKey(storageKey, entityName);
        if (string.IsNullOrWhiteSpace(key))
            return;

        lock (EntityLeaderSync)
        {
            if (EntityLeaderElections.TryGetValue(key, out var existing))
                existing.Dispose();

            EntityLeaderElections[key] = election;
        }
    }

    public static void RegisterEntityHeartbeatMonitor(string storageKey, string entityName, IndexHeartbeatMonitor monitor)
    {
        if (monitor == null)
            throw new ArgumentNullException(nameof(monitor));

        var key = BuildEntityLeaseKey(storageKey, entityName);
        if (string.IsNullOrWhiteSpace(key))
            return;

        lock (EntityLeaderSync)
        {
            if (EntityHeartbeatMonitors.TryGetValue(key, out var existing))
                existing.Dispose();

            EntityHeartbeatMonitors[key] = monitor;
        }
    }
}
