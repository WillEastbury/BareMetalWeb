using System;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Default implementation of IIdGenerator that produces sequential uint32 keys.
/// Keys are persisted via <see cref="DataStoreProvider.PrimaryProvider"/> so they
/// survive application restarts without generating duplicates. An in-memory fallback
/// is used when no provider is configured (e.g. in unit tests).
/// Thread-safe for concurrent key generation.
/// </summary>
public sealed class DefaultIdGenerator : IIdGenerator
{
    // In-memory fallback counters used when no IDataProvider is available (e.g. unit tests).
    private static readonly ConcurrentDictionary<Type, StrongBox<uint>> SequenceCounters = new();

    public uint GenerateKey(Type entityType)
    {
        // Prefer the persistent provider so the counter survives application restarts.
        var provider = DataStoreProvider.PrimaryProvider;
        if (provider != null)
            return provider.NextSequentialKey(entityType.Name);

        // Fallback: in-memory counter (acceptable in tests; resets on restart).
        var counterBox = SequenceCounters.GetOrAdd(entityType, _ => new StrongBox<uint>(0));
        return Interlocked.Increment(ref counterBox.Value);
    }
}
