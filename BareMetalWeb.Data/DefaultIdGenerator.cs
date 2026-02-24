using System;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Default implementation of IIdGenerator that supports GUID strings and sequential long integers.
/// Sequential long IDs are persisted via <see cref="DataStoreProvider.PrimaryProvider"/> so they
/// survive application restarts without generating duplicates.  An in-memory fallback is used when
/// no provider is configured (e.g. in unit tests).
/// Thread-safe for concurrent ID generation.
/// </summary>
public sealed class DefaultIdGenerator : IIdGenerator
{
    // In-memory fallback counters used when no IDataProvider is available (e.g. unit tests).
    private static readonly ConcurrentDictionary<Type, StrongBox<long>> SequenceCounters = new();

    public string GenerateId(Type entityType, IdGenerationStrategy strategy)
    {
        return strategy switch
        {
            IdGenerationStrategy.GuidString => Guid.NewGuid().ToString("N"),
            IdGenerationStrategy.SequentialLong => GenerateSequentialLong(entityType),
            _ => throw new ArgumentException($"Unsupported ID generation strategy: {strategy}", nameof(strategy))
        };
    }

    private static string GenerateSequentialLong(Type entityType)
    {
        // Prefer the persistent provider so the counter survives application restarts.
        var provider = DataStoreProvider.PrimaryProvider;
        if (provider != null)
            return provider.NextSequentialId(entityType.Name);

        // Fallback: in-memory counter (acceptable in tests; resets on restart).
        var counterBox = SequenceCounters.GetOrAdd(entityType, _ => new StrongBox<long>(0));
        return Interlocked.Increment(ref counterBox.Value).ToString();
    }
}
