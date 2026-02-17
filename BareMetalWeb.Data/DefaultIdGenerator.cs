using System;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Default implementation of IIdGenerator that supports GUID strings and sequential long integers.
/// Thread-safe for concurrent ID generation.
/// </summary>
public sealed class DefaultIdGenerator : IIdGenerator
{
    private static readonly ConcurrentDictionary<Type, StrongBox<long>> SequenceCounters = new();

    public string GenerateId(Type entityType, IdGenerationStrategy strategy)
    {
        return strategy switch
        {
            IdGenerationStrategy.GuidString => Guid.NewGuid().ToString("N"),
            IdGenerationStrategy.SequentialLong => GenerateSequentialLong(entityType).ToString(),
            _ => throw new ArgumentException($"Unsupported ID generation strategy: {strategy}", nameof(strategy))
        };
    }

    private static long GenerateSequentialLong(Type entityType)
    {
        // Get or create a counter box for this entity type
        var counterBox = SequenceCounters.GetOrAdd(entityType, _ => new StrongBox<long>(0));
        
        // Use Interlocked.Increment for thread-safe atomic increment
        return Interlocked.Increment(ref counterBox.Value);
    }
}
