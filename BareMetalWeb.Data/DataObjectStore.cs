using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

public sealed class DataObjectStore : IDataObjectStore
{
    private readonly List<IDataProvider> _providersList = new();
    private IDataProvider? _fallbackProvider;

    public IReadOnlyList<IDataProvider> Providers => _providersList;

    public void RegisterProvider(IDataProvider provider, bool prepend = false)
    {
        if (provider is null) throw new ArgumentNullException(nameof(provider));
        if (prepend)
            _providersList.Insert(0, provider);
        else
            _providersList.Add(provider);
    }

    public void RegisterFallbackProvider(IDataProvider provider)
    {
        if (provider is null) throw new ArgumentNullException(nameof(provider));
        _fallbackProvider = provider;
    }

    public void ClearProviders() { _providersList.Clear(); }

    // ── Ordinal-based overloads (hot path) ──────────────────────────────

    private EntitySchema ResolveSchema(int entityOrdinal)
    {
        var meta = DataScaffold.GetEntityByOrdinal(entityOrdinal)
            ?? throw new InvalidOperationException($"No entity registered at ordinal {entityOrdinal}.");
        return meta.Schema
            ?? throw new InvalidOperationException($"Entity '{meta.Name}' (ordinal {entityOrdinal}) has no schema.");
    }

    private EntitySchema ResolveSchema(string entityTypeName)
    {
        var ordinal = DataScaffold.GetEntityOrdinal(entityTypeName);
        if (ordinal < 0)
            throw new InvalidOperationException($"No entity registered with name '{entityTypeName}'.");
        return ResolveSchema(ordinal);
    }

    public void Save(int entityOrdinal, DataRecord obj)
    {
        if (obj is null) throw new ArgumentNullException(nameof(obj));
        var schema = ResolveSchema(entityOrdinal);
        var provider = ResolveProviderByName(schema.EntityName);
        if (obj.Key == 0)
            obj.Key = provider.NextSequentialKey(schema.EntityName);
        provider.Save(schema.EntityName, obj);
    }

    public DataRecord? Load(int entityOrdinal, uint key)
    {
        if (key == 0) throw new ArgumentException("Key cannot be zero.", nameof(key));
        var schema = ResolveSchema(entityOrdinal);
        return ResolveProviderByName(schema.EntityName).Load(schema.EntityName, key);
    }

    public IEnumerable<DataRecord> Query(int entityOrdinal, QueryDefinition? query = null)
    {
        var schema = ResolveSchema(entityOrdinal);
        return ResolveProviderByName(schema.EntityName).Query(schema.EntityName, query);
    }

    public void Delete(int entityOrdinal, uint key)
    {
        if (key == 0) throw new ArgumentException("Key cannot be zero.", nameof(key));
        var schema = ResolveSchema(entityOrdinal);
        ResolveProviderByName(schema.EntityName).Delete(schema.EntityName, key);
    }

    public ValueTask SaveAsync(int entityOrdinal, DataRecord obj, CancellationToken cancellationToken = default)
    { Save(entityOrdinal, obj); return ValueTask.CompletedTask; }

    public ValueTask<DataRecord?> LoadAsync(int entityOrdinal, uint key, CancellationToken cancellationToken = default)
        => new(Load(entityOrdinal, key));

    public ValueTask<IEnumerable<DataRecord>> QueryAsync(int entityOrdinal, QueryDefinition? query = null, CancellationToken cancellationToken = default)
        => new(Query(entityOrdinal, query));

    public ValueTask<int> CountAsync(int entityOrdinal, QueryDefinition? query = null, CancellationToken cancellationToken = default)
    {
        var schema = ResolveSchema(entityOrdinal);
        return ResolveProviderByName(schema.EntityName).CountAsync(schema.EntityName, query, cancellationToken);
    }

    public ValueTask DeleteAsync(int entityOrdinal, uint key, CancellationToken cancellationToken = default)
    { Delete(entityOrdinal, key); return ValueTask.CompletedTask; }

    // ── String-based overloads (resolve name → ordinal → hot path) ──────

    public void Save(string entityTypeName, DataRecord obj)
    {
        if (obj is null) throw new ArgumentNullException(nameof(obj));
        var provider = ResolveProviderByName(entityTypeName);
        if (obj.Key == 0)
            obj.Key = provider.NextSequentialKey(entityTypeName);
        provider.Save(entityTypeName, obj);
    }

    public DataRecord? Load(string entityTypeName, uint key)
    {
        if (key == 0) throw new ArgumentException("Key cannot be zero.", nameof(key));
        return ResolveProviderByName(entityTypeName).Load(entityTypeName, key);
    }

    public IEnumerable<DataRecord> Query(string entityTypeName, QueryDefinition? query = null)
        => ResolveProviderByName(entityTypeName).Query(entityTypeName, query);

    public void Delete(string entityTypeName, uint key)
    {
        if (key == 0) throw new ArgumentException("Key cannot be zero.", nameof(key));
        ResolveProviderByName(entityTypeName).Delete(entityTypeName, key);
    }

    public ValueTask SaveAsync(string entityTypeName, DataRecord obj, CancellationToken cancellationToken = default)
    { Save(entityTypeName, obj); return ValueTask.CompletedTask; }

    public ValueTask<DataRecord?> LoadAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default)
        => new(Load(entityTypeName, key));

    public ValueTask<IEnumerable<DataRecord>> QueryAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default)
        => new(Query(entityTypeName, query));

    public ValueTask<int> CountAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default)
        => ResolveProviderByName(entityTypeName).CountAsync(entityTypeName, query, cancellationToken);

    public ValueTask DeleteAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default)
    { Delete(entityTypeName, key); return ValueTask.CompletedTask; }

    private IDataProvider ResolveProviderByName(string entityTypeName)
    {
        if (_providersList.Count > 0)
            return _providersList[0];
        if (_fallbackProvider is not null)
            return _fallbackProvider;
        throw new InvalidOperationException(
            $"No IDataProvider registered and no fallback provider configured (entity: {entityTypeName}).");
    }
}
