using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
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

        if (provider is LocalFolderBinaryDataProvider && _fallbackProvider is null)
            _fallbackProvider = provider;
    }

    public void RegisterFallbackProvider(IDataProvider provider)
    {
        if (provider is null) throw new ArgumentNullException(nameof(provider));
        _fallbackProvider = provider;
    }

    public void ClearProviders() => _providersList.Clear();

    // Note: Synchronous methods block on async operations via GetAwaiter().GetResult().
    // This can block threads and may risk deadlocks in certain sync contexts.
    // Prefer using the async methods (SaveAsync, LoadAsync, etc.) when possible
    // to avoid blocking and achieve better performance and scalability.
    public void Save<T>(T obj) where T : BaseDataObject
    {
        SaveAsync(obj).AsTask().GetAwaiter().GetResult();
    }

    public async ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        if (obj is null) throw new ArgumentNullException(nameof(obj));
        var provider = ResolveProvider(typeof(T));
        await provider.SaveAsync(obj, cancellationToken).ConfigureAwait(false);
    }

    public T? Load<T>(string id) where T : BaseDataObject
    {
        return LoadAsync<T>(id).AsTask().GetAwaiter().GetResult();
    }

    public async ValueTask<T?> LoadAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        if (string.IsNullOrWhiteSpace(id)) throw new ArgumentException("Id cannot be null or whitespace.", nameof(id));
        var provider = ResolveProvider(typeof(T));
        return await provider.LoadAsync<T>(id, cancellationToken).ConfigureAwait(false);
    }

    public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
    {
        return QueryAsync<T>(query).AsTask().GetAwaiter().GetResult();
    }

    public async ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        var provider = ResolveProvider(typeof(T));
        return await provider.QueryAsync<T>(query, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        var provider = ResolveProvider(typeof(T));
        return await provider.CountAsync<T>(query, cancellationToken).ConfigureAwait(false);
    }

    public void Delete<T>(string id) where T : BaseDataObject
    {
        DeleteAsync<T>(id).AsTask().GetAwaiter().GetResult();
    }

    public async ValueTask DeleteAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        if (string.IsNullOrWhiteSpace(id)) throw new ArgumentException("Id cannot be null or whitespace.", nameof(id));
        var provider = ResolveProvider(typeof(T));
        await provider.DeleteAsync<T>(id, cancellationToken).ConfigureAwait(false);
    }

    private IDataProvider ResolveProvider(Type type)
    {
        var provider = _providersList.FirstOrDefault(p => p.CanHandle(type));
        if (provider is not null)
            return provider;

        if (_fallbackProvider is not null)
            return _fallbackProvider;

        throw new InvalidOperationException($"No IDataProvider registered for type {type.Name} and no fallback provider configured.");
    }
}
