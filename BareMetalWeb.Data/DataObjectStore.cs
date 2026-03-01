using System;
using System.Collections.Concurrent;
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
    private readonly ConcurrentDictionary<Type, IDataProvider> _providerCache = new();

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

        _providerCache.Clear();
    }

    public void RegisterFallbackProvider(IDataProvider provider)
    {
        if (provider is null) throw new ArgumentNullException(nameof(provider));
        _fallbackProvider = provider;
        _providerCache.Clear();
    }

    public void ClearProviders() { _providersList.Clear(); _providerCache.Clear(); }

    public void Save<T>(T obj) where T : BaseDataObject
    {
        if (obj is null) throw new ArgumentNullException(nameof(obj));
        var provider = ResolveProvider(typeof(T));
        if (obj.Key == 0)
            obj.Key = provider.NextSequentialKey(typeof(T).Name);
        provider.Save(obj);
    }

    public async ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        if (obj is null) throw new ArgumentNullException(nameof(obj));
        var provider = ResolveProvider(typeof(T));
        if (obj.Key == 0)
            obj.Key = provider.NextSequentialKey(typeof(T).Name);
        await provider.SaveAsync(obj, cancellationToken).ConfigureAwait(false);
    }

    public T? Load<T>(uint key) where T : BaseDataObject
    {
        if (key == 0) throw new ArgumentException("Key cannot be zero.", nameof(key));
        var provider = ResolveProvider(typeof(T));
        return provider.Load<T>(key);
    }

    public async ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        if (key == 0) throw new ArgumentException("Key cannot be zero.", nameof(key));
        var provider = ResolveProvider(typeof(T));
        return await provider.LoadAsync<T>(key, cancellationToken).ConfigureAwait(false);
    }

    public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
    {
        var provider = ResolveProvider(typeof(T));
        return provider.Query<T>(query);
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

    public void Delete<T>(uint key) where T : BaseDataObject
    {
        if (key == 0) throw new ArgumentException("Key cannot be zero.", nameof(key));
        var provider = ResolveProvider(typeof(T));
        provider.Delete<T>(key);
    }

    public async ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        if (key == 0) throw new ArgumentException("Key cannot be zero.", nameof(key));
        var provider = ResolveProvider(typeof(T));
        await provider.DeleteAsync<T>(key, cancellationToken).ConfigureAwait(false);
    }

    private IDataProvider ResolveProvider(Type type)
    {
        return _providerCache.GetOrAdd(type, t =>
        {
            var provider = _providersList.FirstOrDefault(p => p.CanHandle(t));
            if (provider is not null)
                return provider;

            if (_fallbackProvider is not null)
                return _fallbackProvider;

            throw new InvalidOperationException($"No IDataProvider registered for type {t.Name} and no fallback provider configured.");
        });
    }
}
