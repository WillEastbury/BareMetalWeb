using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;

namespace BareMetalWeb.Data.Interfaces;

public interface IDataObjectStore
{
    IReadOnlyList<IDataProvider> Providers { get; }
    void RegisterProvider(IDataProvider provider, bool prepend = false);
    void RegisterFallbackProvider(IDataProvider provider);
    void ClearProviders();
    void Save<T>(T obj) where T : BaseDataObject;
    T? Load<T>(uint key) where T : BaseDataObject;
    IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject;
    void Delete<T>(uint key) where T : BaseDataObject;
    ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject;
    ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject;
    ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject;
    ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject;
    ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject;
}
