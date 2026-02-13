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
    ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject;
    ValueTask<T?> LoadAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject;
    ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject;
    ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject;
    ValueTask DeleteAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject;
}
