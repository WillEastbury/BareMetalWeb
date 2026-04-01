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

    // ── String-based CRUD (canonical API) ────────────────────────────────
    void Save(string entityTypeName, BaseDataObject obj);
    BaseDataObject? Load(string entityTypeName, uint key);
    IEnumerable<BaseDataObject> Query(string entityTypeName, QueryDefinition? query = null);
    void Delete(string entityTypeName, uint key);
    ValueTask SaveAsync(string entityTypeName, BaseDataObject obj, CancellationToken cancellationToken = default);
    ValueTask<BaseDataObject?> LoadAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default);
    ValueTask<IEnumerable<BaseDataObject>> QueryAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default);
    ValueTask<int> CountAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default);
    ValueTask DeleteAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default);

    // ── Ordinal-based overloads (hot path — no dictionary lookup) ────────
    void Save(int entityOrdinal, BaseDataObject obj);
    BaseDataObject? Load(int entityOrdinal, uint key);
    IEnumerable<BaseDataObject> Query(int entityOrdinal, QueryDefinition? query = null);
    void Delete(int entityOrdinal, uint key);
    ValueTask SaveAsync(int entityOrdinal, BaseDataObject obj, CancellationToken cancellationToken = default);
    ValueTask<BaseDataObject?> LoadAsync(int entityOrdinal, uint key, CancellationToken cancellationToken = default);
    ValueTask<IEnumerable<BaseDataObject>> QueryAsync(int entityOrdinal, QueryDefinition? query = null, CancellationToken cancellationToken = default);
    ValueTask<int> CountAsync(int entityOrdinal, QueryDefinition? query = null, CancellationToken cancellationToken = default);
    ValueTask DeleteAsync(int entityOrdinal, uint key, CancellationToken cancellationToken = default);
}
