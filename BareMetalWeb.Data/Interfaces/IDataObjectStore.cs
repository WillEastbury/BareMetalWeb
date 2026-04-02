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
    void Save(string entityTypeName, DataRecord obj);
    DataRecord? Load(string entityTypeName, uint key);
    IEnumerable<DataRecord> Query(string entityTypeName, QueryDefinition? query = null);
    void Delete(string entityTypeName, uint key);
    ValueTask SaveAsync(string entityTypeName, DataRecord obj, CancellationToken cancellationToken = default);
    ValueTask<DataRecord?> LoadAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default);
    ValueTask<IEnumerable<DataRecord>> QueryAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default);
    ValueTask<int> CountAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default);
    ValueTask DeleteAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default);

    // ── Ordinal-based overloads (hot path — no dictionary lookup) ────────
    void Save(int entityOrdinal, DataRecord obj);
    DataRecord? Load(int entityOrdinal, uint key);
    IEnumerable<DataRecord> Query(int entityOrdinal, QueryDefinition? query = null);
    void Delete(int entityOrdinal, uint key);
    ValueTask SaveAsync(int entityOrdinal, DataRecord obj, CancellationToken cancellationToken = default);
    ValueTask<DataRecord?> LoadAsync(int entityOrdinal, uint key, CancellationToken cancellationToken = default);
    ValueTask<IEnumerable<DataRecord>> QueryAsync(int entityOrdinal, QueryDefinition? query = null, CancellationToken cancellationToken = default);
    ValueTask<int> CountAsync(int entityOrdinal, QueryDefinition? query = null, CancellationToken cancellationToken = default);
    ValueTask DeleteAsync(int entityOrdinal, uint key, CancellationToken cancellationToken = default);
}
