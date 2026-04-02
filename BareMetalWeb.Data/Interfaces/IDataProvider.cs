using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.Interfaces;

public enum IndexFileKind
{
    Log,
    Snapshot
}

public interface IDataProvider
{
    string Name { get; }
    string IndexRootPath { get; }
    string IndexFolderName { get; }
    string IndexLogExtension { get; }
    string IndexSnapshotExtension { get; }
    string IndexTempExtension { get; }

    // ── Entity-name-based CRUD (canonical API) ──────────────────────────
    void Save(string entityTypeName, DataRecord obj);
    ValueTask SaveAsync(string entityTypeName, DataRecord obj, CancellationToken cancellationToken = default);
    DataRecord? Load(string entityTypeName, uint key);
    ValueTask<DataRecord?> LoadAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default);
    IEnumerable<DataRecord> Query(string entityTypeName, QueryDefinition? query = null);
    ValueTask<IEnumerable<DataRecord>> QueryAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default);
    int Count(string entityTypeName, QueryDefinition? query = null);
    ValueTask<int> CountAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default);
    void Delete(string entityTypeName, uint key);
    ValueTask DeleteAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default);

    IDisposable AcquireIndexLock(string entityName, string fieldName);
    bool IndexFileExists(string entityName, string fieldName, IndexFileKind kind);
    Stream OpenIndexRead(string entityName, string fieldName, IndexFileKind kind);
    Stream OpenIndexAppend(string entityName, string fieldName, IndexFileKind kind);
    Stream OpenIndexWriteTemp(string entityName, string fieldName, IndexFileKind kind, out string tempToken);
    void CommitIndexTemp(string entityName, string fieldName, IndexFileKind kind, string tempToken);
    bool PagedFileExists(string entityName, string fileName);
    IPagedFile OpenPagedFile(string entityName, string fileName, int pageSize, FileAccess access);
    ValueTask DeletePagedFileAsync(string entityName, string fileName, CancellationToken cancellationToken = default);
    void RenamePagedFile(string entityName, string oldFileName, string newFileName);

    /// <summary>
    /// Atomically increments and returns the next sequential uint32 key for the given entity.
    /// The value is persisted so it survives application restarts.
    /// </summary>
    uint NextSequentialKey(string entityName);

    /// <summary>
    /// Sets the sequential counter for the given entity to at least <paramref name="floor"/>
    /// if the current stored value is lower. Used to seed the counter from existing data
    /// on first use after an upgrade or initial deployment.
    /// </summary>
    void SeedSequentialKey(string entityName, uint floor);

    /// <summary>
    /// Permanently removes all stored records, index files, schema files, and any other
    /// on-disk artefacts managed by this provider, then reinitialises the provider so it
    /// is ready for new writes immediately after this call returns.
    /// </summary>
    ValueTask WipeStorageAsync(CancellationToken cancellationToken = default)
        => ValueTask.CompletedTask;
}
