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
    bool CanHandle(Type type);
    void Save<T>(T obj) where T : BaseDataObject;
    ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject;
    T? Load<T>(uint key) where T : BaseDataObject;
    ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject;
    IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject;
    ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject;
    int Count<T>(QueryDefinition? query = null) where T : BaseDataObject;
    ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject;
    void Delete<T>(uint key) where T : BaseDataObject;
    ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject;
    IDisposable AcquireIndexLock(string entityName, string fieldName);
    bool IndexFileExists(string entityName, string fieldName, IndexFileKind kind);
    Stream OpenIndexRead(string entityName, string fieldName, IndexFileKind kind);
    Stream OpenIndexAppend(string entityName, string fieldName, IndexFileKind kind);
    Stream OpenIndexWriteTemp(string entityName, string fieldName, IndexFileKind kind, out string tempToken);
    void CommitIndexTemp(string entityName, string fieldName, IndexFileKind kind, string tempToken);
    bool PagedFileExists(string entityName, string fileName);
    IPagedFile OpenPagedFile(string entityName, string fileName, int pageSize, FileAccess access);
    ValueTask DeletePagedFileAsync(string entityName, string fileName, CancellationToken cancellationToken = default);

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
}
