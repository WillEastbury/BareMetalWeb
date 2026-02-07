using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Data;

namespace BareMetalWeb.Interfaces;

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
    ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject;
    ValueTask<T?> LoadAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject;
    ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject;
    ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject;
    ValueTask DeleteAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject;
    IDisposable AcquireIndexLock(string entityName, string fieldName);
    bool IndexFileExists(string entityName, string fieldName, IndexFileKind kind);
    Stream OpenIndexRead(string entityName, string fieldName, IndexFileKind kind);
    Stream OpenIndexAppend(string entityName, string fieldName, IndexFileKind kind);
    Stream OpenIndexWriteTemp(string entityName, string fieldName, IndexFileKind kind, out string tempToken);
    void CommitIndexTemp(string entityName, string fieldName, IndexFileKind kind, string tempToken);
    bool PagedFileExists(string entityName, string fileName);
    IPagedFile OpenPagedFile(string entityName, string fileName, int pageSize, FileAccess access);
    ValueTask DeletePagedFileAsync(string entityName, string fileName, CancellationToken cancellationToken = default);
}
