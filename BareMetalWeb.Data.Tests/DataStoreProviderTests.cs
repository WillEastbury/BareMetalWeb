using System;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class DataStoreProviderTests
{
    [Fact]
    public void Current_DefaultValue_IsDataObjectStore()
    {
        // Arrange & Act
        var current = DataStoreProvider.Current;

        // Assert
        Assert.NotNull(current);
        Assert.IsType<DataObjectStore>(current);
    }

    [Fact]
    public void Current_CanBeReplaced_WithCustomStore()
    {
        // Arrange
        var originalStore = DataStoreProvider.Current;
        var customStore = new DataObjectStore();

        try
        {
            // Act
            DataStoreProvider.Current = customStore;

            // Assert
            Assert.Same(customStore, DataStoreProvider.Current);
        }
        finally
        {
            // Cleanup
            DataStoreProvider.Current = originalStore;
        }
    }

    [Fact]
    public void PrimaryProvider_DefaultValue_IsNull()
    {
        // Arrange
        var originalProvider = DataStoreProvider.PrimaryProvider;

        try
        {
            // Act
            DataStoreProvider.PrimaryProvider = null;
            var primaryProvider = DataStoreProvider.PrimaryProvider;

            // Assert
            Assert.Null(primaryProvider);
        }
        finally
        {
            // Cleanup
            DataStoreProvider.PrimaryProvider = originalProvider;
        }
    }

    [Fact]
    public void PrimaryProvider_CanBeSet_WithCustomProvider()
    {
        // Arrange
        var originalProvider = DataStoreProvider.PrimaryProvider;
        var customProvider = new TestDataProvider();

        try
        {
            // Act
            DataStoreProvider.PrimaryProvider = customProvider;

            // Assert
            Assert.Same(customProvider, DataStoreProvider.PrimaryProvider);
        }
        finally
        {
            // Cleanup
            DataStoreProvider.PrimaryProvider = originalProvider;
        }
    }

    [Fact]
    public void Current_AndPrimaryProvider_AreIndependent()
    {
        // Arrange
        var originalStore = DataStoreProvider.Current;
        var originalProvider = DataStoreProvider.PrimaryProvider;
        var customStore = new DataObjectStore();
        var customProvider = new TestDataProvider();

        try
        {
            // Act
            DataStoreProvider.Current = customStore;
            DataStoreProvider.PrimaryProvider = customProvider;

            // Assert
            Assert.Same(customStore, DataStoreProvider.Current);
            Assert.Same(customProvider, DataStoreProvider.PrimaryProvider);
            Assert.NotSame((object)DataStoreProvider.Current, DataStoreProvider.PrimaryProvider);
        }
        finally
        {
            // Cleanup
            DataStoreProvider.Current = originalStore;
            DataStoreProvider.PrimaryProvider = originalProvider;
        }
    }

    private class TestDataProvider : IDataProvider
    {
        public string Name => "Test";
        public string IndexRootPath => string.Empty;
        public string IndexFolderName => string.Empty;
        public string IndexLogExtension => string.Empty;
        public string IndexSnapshotExtension => string.Empty;
        public string IndexTempExtension => string.Empty;
        public bool CanHandle(Type type) => true;
        public void Save<T>(T obj) where T : BaseDataObject { }
        public System.Threading.Tasks.ValueTask SaveAsync<T>(T obj, System.Threading.CancellationToken cancellationToken = default) where T : BaseDataObject => System.Threading.Tasks.ValueTask.CompletedTask;
        public T? Load<T>(string id) where T : BaseDataObject => null;
        public System.Threading.Tasks.ValueTask<T?> LoadAsync<T>(string id, System.Threading.CancellationToken cancellationToken = default) where T : BaseDataObject => System.Threading.Tasks.ValueTask.FromResult<T?>(null);
        public System.Collections.Generic.IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject => Array.Empty<T>();
        public System.Threading.Tasks.ValueTask<System.Collections.Generic.IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, System.Threading.CancellationToken cancellationToken = default) where T : BaseDataObject => System.Threading.Tasks.ValueTask.FromResult<System.Collections.Generic.IEnumerable<T>>(Array.Empty<T>());
        public int Count<T>(QueryDefinition? query = null) where T : BaseDataObject => 0;
        public System.Threading.Tasks.ValueTask<int> CountAsync<T>(QueryDefinition? query = null, System.Threading.CancellationToken cancellationToken = default) where T : BaseDataObject => System.Threading.Tasks.ValueTask.FromResult(0);
        public void Delete<T>(string id) where T : BaseDataObject { }
        public System.Threading.Tasks.ValueTask DeleteAsync<T>(string id, System.Threading.CancellationToken cancellationToken = default) where T : BaseDataObject => System.Threading.Tasks.ValueTask.CompletedTask;
        public IDisposable AcquireIndexLock(string entityName, string fieldName) => new DummyDisposable();
        public bool IndexFileExists(string entityName, string fieldName, IndexFileKind kind) => false;
        public System.IO.Stream OpenIndexRead(string entityName, string fieldName, IndexFileKind kind) => throw new NotImplementedException();
        public System.IO.Stream OpenIndexAppend(string entityName, string fieldName, IndexFileKind kind) => throw new NotImplementedException();
        public System.IO.Stream OpenIndexWriteTemp(string entityName, string fieldName, IndexFileKind kind, out string tempToken) => throw new NotImplementedException();
        public void CommitIndexTemp(string entityName, string fieldName, IndexFileKind kind, string tempToken) => throw new NotImplementedException();
        public bool PagedFileExists(string entityName, string fileName) => false;
        public BareMetalWeb.Core.Interfaces.IPagedFile OpenPagedFile(string entityName, string fileName, int pageSize, System.IO.FileAccess access) => throw new NotImplementedException();
        public System.Threading.Tasks.ValueTask DeletePagedFileAsync(string entityName, string fileName, System.Threading.CancellationToken cancellationToken = default) => throw new NotImplementedException();

        private class DummyDisposable : IDisposable
        {
            public void Dispose() { }
        }
    }
}
