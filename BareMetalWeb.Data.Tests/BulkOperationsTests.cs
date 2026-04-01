using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[Collection("SharedState")]
public class BulkOperationsTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;

    public BulkOperationsTests()
    {
        _originalStore = DataStoreProvider.Current;
        DataStoreProvider.Current = new InMemoryDataStore();
        
        _ = GalleryTestFixture.State;
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
    }

    [Fact]
    public void BuildListHeaders_WithBulkSelection_AddsCheckboxColumn()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("products", out var meta));

        // Act
        var headers = DataScaffold.BuildListHeaders(meta, includeActions: true, includeBulkSelection: true);

        // Assert
        Assert.True(headers.Count >= 3); // At least: Checkbox + Actions + some data columns
        Assert.Contains("checkbox", headers[0], StringComparison.OrdinalIgnoreCase);
        Assert.Equal("Actions", headers[1]);
    }

    [Fact]
    public void BuildListHeaders_WithoutBulkSelection_NoCheckboxColumn()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("products", out var meta));

        // Act without bulk selection
        var headersWithoutBulk = DataScaffold.BuildListHeaders(meta, includeActions: true, includeBulkSelection: false);
        
        // Act with bulk selection
        var headersWithBulk = DataScaffold.BuildListHeaders(meta, includeActions: true, includeBulkSelection: true);

        // Assert
        Assert.Equal("Actions", headersWithoutBulk[0]); // Without bulk, Actions is first
        Assert.Contains("checkbox", headersWithBulk[0], StringComparison.OrdinalIgnoreCase); // With bulk, checkbox is first
        Assert.Equal(headersWithoutBulk.Count + 1, headersWithBulk.Count); // One more column with bulk selection
    }

    private class InMemoryDataStore : IDataObjectStore
    {
        private readonly Dictionary<(Type, uint), BaseDataObject> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        public void Save<T>(T obj) where T : BaseDataObject
            => _store[(typeof(T), obj.Key)] = obj;

        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        { Save(obj); return ValueTask.CompletedTask; }

        public T? Load<T>(uint key) where T : BaseDataObject
            => _store.TryGetValue((typeof(T), key), out var obj) ? obj as T : null;

        public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Load<T>(key));

        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
            => _store.Values.OfType<T>();

        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Query<T>(query));

        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Query<T>(query).Count());

        public void Delete<T>(uint key) where T : BaseDataObject
            => _store.Remove((typeof(T), key));

        public ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
        { Delete<T>(key); return ValueTask.CompletedTask; }

        // ── Non-generic stubs (string + ordinal) ───────────────────────
        public void Save(string e, BaseDataObject o) => throw new NotSupportedException();
        public BaseDataObject? Load(string e, uint k) => throw new NotSupportedException();
        public IEnumerable<BaseDataObject> Query(string e, QueryDefinition? q = null) => throw new NotSupportedException();
        public void Delete(string e, uint k) => throw new NotSupportedException();
        public ValueTask SaveAsync(string e, BaseDataObject o, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask<BaseDataObject?> LoadAsync(string e, uint k, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask<IEnumerable<BaseDataObject>> QueryAsync(string e, QueryDefinition? q = null, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask<int> CountAsync(string e, QueryDefinition? q = null, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask DeleteAsync(string e, uint k, CancellationToken ct = default) => throw new NotSupportedException();
        public void Save(int o, BaseDataObject obj) => throw new NotSupportedException();
        public BaseDataObject? Load(int o, uint k) => throw new NotSupportedException();
        public IEnumerable<BaseDataObject> Query(int o, QueryDefinition? q = null) => throw new NotSupportedException();
        public void Delete(int o, uint k) => throw new NotSupportedException();
        public ValueTask SaveAsync(int o, BaseDataObject obj, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask<BaseDataObject?> LoadAsync(int o, uint k, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask<IEnumerable<BaseDataObject>> QueryAsync(int o, QueryDefinition? q = null, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask<int> CountAsync(int o, QueryDefinition? q = null, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask DeleteAsync(int o, uint k, CancellationToken ct = default) => throw new NotSupportedException();
    }
}
