using System;
using System.Collections.Generic;
using System.Linq;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[Collection("DataStoreProvider")]
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

    [Fact]
    public void BuildListRows_WithBulkSelection_AddsCheckboxes()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("products", out var meta));

        var items = new List<BaseDataObject>();
        for (int i = 1; i <= 2; i++)
        {
            var p = meta.Handlers.Create();
            p.Key = (uint)i;
            meta.FindField("Name")!.SetValueFn(p, $"Item {i}");
            items.Add(p);
        }

        // Act
        var rows = DataScaffold.BuildListRows(
            meta,
            items,
            "/admin/data/products",
            includeActions: true,
            includeBulkSelection: true);

        // Assert
        Assert.Equal(2, rows.Count);
        
        // First row should have checkbox as first cell
        var firstRow = rows[0];
        Assert.Contains("data-row-checkbox", firstRow[0]);
        Assert.Contains("data-row-id=\"1\"", firstRow[0]);
        
        // Second row should have checkbox as first cell
        var secondRow = rows[1];
        Assert.Contains("data-row-checkbox", secondRow[0]);
        Assert.Contains("data-row-id=\"2\"", secondRow[0]);
    }

    [Fact]
    public void BuildListRows_WithoutBulkSelection_NoCheckboxes()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("products", out var meta));

        var items = new List<BaseDataObject>();
        var p = meta.Handlers.Create();
        p.Key = (uint)1;
        meta.FindField("Name")!.SetValueFn(p, "Item 1");
        items.Add(p);

        // Act
        var rows = DataScaffold.BuildListRows(
            meta,
            items,
            "/admin/data/products",
            includeActions: true,
            includeBulkSelection: false);

        // Assert
        Assert.Single(rows);
        
        // First cell should be actions, not checkbox
        var firstRow = rows[0];
        Assert.DoesNotContain("data-row-checkbox", firstRow[0]);
        Assert.Contains("btn", firstRow[0]); // Actions column
    }

    [Fact]
    public void BuildListRows_BothFlagsTrue_CheckboxBeforeActions()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("products", out var meta));

        var items = new List<BaseDataObject>();
        var p = meta.Handlers.Create();
        p.Key = (uint)1;
        meta.FindField("Name")!.SetValueFn(p, "Item 1");
        items.Add(p);

        // Act
        var rows = DataScaffold.BuildListRows(
            meta,
            items,
            "/admin/data/products",
            includeActions: true,
            includeBulkSelection: true);

        // Assert
        Assert.Single(rows);
        var row = rows[0];
        
        // First cell should be checkbox
        Assert.Contains("data-row-checkbox", row[0]);
        
        // Second cell should be actions
        Assert.Contains("btn", row[1]);
        Assert.DoesNotContain("data-row-checkbox", row[1]);
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
    }
}
