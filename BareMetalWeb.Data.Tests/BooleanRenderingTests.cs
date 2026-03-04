using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for rendering boolean values as checkboxes in list and view contexts.
/// </summary>
[Collection("SharedState")]
public class BooleanRenderingTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;

    public BooleanRenderingTests()
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
    public void BuildViewRowsHtml_WithBooleanTrue_RendersGreenCheckbox()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));

        var customer = meta.Handlers.Create();
        customer.Key = 1;
        meta.FindField("Name")!.SetValueFn(customer, "Test Customer");
        meta.FindField("Email")!.SetValueFn(customer, "test@example.com");
        meta.FindField("IsActive")!.SetValueFn(customer, true);

        // Act
        var rows = DataScaffold.BuildViewRowsHtml(meta, customer);

        // Assert
        var activeRow = rows.FirstOrDefault(r => r.Label == "Active");
        Assert.True(activeRow.IsHtml, "IsActive field should be rendered as HTML");
        Assert.Contains("bi-check-square-fill", activeRow.Value);
        Assert.Contains("text-success", activeRow.Value);
        Assert.Contains("title=\"True\"", activeRow.Value);
    }

    [Fact]
    public void BuildViewRowsHtml_WithBooleanFalse_RendersRedCheckbox()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));

        var customer = meta.Handlers.Create();
        customer.Key = 2;
        meta.FindField("Name")!.SetValueFn(customer, "Inactive Customer");
        meta.FindField("Email")!.SetValueFn(customer, "inactive@example.com");
        meta.FindField("IsActive")!.SetValueFn(customer, false);

        // Act
        var rows = DataScaffold.BuildViewRowsHtml(meta, customer);

        // Assert
        var activeRow = rows.FirstOrDefault(r => r.Label == "Active");
        Assert.True(activeRow.IsHtml, "IsActive field should be rendered as HTML");
        Assert.Contains("bi-square", activeRow.Value);
        Assert.Contains("text-danger", activeRow.Value);
        Assert.Contains("title=\"False\"", activeRow.Value);
    }

    [Fact]
    public void BuildListRows_WithBooleanTrue_RendersGreenCheckbox()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("products", out var meta));

        var product = meta.Handlers.Create();
        product.Key = 1;
        meta.FindField("Name")!.SetValueFn(product, "Active Product");
        meta.FindField("Sku")!.SetValueFn(product, "SKU-001");
        meta.FindField("IsActive")!.SetValueFn(product, true);
        meta.FindField("UnitOfMeasureId")!.SetValueFn(product, "uom-1");
        meta.FindField("CurrencyId")!.SetValueFn(product, "cur-1");
        var products = new[] { product };


        // Act
        var rows = DataScaffold.BuildListRows(meta, products, "/admin/data/products", includeActions: false);

        // Assert
        Assert.Single(rows);
        var row = rows[0];
        
        // Find the IsActive column
        var isActiveField = meta.Fields.FirstOrDefault(f => f.Name == "IsActive" && f.List);
        if (isActiveField != null)
        {
            var fieldIndex = meta.Fields.Where(f => f.List).OrderBy(f => f.Order).ToList().IndexOf(isActiveField);
            var cellValue = row[fieldIndex];
            Assert.Contains("bi-check-square-fill", cellValue);
            Assert.Contains("text-success", cellValue);
        }
    }

    [Fact]
    public void BuildListRows_WithBooleanFalse_RendersRedCheckbox()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("products", out var meta));

        var product = meta.Handlers.Create();
        product.Key = 2;
        meta.FindField("Name")!.SetValueFn(product, "Inactive Product");
        meta.FindField("Sku")!.SetValueFn(product, "SKU-002");
        meta.FindField("IsActive")!.SetValueFn(product, false);
        meta.FindField("UnitOfMeasureId")!.SetValueFn(product, "uom-1");
        meta.FindField("CurrencyId")!.SetValueFn(product, "cur-1");
        var products = new[] { product };


        // Act
        var rows = DataScaffold.BuildListRows(meta, products, "/admin/data/products", includeActions: false);

        // Assert
        Assert.Single(rows);
        var row = rows[0];
        
        // Find the IsActive column
        var isActiveField = meta.Fields.FirstOrDefault(f => f.Name == "IsActive" && f.List);
        if (isActiveField != null)
        {
            var fieldIndex = meta.Fields.Where(f => f.List).OrderBy(f => f.Order).ToList().IndexOf(isActiveField);
            var cellValue = row[fieldIndex];
            Assert.Contains("bi-square", cellValue);
            Assert.Contains("text-danger", cellValue);
        }
    }

    [Fact]
    public void BuildListRows_WithMixedBooleans_RendersAppropriateCheckboxes()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));

        var customer1 = meta.Handlers.Create();
        customer1.Key = 1;
        meta.FindField("Name")!.SetValueFn(customer1, "Active");
        meta.FindField("Email")!.SetValueFn(customer1, "a@test.com");
        meta.FindField("IsActive")!.SetValueFn(customer1, true);

        var customer2 = meta.Handlers.Create();
        customer2.Key = 2;
        meta.FindField("Name")!.SetValueFn(customer2, "Inactive");
        meta.FindField("Email")!.SetValueFn(customer2, "b@test.com");
        meta.FindField("IsActive")!.SetValueFn(customer2, false);

        var customers = new[] { customer1, customer2 };


        // Act
        var rows = DataScaffold.BuildListRows(meta, customers, "/admin/data/customers", includeActions: false);

        // Assert
        Assert.Equal(2, rows.Count);
        
        var isActiveField = meta.Fields.FirstOrDefault(f => f.Name == "IsActive" && f.List);
        if (isActiveField != null)
        {
            var fieldIndex = meta.Fields.Where(f => f.List).OrderBy(f => f.Order).ToList().IndexOf(isActiveField);
            
            // First row should have green checkbox
            Assert.Contains("bi-check-square-fill", rows[0][fieldIndex]);
            Assert.Contains("text-success", rows[0][fieldIndex]);
            
            // Second row should have red checkbox
            Assert.Contains("bi-square", rows[1][fieldIndex]);
            Assert.Contains("text-danger", rows[1][fieldIndex]);
        }
    }

    /// <summary>
    /// Minimal in-memory IDataObjectStore for testing.
    /// </summary>
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
