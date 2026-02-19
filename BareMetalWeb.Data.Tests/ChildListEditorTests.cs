using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for child list editor functionality in DataScaffold.
/// </summary>
public class ChildListEditorTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;

    public ChildListEditorTests()
    {
        _originalStore = DataStoreProvider.Current;
        DataStoreProvider.Current = new InMemoryDataStore();

        // Force UserClasses assembly to load before scanning
        _ = typeof(Customer).Assembly;
        DataEntityRegistry.RegisterAllEntities();
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
    }

    [Fact]
    public void BuildFormFields_WithChildListField_IncludesOnSubmitFalse()
    {
        // Arrange - Create an Order with child OrderRows
        var order = new Order
        {
            Id = "order-1",
            OrderNumber = "ORD-001",
            CustomerId = "cust-1",
            OrderDate = DateOnly.FromDateTime(DateTime.UtcNow),
            Status = "Open",
            CurrencyId = "USD",
            IsOpen = true
        };
        order.OrderRows.Add(new OrderRow
        {
            ProductId = "prod-1",
            Quantity = 2,
            UnitPrice = 10.50m
        });

        var meta = DataScaffold.GetEntityByType(typeof(Order));
        Assert.NotNull(meta);

        // Act - Build the form fields (which includes child list editor HTML)
        var formFields = DataScaffold.BuildFormFields(meta, order, forCreate: false);

        // Assert - Find the OrderRows field
        var orderRowsField = formFields.FirstOrDefault(f => f.Name == "OrderRows");
        Assert.NotNull(orderRowsField);
        
        // Verify the HTML includes onsubmit="return false;" for the child list editor
        Assert.Contains("onsubmit=\"return false;\"", orderRowsField.Html);
        
        // Additional verification: ensure it's in the modal form for OrderRows
        Assert.Contains("modal_OrderRows", orderRowsField.Html);
        Assert.Contains("form_OrderRows", orderRowsField.Html);
        
        // Verify the save button is present
        Assert.Contains("data-action=\"save\"", orderRowsField.Html);
        Assert.Contains("Save</button>", orderRowsField.Html);
    }

    [Fact]
    public void BuildFormFields_WithChildListLookupField_IncludesRefreshAndAddButtons()
    {
        // Arrange - Create an Order (OrderRow has a lookup field for Product)
        var order = new Order
        {
            Id = "order-1",
            OrderNumber = "ORD-001",
            CustomerId = "cust-1",
            OrderDate = DateOnly.FromDateTime(DateTime.UtcNow),
            Status = "Open",
            CurrencyId = "USD",
            IsOpen = true
        };

        var meta = DataScaffold.GetEntityByType(typeof(Order));
        Assert.NotNull(meta);

        // Act - Build the form fields (which includes child list editor HTML)
        var formFields = DataScaffold.BuildFormFields(meta, order, forCreate: false);

        // Assert - Find the OrderRows field
        var orderRowsField = formFields.FirstOrDefault(f => f.Name == "OrderRows");
        Assert.NotNull(orderRowsField);
        
        // Verify lookup buttons are rendered for ProductId field in the modal
        // The ProductId field should have refresh and add buttons
        Assert.Contains("data-lookup-refresh=\"modal_OrderRows_ProductId\"", orderRowsField.Html);
        Assert.Contains("data-lookup-add=\"products\"", orderRowsField.Html);
        Assert.Contains("data-lookup-field=\"modal_OrderRows_ProductId\"", orderRowsField.Html);
        
        // Verify the input-group wrapper is present
        Assert.Contains("input-group", orderRowsField.Html);
        
        // Verify button symbols
        Assert.Contains("↻</button>", orderRowsField.Html); // Refresh button
        Assert.Contains("+</button>", orderRowsField.Html); // Add button
        
        // Verify the select has the correct ID for the JavaScript to work
        Assert.Contains("id=\"modal_OrderRows_ProductId\"", orderRowsField.Html);
    }

    /// <summary>
    /// Minimal in-memory IDataObjectStore for testing.
    /// </summary>
    private class InMemoryDataStore : IDataObjectStore
    {
        private readonly Dictionary<(Type, string), BaseDataObject> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        public void Save<T>(T obj) where T : BaseDataObject
            => _store[(typeof(T), obj.Id)] = obj;

        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        { Save(obj); return ValueTask.CompletedTask; }

        public T? Load<T>(string id) where T : BaseDataObject
            => _store.TryGetValue((typeof(T), id), out var obj) ? obj as T : null;

        public ValueTask<T?> LoadAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Load<T>(id));

        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
            => _store.Values.OfType<T>();

        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Query<T>(query));

        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Query<T>(query).Count());

        public void Delete<T>(string id) where T : BaseDataObject
            => _store.Remove((typeof(T), id));

        public ValueTask DeleteAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
        { Delete<T>(id); return ValueTask.CompletedTask; }
    }
}
