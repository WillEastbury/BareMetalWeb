using System.Collections;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests that BuildFormFields works for entities with [DataLookup] attributes.
/// Regression test for the create-route 500 bug caused by QueryByType attempting
/// an invalid cast from ValueTask&lt;IEnumerable&lt;T&gt;&gt; to ValueTask&lt;IEnumerable&gt;.
/// </summary>
public class DataScaffoldLookupTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;

    public DataScaffoldLookupTests()
    {
        _originalStore = DataStoreProvider.Current;
        DataStoreProvider.Current = new InMemoryDataStore();

        // Ensure lookup target entities are registered
        DataEntityRegistry.RegisterAllEntities();
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
    }

    [Fact]
    public void BuildFormFields_ForCreate_WithLookupFields_DoesNotThrow()
    {
        // Product has [DataLookup] on UnitOfMeasureId and CurrencyId
        var meta = DataScaffold.GetEntityByType(typeof(Product));
        Assert.NotNull(meta);

        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);
        Assert.NotNull(fields);
        Assert.True(fields.Count > 0, "Expected at least one form field for Product create");
    }

    [Fact]
    public void BuildFormFields_ForCreate_WithLookupFields_ReturnsLookupListType()
    {
        var meta = DataScaffold.GetEntityByType(typeof(Product));
        Assert.NotNull(meta);

        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);

        // UnitOfMeasureId and CurrencyId should be LookupList fields
        var uomField = fields.FirstOrDefault(f => f.Name == "UnitOfMeasureId");
        Assert.NotNull(uomField);
        Assert.Equal(Rendering.Models.FormFieldType.LookupList, uomField.FieldType);

        var currencyField = fields.FirstOrDefault(f => f.Name == "CurrencyId");
        Assert.NotNull(currencyField);
        Assert.Equal(Rendering.Models.FormFieldType.LookupList, currencyField.FieldType);
    }

    [Fact]
    public void BuildFormFields_ForCreate_WithLookupFields_PopulatesLookupOptions()
    {
        // Seed some lookup data
        var uom = new UnitOfMeasure { Id = "uom-1", Name = "Each" };
        DataStoreProvider.Current.Save(uom);

        var currency = new Currency { Id = "cur-1" };
        // Set IsoCode via reflection (it's a property)
        typeof(Currency).GetProperty("IsoCode")?.SetValue(currency, "USD");

        DataStoreProvider.Current.Save(currency);

        // Clear lookup cache to force re-query
        ClearLookupCache();

        var meta = DataScaffold.GetEntityByType(typeof(Product));
        Assert.NotNull(meta);

        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);

        var uomField = fields.FirstOrDefault(f => f.Name == "UnitOfMeasureId");
        Assert.NotNull(uomField);
        Assert.NotNull(uomField.LookupOptions);
        Assert.Contains(uomField.LookupOptions, o => o.Key == "uom-1" && o.Value == "Each");
    }

    [Fact]
    public void BuildFormFields_ForCreate_Order_WithCustomerLookup_DoesNotThrow()
    {
        // Order has [DataLookup] on CustomerId and CurrencyId
        var meta = DataScaffold.GetEntityByType(typeof(Order));
        Assert.NotNull(meta);

        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);
        Assert.NotNull(fields);
        Assert.True(fields.Count > 0);
    }

    [Fact]
    public void BuildFormFields_ForCreate_Invoice_WithLookups_DoesNotThrow()
    {
        var meta = DataScaffold.GetEntityByType(typeof(Invoice));
        Assert.NotNull(meta);

        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);
        Assert.NotNull(fields);
        Assert.True(fields.Count > 0);
    }

    [Fact]
    public void BuildFormFields_ForEdit_WithLookupFields_DoesNotThrow()
    {
        var product = new Product
        {
            Id = "prod-1",
            Name = "Widget",
            Sku = "W001",
            UnitOfMeasureId = "uom-1",
            CurrencyId = "cur-1",
            Price = 9.99m
        };

        var meta = DataScaffold.GetEntityByType(typeof(Product));
        Assert.NotNull(meta);

        var fields = DataScaffold.BuildFormFields(meta, product, forCreate: false);
        Assert.NotNull(fields);
        Assert.True(fields.Count > 0);
    }

    private static void ClearLookupCache()
    {
        // Use reflection to clear the private lookup cache
        var cacheField = typeof(DataScaffold).GetField("LookupCache",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        if (cacheField?.GetValue(null) is IDictionary cache)
            cache.Clear();
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
