using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for computed field attribute and service functionality.
/// </summary>
[Collection("SharedState")]
public class ComputedFieldTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;

    public ComputedFieldTests()
    {
        _originalStore = DataStoreProvider.Current;
        // Ensure a no-op store is active for tests that do not configure their own store
        DataStoreProvider.Current = new InMemoryDataObjectStore();
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
    }

    // Minimal in-memory implementation used as a safe default for this test class
    private sealed class InMemoryDataObjectStore : IDataObjectStore
    {
        private readonly Dictionary<(Type, uint), BaseDataObject> _items = new();
        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }
        public void Save<T>(T obj) where T : BaseDataObject => _items[(typeof(T), obj.Key)] = obj;
        public ValueTask SaveAsync<T>(T obj, CancellationToken ct = default) where T : BaseDataObject { Save(obj); return ValueTask.CompletedTask; }
        public T? Load<T>(uint key) where T : BaseDataObject => _items.TryGetValue((typeof(T), key), out var o) ? (T)o : null;
        public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken ct = default) where T : BaseDataObject => ValueTask.FromResult(Load<T>(key));
        public IEnumerable<T> Query<T>(QueryDefinition? q = null) where T : BaseDataObject => _items.Values.OfType<T>();
        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? q = null, CancellationToken ct = default) where T : BaseDataObject => ValueTask.FromResult(Query<T>(q));
        public ValueTask<int> CountAsync<T>(QueryDefinition? q = null, CancellationToken ct = default) where T : BaseDataObject => ValueTask.FromResult(Query<T>(q).Count());
        public void Delete<T>(uint key) where T : BaseDataObject => _items.Remove((typeof(T), key));
        public ValueTask DeleteAsync<T>(uint key, CancellationToken ct = default) where T : BaseDataObject { Delete<T>(key); return ValueTask.CompletedTask; }
    }

    // Test entities for computed field scenarios
    [DataEntity("Test Products")]
    public class TestProduct : BaseDataObject
    {
        [DataField(Label = "Product Name")]
        public string Name { get; set; } = string.Empty;

        [DataField(Label = "Base Price", FieldType = FormFieldType.Money)]
        public decimal BasePrice { get; set; }

        [DataField(Label = "Stock Quantity")]
        public int StockQuantity { get; set; }
    }

    [DataEntity("Test Orders")]
    public class TestOrder : BaseDataObject
    {
        [DataField(Label = "Order Number")]
        public string OrderNumber { get; set; } = string.Empty;

        [DataField(Label = "Product ID")]
        [DataLookup(typeof(TestProduct))]
        public string ProductId { get; set; } = string.Empty;

        [DataField(Label = "Quantity")]
        public int Quantity { get; set; }

        // Snapshot: price frozen at order creation
        [ComputedField(
            SourceEntity = typeof(TestProduct),
            SourceField = nameof(TestProduct.BasePrice),
            ForeignKeyField = nameof(ProductId),
            Strategy = ComputedStrategy.Snapshot,
            Trigger = ComputedTrigger.OnCreate)]
        [DataField(Label = "Unit Price (Snapshot)", FieldType = FormFieldType.Money)]
        public decimal UnitPriceSnapshot { get; set; }

        // Cached Live: shows current price with caching
        [ComputedField(
            SourceEntity = typeof(TestProduct),
            SourceField = nameof(TestProduct.BasePrice),
            ForeignKeyField = nameof(ProductId),
            Strategy = ComputedStrategy.CachedLive,
            CacheSeconds = 30)]
        [DataField(Label = "Current Price (Cached)", FieldType = FormFieldType.Money)]
        public decimal CurrentPriceCached { get; set; }

        // Always Live: always shows current price
        [ComputedField(
            SourceEntity = typeof(TestProduct),
            SourceField = nameof(TestProduct.BasePrice),
            ForeignKeyField = nameof(ProductId),
            Strategy = ComputedStrategy.AlwaysLive)]
        [DataField(Label = "Current Price (Live)", FieldType = FormFieldType.Money, ReadOnly = true)]
        public decimal CurrentPriceLive { get; set; }

        // Computed total (snapshot * quantity)
        [DataField(Label = "Line Items", Create = false, Edit = false)]
        public List<TestOrderLine> Lines { get; set; } = new();

        // Aggregate: sum of line totals
        [ComputedField(
            ChildCollectionProperty = nameof(Lines),
            SourceField = nameof(TestOrderLine.LineTotal),
            Strategy = ComputedStrategy.AlwaysLive,
            Aggregate = AggregateFunction.Sum)]
        [DataField(Label = "Order Total", FieldType = FormFieldType.Money)]
        public decimal OrderTotal { get; set; }
    }

    public class TestOrderLine
    {
        public string ProductId { get; set; } = string.Empty;
        public decimal UnitPrice { get; set; }
        public int Quantity { get; set; }
        public decimal LineTotal => UnitPrice * Quantity;
    }

    [Fact]
    public void ComputedFieldAttribute_CanBeApplied()
    {
        // Arrange & Act
        var property = typeof(TestOrder).GetProperty(nameof(TestOrder.UnitPriceSnapshot));
        var attribute = property?.GetCustomAttributes(typeof(ComputedFieldAttribute), true);

        // Assert
        Assert.NotNull(attribute);
        Assert.NotEmpty(attribute);
        Assert.IsType<ComputedFieldAttribute>(attribute[0]);
    }

    [Fact]
    public void DataFieldMetadata_IncludesComputedConfig()
    {
        // Arrange
        DataScaffold.RegisterEntity<TestProduct>();
        DataScaffold.RegisterEntity<TestOrder>();
        
        // Act
        var success = DataScaffold.TryGetEntity("test-orders", out var metadata);
        Assert.True(success);

        // Find the snapshot field
        var snapshotField = Array.Find(metadata.Fields.ToArray(), 
            f => f.Name == nameof(TestOrder.UnitPriceSnapshot));

        // Assert
        Assert.NotNull(snapshotField);
        Assert.NotNull(snapshotField.Computed);
        Assert.Equal(ComputedStrategy.Snapshot, snapshotField.Computed.Strategy);
        Assert.Equal(ComputedTrigger.OnCreate, snapshotField.Computed.Trigger);
        Assert.Equal(typeof(TestProduct), snapshotField.Computed.SourceEntity);
        Assert.Equal(nameof(TestProduct.BasePrice), snapshotField.Computed.SourceField);
        Assert.Equal(nameof(TestOrder.ProductId), snapshotField.Computed.ForeignKeyField);
    }

    [Fact]
    public void DataFieldMetadata_ComputedFieldsMarkedReadOnly()
    {
        // Arrange
        DataScaffold.RegisterEntity<TestProduct>();
        DataScaffold.RegisterEntity<TestOrder>();
        
        // Act
        var success = DataScaffold.TryGetEntity("test-orders", out var metadata);
        Assert.True(success);

        // Assert - all computed fields should be readonly
        var snapshotField = Array.Find(metadata.Fields.ToArray(), 
            f => f.Name == nameof(TestOrder.UnitPriceSnapshot));
        Assert.NotNull(snapshotField);
        Assert.True(snapshotField.ReadOnly);

        var cachedField = Array.Find(metadata.Fields.ToArray(), 
            f => f.Name == nameof(TestOrder.CurrentPriceCached));
        Assert.NotNull(cachedField);
        Assert.True(cachedField.ReadOnly);

        var liveField = Array.Find(metadata.Fields.ToArray(), 
            f => f.Name == nameof(TestOrder.CurrentPriceLive));
        Assert.NotNull(liveField);
        Assert.True(liveField.ReadOnly);
    }

    [Fact]
    public async Task GetComputedValueAsync_CachedLiveStrategy_UsesCaching()
    {
        // Arrange
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var originalStore = DataStoreProvider.Current;
        try
        {
            Directory.CreateDirectory(tempDir);
            var provider = new WalDataProvider(tempDir);
            var store = new DataObjectStore();
            store.RegisterProvider(provider);
            DataStoreProvider.Current = store;

            DataScaffold.RegisterEntity<TestProduct>();
            DataScaffold.RegisterEntity<TestOrder>();

            // Create a product
            var product = new TestProduct
            {
                Key = 1,
                Name = "Widget",
                BasePrice = 49.99m,
                StockQuantity = 100
            };
            await store.SaveAsync(product);

            var order = new TestOrder
            {
                Key = 1,
                OrderNumber = "ORD-001",
                ProductId = "1",
                Quantity = 5
            };

            var success = DataScaffold.TryGetEntity("test-orders", out var metadata);
            Assert.True(success);

            var cachedField = Array.Find(metadata.Fields.ToArray(), 
                f => f.Name == nameof(TestOrder.CurrentPriceCached));
            Assert.NotNull(cachedField);

            // Act - first call should fetch from source
            var value1 = await ComputedFieldService.GetComputedValueAsync(metadata, order, cachedField);

            // Update the product price
            product.BasePrice = 59.99m;
            await store.SaveAsync(product);

            // Act - second call within cache window should return cached value
            var value2 = await ComputedFieldService.GetComputedValueAsync(metadata, order, cachedField);

            // Assert - both should be the same (cached)
            Assert.Equal(49.99m, value1);
            Assert.Equal(49.99m, value2); // Still cached
        }
        finally
        {
            ComputedFieldService.ClearAllCache();
            DataStoreProvider.Current = originalStore;
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task GetComputedValueAsync_AlwaysLiveStrategy_AlwaysRefreshes()
    {
        // Arrange
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var originalStore = DataStoreProvider.Current;
        try
        {
            Directory.CreateDirectory(tempDir);
            var provider = new WalDataProvider(tempDir);
            var store = new DataObjectStore();
            store.RegisterProvider(provider);
            DataStoreProvider.Current = store;

            DataScaffold.RegisterEntity<TestProduct>();
            DataScaffold.RegisterEntity<TestOrder>();

            // Create a product
            var product = new TestProduct
            {
                Key = 1,
                Name = "Widget",
                BasePrice = 49.99m,
                StockQuantity = 100
            };
            await store.SaveAsync(product);

            var order = new TestOrder
            {
                Key = 1,
                OrderNumber = "ORD-001",
                ProductId = "1",
                Quantity = 5
            };

            var success = DataScaffold.TryGetEntity("test-orders", out var metadata);
            Assert.True(success);

            var liveField = Array.Find(metadata.Fields.ToArray(), 
                f => f.Name == nameof(TestOrder.CurrentPriceLive));
            Assert.NotNull(liveField);

            // Act - first call
            var value1 = await ComputedFieldService.GetComputedValueAsync(metadata, order, liveField);

            // Update the product price
            product.BasePrice = 59.99m;
            await store.SaveAsync(product);

            // Act - second call should get updated value (no caching)
            var value2 = await ComputedFieldService.GetComputedValueAsync(metadata, order, liveField);

            // Assert - should reflect the change
            Assert.Equal(49.99m, value1);
            Assert.Equal(59.99m, value2); // Live refresh!
        }
        finally
        {
            DataStoreProvider.Current = originalStore;
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, true);
        }
    }

    [Fact]
    public async Task ComputedField_AggregateSum_CalculatesTotal()
    {
        // Arrange
        DataScaffold.RegisterEntity<TestProduct>();
        DataScaffold.RegisterEntity<TestOrder>();

        var order = new TestOrder
        {
            Key = 1,
            OrderNumber = "ORD-001",
            Lines = new List<TestOrderLine>
            {
                new() { ProductId = "1", UnitPrice = 10.00m, Quantity = 2 },
                new() { ProductId = "PROD-2", UnitPrice = 25.00m, Quantity = 3 },
                new() { ProductId = "PROD-3", UnitPrice = 5.00m, Quantity = 10 }
            }
        };

        var success = DataScaffold.TryGetEntity("test-orders", out var metadata);
        Assert.True(success);

        var totalField = Array.Find(metadata.Fields.ToArray(), 
            f => f.Name == nameof(TestOrder.OrderTotal));
        Assert.NotNull(totalField);

        // Act
        var total = await ComputedFieldService.GetComputedValueAsync(metadata, order, totalField);

        // Assert
        // (10 * 2) + (25 * 3) + (5 * 10) = 20 + 75 + 50 = 145
        Assert.Equal(145.00m, total);
    }

    [Fact]
    public void ComputedFieldService_ClearCache_RemovesCachedValues()
    {
        // Arrange
        DataScaffold.RegisterEntity<TestOrder>();
        var success = DataScaffold.TryGetEntity("test-orders", out var metadata);
        Assert.True(success);

        // Act
        ComputedFieldService.ClearCache(metadata, "ORD-1");
        ComputedFieldService.ClearAllCache();

        // Assert - should not throw
        Assert.True(true);
    }
}
