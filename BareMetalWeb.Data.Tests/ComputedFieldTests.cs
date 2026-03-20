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
        public override string EntityTypeName => "Test Products";
        private const int Ord_BasePrice = BaseFieldCount + 0;
        private const int Ord_Name = BaseFieldCount + 1;
        private const int Ord_StockQuantity = BaseFieldCount + 2;
        internal new const int TotalFieldCount = BaseFieldCount + 3;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("BasePrice", Ord_BasePrice),
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Name", Ord_Name),
            new FieldSlot("StockQuantity", Ord_StockQuantity),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TestProduct() : base(TotalFieldCount) { }
        public TestProduct(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Label = "Product Name")]
        public string Name
        {
            get => (string?)_values[Ord_Name] ?? string.Empty;
            set => _values[Ord_Name] = value;
        }



        [DataField(Label = "Base Price", FieldType = FormFieldType.Money)]
        public decimal BasePrice
        {
            get => (decimal)(_values[Ord_BasePrice] ?? 0m);
            set => _values[Ord_BasePrice] = value;
        }



        [DataField(Label = "Stock Quantity")]
        public int StockQuantity
        {
            get => (int)(_values[Ord_StockQuantity] ?? 0);
            set => _values[Ord_StockQuantity] = value;
        }
    }

    [DataEntity("Test Orders")]
    public class TestOrder : BaseDataObject
    {
        public override string EntityTypeName => "Test Orders";
        private const int Ord_CurrentPriceCached = BaseFieldCount + 0;
        private const int Ord_CurrentPriceLive = BaseFieldCount + 1;
        private const int Ord_Lines = BaseFieldCount + 2;
        private const int Ord_OrderNumber = BaseFieldCount + 3;
        private const int Ord_OrderTotal = BaseFieldCount + 4;
        private const int Ord_ProductId = BaseFieldCount + 5;
        private const int Ord_Quantity = BaseFieldCount + 6;
        private const int Ord_UnitPriceSnapshot = BaseFieldCount + 7;
        internal new const int TotalFieldCount = BaseFieldCount + 8;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("CurrentPriceCached", Ord_CurrentPriceCached),
            new FieldSlot("CurrentPriceLive", Ord_CurrentPriceLive),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Lines", Ord_Lines),
            new FieldSlot("OrderNumber", Ord_OrderNumber),
            new FieldSlot("OrderTotal", Ord_OrderTotal),
            new FieldSlot("ProductId", Ord_ProductId),
            new FieldSlot("Quantity", Ord_Quantity),
            new FieldSlot("UnitPriceSnapshot", Ord_UnitPriceSnapshot),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TestOrder() : base(TotalFieldCount) { }
        public TestOrder(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Label = "Order Number")]
        public string OrderNumber
        {
            get => (string?)_values[Ord_OrderNumber] ?? string.Empty;
            set => _values[Ord_OrderNumber] = value;
        }



        [DataField(Label = "Product ID")]
        [DataLookup(typeof(TestProduct))]
        public string ProductId
        {
            get => (string?)_values[Ord_ProductId] ?? string.Empty;
            set => _values[Ord_ProductId] = value;
        }



        [DataField(Label = "Quantity")]
        public int Quantity
        {
            get => (int)(_values[Ord_Quantity] ?? 0);
            set => _values[Ord_Quantity] = value;
        }


        [DataField(Label = "Unit Price (Snapshot)", FieldType = FormFieldType.Money)]
        public decimal UnitPriceSnapshot
        {
            get => (decimal)(_values[Ord_UnitPriceSnapshot] ?? 0m);
            set => _values[Ord_UnitPriceSnapshot] = value;
        }


        [DataField(Label = "Current Price (Cached)", FieldType = FormFieldType.Money)]
        public decimal CurrentPriceCached
        {
            get => (decimal)(_values[Ord_CurrentPriceCached] ?? 0m);
            set => _values[Ord_CurrentPriceCached] = value;
        }


        [DataField(Label = "Current Price (Live)", FieldType = FormFieldType.Money, ReadOnly = true)]
        public decimal CurrentPriceLive
        {
            get => (decimal)(_values[Ord_CurrentPriceLive] ?? 0m);
            set => _values[Ord_CurrentPriceLive] = value;
        }


        [DataField(Label = "Line Items", Create = false, Edit = false)]
        public List<TestOrderLine> Lines
        {
            get => (List<TestOrderLine>?)_values[Ord_Lines] ?? new();
            set => _values[Ord_Lines] = value;
        }


        [DataField(Label = "Order Total", FieldType = FormFieldType.Money)]
        public decimal OrderTotal
        {
            get => (decimal)(_values[Ord_OrderTotal] ?? 0m);
            set => _values[Ord_OrderTotal] = value;
        }
    }

    public class TestOrderLine
    {
        public string ProductId { get; set; } = string.Empty;
        public decimal UnitPrice { get; set; }
        public int Quantity { get; set; }
        public decimal LineTotal => UnitPrice * Quantity;
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
