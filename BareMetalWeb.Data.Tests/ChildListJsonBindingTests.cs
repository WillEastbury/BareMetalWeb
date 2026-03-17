using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests that child list fields (e.g. Order.OrderRows) can be deserialized
/// from JSON payloads sent by the VNext SPA.
/// </summary>
[Collection("SharedState")]
public class ChildListJsonBindingTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;

    [DataEntity("Test Order Rows", Slug = "test-order-rows")]
    private class TestOrderRow : BaseDataObject
    {
        private const int Ord_LineTotal = BaseFieldCount + 0;
        private const int Ord_Notes = BaseFieldCount + 1;
        private const int Ord_ProductId = BaseFieldCount + 2;
        private const int Ord_Quantity = BaseFieldCount + 3;
        private const int Ord_UnitPrice = BaseFieldCount + 4;
        internal new const int TotalFieldCount = BaseFieldCount + 5;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("LineTotal", Ord_LineTotal),
            new FieldSlot("Notes", Ord_Notes),
            new FieldSlot("ProductId", Ord_ProductId),
            new FieldSlot("Quantity", Ord_Quantity),
            new FieldSlot("UnitPrice", Ord_UnitPrice),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TestOrderRow() : base(TotalFieldCount) { }
        public TestOrderRow(string createdBy) : base(TotalFieldCount, createdBy) { }

        [DataField]
        public string ProductId
        {
            get => (string?)_values[Ord_ProductId] ?? string.Empty;
            set => _values[Ord_ProductId] = value;
        }

        [DataField]
        public int Quantity
        {
            get => (int)(_values[Ord_Quantity] ?? 0);
            set => _values[Ord_Quantity] = value;
        }

        [DataField]
        public decimal UnitPrice
        {
            get => (decimal)(_values[Ord_UnitPrice] ?? 0m);
            set => _values[Ord_UnitPrice] = value;
        }

        [DataField]
        public string Notes
        {
            get => (string?)_values[Ord_Notes] ?? string.Empty;
            set => _values[Ord_Notes] = value;
        }

        [DataField]
        public decimal LineTotal
        {
            get => (decimal)(_values[Ord_LineTotal] ?? 0m);
            set => _values[Ord_LineTotal] = value;
        }
    }

    public ChildListJsonBindingTests()
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
    public void TryConvertJson_ChildList_Array_Of_Objects()
    {
        // Simulate VNext payload: OrderRows as JSON array of objects
        var json = """
        [
            { "ProductId": "prod-1", "Quantity": 3, "UnitPrice": 9.99, "Notes": "rush" },
            { "ProductId": "prod-2", "Quantity": 1, "UnitPrice": 25.00 }
        ]
        """;
        var element = JsonDocument.Parse(json).RootElement;

        var result = DataScaffold.TryConvertJson(element, typeof(List<TestOrderRow>), out var converted);

        Assert.True(result, "TryConvertJson should succeed for List<TestOrderRow>");
        var list = Assert.IsType<List<TestOrderRow>>(converted);
        Assert.Equal(2, list.Count);

        Assert.Equal("prod-1", list[0].ProductId);
        Assert.Equal(3, list[0].Quantity);
        Assert.Equal(9.99m, list[0].UnitPrice);
        Assert.Equal("rush", list[0].Notes);

        Assert.Equal("prod-2", list[1].ProductId);
        Assert.Equal(1, list[1].Quantity);
        Assert.Equal(25.00m, list[1].UnitPrice);
    }

    [Fact]
    public void TryConvertJson_ChildList_Empty_Array()
    {
        var element = JsonDocument.Parse("[]").RootElement;

        var result = DataScaffold.TryConvertJson(element, typeof(List<TestOrderRow>), out var converted);

        Assert.True(result);
        var list = Assert.IsType<List<TestOrderRow>>(converted);
        Assert.Empty(list);
    }

    [Fact]
    public void TryConvertJson_ChildList_Null_Returns_Empty_List()
    {
        var element = JsonDocument.Parse("null").RootElement;

        var result = DataScaffold.TryConvertJson(element, typeof(List<TestOrderRow>), out var converted);

        Assert.True(result);
        var list = Assert.IsType<List<TestOrderRow>>(converted);
        Assert.Empty(list);
    }

    [Fact]
    public void TryConvertJson_ChildList_Ignores_Unknown_Properties()
    {
        var json = """[{ "ProductId": "x", "Quantity": 1, "UnitPrice": 5, "Bogus": "ignored" }]""";
        var element = JsonDocument.Parse(json).RootElement;

        var result = DataScaffold.TryConvertJson(element, typeof(List<TestOrderRow>), out var converted);

        Assert.True(result);
        var list = Assert.IsType<List<TestOrderRow>>(converted);
        Assert.Single(list);
        Assert.Equal("x", list[0].ProductId);
    }

    [Fact]
    public void TryConvertJson_ChildList_CaseInsensitive_Properties()
    {
        // VNext payload may use camelCase while C# uses PascalCase
        var json = """[{ "productId": "p1", "quantity": 2, "unitPrice": 10.5 }]""";
        var element = JsonDocument.Parse(json).RootElement;

        var result = DataScaffold.TryConvertJson(element, typeof(List<TestOrderRow>), out var converted);

        Assert.True(result);
        var list = Assert.IsType<List<TestOrderRow>>(converted);
        Assert.Single(list);
        Assert.Equal("p1", list[0].ProductId);
        Assert.Equal(2, list[0].Quantity);
        Assert.Equal(10.5m, list[0].UnitPrice);
    }

    [Fact]
    public void TryConvertJson_ListString_Still_Works()
    {
        // Ensure we didn't break List<string> handling
        var json = """["tag1", "tag2", "tag3"]""";
        var element = JsonDocument.Parse(json).RootElement;

        var result = DataScaffold.TryConvertJson(element, typeof(List<string>), out var converted);

        Assert.True(result);
        var list = Assert.IsType<List<string>>(converted);
        Assert.Equal(3, list.Count);
        Assert.Equal("tag1", list[0]);
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
