using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for ReportQuery, ReportExecutor, and related report models.
/// </summary>
[Collection("DataStoreProvider")]
public class ReportQueryTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;
    private readonly InMemoryDataObjectStore _store;

    public ReportQueryTests()
    {
        _originalStore = DataStoreProvider.Current;
        _store = new InMemoryDataObjectStore();
        DataStoreProvider.Current = _store;
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
    }

    // ── Test entities ────────────────────────────────────────────────────────

    [DataEntity("Test Customers", Slug = "test-customers")]
    public class TestCustomer : BaseDataObject
    {
        [DataField(Label = "Name")]
        public string Name { get; set; } = string.Empty;

        [DataField(Label = "Discount")]
        public decimal Discount { get; set; }
    }

    [DataEntity("Test Orders", Slug = "test-orders")]
    public class TestOrder : BaseDataObject
    {
        [DataField(Label = "Customer Id")]
        public string CustomerId { get; set; } = string.Empty;

        [DataField(Label = "Amount")]
        public decimal Amount { get; set; }

        [DataField(Label = "Status")]
        public string Status { get; set; } = "Open";
    }

    // ── ReportQuery builder tests ────────────────────────────────────────────

    [Fact]
    public void ReportQuery_From_SetsRootEntity()
    {
        var query = new ReportQuery().From("orders");
        Assert.Equal("orders", query.RootEntity);
    }

    [Fact]
    public void ReportQuery_Join_AddsJoin()
    {
        var query = new ReportQuery()
            .From("orders")
            .Join("orders", "CustomerId", "customers", "Id");

        Assert.Single(query.Joins);
        Assert.Equal("orders", query.Joins[0].FromEntity);
        Assert.Equal("CustomerId", query.Joins[0].FromField);
        Assert.Equal("customers", query.Joins[0].ToEntity);
        Assert.Equal("Id", query.Joins[0].ToField);
    }

    [Fact]
    public void ReportQuery_Select_AddsColumns()
    {
        var query = new ReportQuery()
            .From("orders")
            .Select("orders.Amount", "customers.Name");

        Assert.Equal(2, query.Columns.Count);
        Assert.Equal("orders", query.Columns[0].Entity);
        Assert.Equal("Amount", query.Columns[0].Field);
        Assert.Equal("customers", query.Columns[1].Entity);
        Assert.Equal("Name", query.Columns[1].Field);
    }

    [Fact]
    public void ReportQuery_Where_AddsFilter()
    {
        var query = new ReportQuery()
            .From("orders")
            .Where("orders.Status", "=", "Open");

        Assert.Single(query.Filters);
        Assert.Equal("orders", query.Filters[0].Entity);
        Assert.Equal("Status", query.Filters[0].Field);
        Assert.Equal("=", query.Filters[0].Operator);
        Assert.Equal("Open", query.Filters[0].Value);
    }

    [Fact]
    public void ReportQuery_Where_WithoutEntityPrefix_UsesRootEntity()
    {
        var query = new ReportQuery()
            .From("orders")
            .Where("Status", "=", "Open");

        Assert.Single(query.Filters);
        Assert.Equal("orders", query.Filters[0].Entity);
        Assert.Equal("Status", query.Filters[0].Field);
    }

    [Fact]
    public void ReportQuery_OrderBy_SetsSortField()
    {
        var query = new ReportQuery()
            .From("orders")
            .OrderBy("orders.Amount", descending: true);

        Assert.Equal("orders.Amount", query.SortField);
        Assert.True(query.SortDescending);
    }

    [Fact]
    public void ReportQuery_Limit_SetsQueryLimit()
    {
        var query = new ReportQuery().From("orders").Limit(100);
        Assert.Equal(100, query.QueryLimit);
    }

    [Fact]
    public void ReportQuery_SelectColumn_AddsColumnWithLabel()
    {
        var query = new ReportQuery()
            .From("orders")
            .SelectColumn("orders", "Amount", "Order Total", "currency", AggregateFunction.Sum);

        Assert.Single(query.Columns);
        Assert.Equal("Order Total", query.Columns[0].Label);
        Assert.Equal("currency", query.Columns[0].Format);
        Assert.Equal(AggregateFunction.Sum, query.Columns[0].Aggregate);
    }

    // ── ReportExecutor tests ─────────────────────────────────────────────────

    private void RegisterAndSeedTestEntities()
    {
        DataScaffold.RegisterEntity<TestCustomer>();
        DataScaffold.RegisterEntity<TestOrder>();

        var c1 = new TestCustomer { Name = "Acme Corp", Discount = 10 };
        var c2 = new TestCustomer { Name = "Globex", Discount = 5 };
        _store.Save(c1);
        _store.Save(c2);

        _store.Save(new TestOrder { CustomerId = c1.Id, Amount = 100m, Status = "Open" });
        _store.Save(new TestOrder { CustomerId = c1.Id, Amount = 200m, Status = "Completed" });
        _store.Save(new TestOrder { CustomerId = c2.Id, Amount = 50m, Status = "Open" });
    }

    [Fact]
    public async Task ReportExecutor_SingleEntityNoJoin_ReturnsAllRows()
    {
        RegisterAndSeedTestEntities();

        var query = new ReportQuery()
            .From("test-orders")
            .SelectColumn("test-orders", "Amount", "Amount")
            .SelectColumn("test-orders", "Status", "Status");

        var executor = new ReportExecutor(_store);
        var result = await executor.ExecuteAsync(query);

        Assert.Equal(3, result.TotalRows);
        Assert.Equal(2, result.ColumnLabels.Length);
        Assert.Equal("Amount", result.ColumnLabels[0]);
        Assert.Equal("Status", result.ColumnLabels[1]);
    }

    [Fact]
    public async Task ReportExecutor_InnerJoin_ReturnsOnlyMatchedRows()
    {
        RegisterAndSeedTestEntities();

        var query = new ReportQuery()
            .From("test-orders")
            .Join("test-orders", "CustomerId", "test-customers", "Id")
            .SelectColumn("test-orders", "Amount", "Amount")
            .SelectColumn("test-customers", "Name", "Customer");

        var executor = new ReportExecutor(_store);
        var result = await executor.ExecuteAsync(query);

        // All 3 orders have matching customers
        Assert.Equal(3, result.TotalRows);
        Assert.Contains(result.Rows, r => r[1] == "Acme Corp");
        Assert.Contains(result.Rows, r => r[1] == "Globex");
    }

    [Fact]
    public async Task ReportExecutor_Filter_AppliesCorrectly()
    {
        RegisterAndSeedTestEntities();

        var query = new ReportQuery()
            .From("test-orders")
            .SelectColumn("test-orders", "Status", "Status")
            .Where("test-orders.Status", "=", "Open");

        var executor = new ReportExecutor(_store);
        var result = await executor.ExecuteAsync(query);

        Assert.Equal(2, result.TotalRows);
        Assert.All(result.Rows, r => Assert.Equal("Open", r[0]));
    }

    [Fact]
    public async Task ReportExecutor_Filter_ContainsOperator()
    {
        RegisterAndSeedTestEntities();

        var query = new ReportQuery()
            .From("test-customers")
            .SelectColumn("test-customers", "Name", "Name")
            .Where("test-customers.Name", "contains", "Corp");

        var executor = new ReportExecutor(_store);
        var result = await executor.ExecuteAsync(query);

        Assert.Equal(1, result.TotalRows);
        Assert.Equal("Acme Corp", result.Rows[0][0]);
    }

    [Fact]
    public async Task ReportExecutor_Aggregation_Sum()
    {
        RegisterAndSeedTestEntities();

        var query = new ReportQuery()
            .From("test-orders")
            .SelectColumn("test-orders", "Status", "Status")
            .SelectColumn("test-orders", "Amount", "Total", aggregate: AggregateFunction.Sum);

        var executor = new ReportExecutor(_store);
        var result = await executor.ExecuteAsync(query);

        // Two groups: "Open" and "Completed"
        Assert.Equal(2, result.TotalRows);

        var openRow = result.Rows.FirstOrDefault(r => r[0] == "Open");
        Assert.NotNull(openRow);
        Assert.Equal("150", openRow![1]); // 100 + 50

        var completedRow = result.Rows.FirstOrDefault(r => r[0] == "Completed");
        Assert.NotNull(completedRow);
        Assert.Equal("200", completedRow![1]);
    }

    [Fact]
    public async Task ReportExecutor_Aggregation_Count()
    {
        RegisterAndSeedTestEntities();

        var query = new ReportQuery()
            .From("test-orders")
            .SelectColumn("test-orders", "Status", "Status")
            .SelectColumn("test-orders", "Id", "Count", aggregate: AggregateFunction.Count);

        var executor = new ReportExecutor(_store);
        var result = await executor.ExecuteAsync(query);

        Assert.Equal(2, result.TotalRows);
        var openRow = result.Rows.FirstOrDefault(r => r[0] == "Open");
        Assert.NotNull(openRow);
        Assert.Equal("2", openRow![1]);
    }

    [Fact]
    public async Task ReportExecutor_RowLimit_TruncatesResults()
    {
        DataScaffold.RegisterEntity<TestCustomer>();
        for (int i = 0; i < 5; i++)
            _store.Save(new TestCustomer { Name = $"Customer {i}" });

        var query = new ReportQuery()
            .From("test-customers")
            .SelectColumn("test-customers", "Name", "Name")
            .Limit(3);

        var executor = new ReportExecutor(_store);
        var result = await executor.ExecuteAsync(query);

        Assert.Equal(3, result.TotalRows);
        Assert.True(result.IsTruncated);
    }

    [Fact]
    public async Task ReportExecutor_NoColumns_DefaultsToEntityFields()
    {
        RegisterAndSeedTestEntities();

        var query = new ReportQuery().From("test-customers");
        var executor = new ReportExecutor(_store);
        var result = await executor.ExecuteAsync(query);

        // Should return rows with default columns from entity metadata
        Assert.Equal(2, result.TotalRows);
        Assert.True(result.ColumnLabels.Length > 0);
    }

    // ── ReportDefinition entity tests ────────────────────────────────────────

    [Fact]
    public void ReportDefinition_JoinsRoundTrip()
    {
        var def = new ReportDefinition { Name = "Test Report", RootEntity = "orders" };
        def.Joins = new List<ReportJoin>
        {
            new ReportJoin { FromEntity = "orders", FromField = "CustomerId", ToEntity = "customers", ToField = "Id" }
        };

        var roundTripped = def.Joins;
        Assert.Single(roundTripped);
        Assert.Equal("orders", roundTripped[0].FromEntity);
        Assert.Equal("CustomerId", roundTripped[0].FromField);
    }

    [Fact]
    public void ReportDefinition_ColumnsRoundTrip()
    {
        var def = new ReportDefinition { Name = "Test Report", RootEntity = "orders" };
        def.Columns = new List<ReportColumn>
        {
            new ReportColumn { Entity = "orders", Field = "Amount", Label = "Total", Aggregate = AggregateFunction.Sum }
        };

        var roundTripped = def.Columns;
        Assert.Single(roundTripped);
        Assert.Equal("Total", roundTripped[0].Label);
        Assert.Equal(AggregateFunction.Sum, roundTripped[0].Aggregate);
    }

    [Fact]
    public void ReportDefinition_FiltersRoundTrip()
    {
        var def = new ReportDefinition { Name = "Test Report", RootEntity = "orders" };
        def.Filters = new List<ReportFilter>
        {
            new ReportFilter { Entity = "orders", Field = "Status", Operator = "=", Value = "Open" }
        };

        var roundTripped = def.Filters;
        Assert.Single(roundTripped);
        Assert.Equal("=", roundTripped[0].Operator);
        Assert.Equal("Open", roundTripped[0].Value);
    }

    [Fact]
    public void ReportDefinition_ParametersRoundTrip()
    {
        var def = new ReportDefinition { Name = "Test Report", RootEntity = "orders" };
        def.Parameters = new List<ReportParameter>
        {
            new ReportParameter { Name = "status", Label = "Status", Type = "string", DefaultValue = "Open" }
        };

        var roundTripped = def.Parameters;
        Assert.Single(roundTripped);
        Assert.Equal("status", roundTripped[0].Name);
        Assert.Equal("Open", roundTripped[0].DefaultValue);
    }

    [Fact]
    public void ReportDefinition_EmptyJson_ReturnsEmptyList()
    {
        var def = new ReportDefinition { Name = "Test", RootEntity = "orders" };
        Assert.Empty(def.Joins);
        Assert.Empty(def.Columns);
        Assert.Empty(def.Filters);
        Assert.Empty(def.Parameters);
    }

    // ── AggregateFunction tests ──────────────────────────────────────────────

    [Fact]
    public void AggregateFunction_ValuesAreDefined()
    {
        Assert.Equal(0, (int)AggregateFunction.None);
        Assert.Equal(1, (int)AggregateFunction.Sum);
        Assert.Equal(2, (int)AggregateFunction.Count);
        Assert.Equal(3, (int)AggregateFunction.Min);
        Assert.Equal(4, (int)AggregateFunction.Max);
        Assert.Equal(5, (int)AggregateFunction.Average);
    }

    // ── InMemory store for test isolation ────────────────────────────────────

    private sealed class InMemoryDataObjectStore : IDataObjectStore
    {
        private readonly Dictionary<(Type, string), BaseDataObject> _items = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider p, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider p) { }
        public void ClearProviders() { }

        public void Save<T>(T obj) where T : BaseDataObject => _items[(typeof(T), obj.Id)] = obj;
        public ValueTask SaveAsync<T>(T obj, CancellationToken ct = default) where T : BaseDataObject { Save(obj); return ValueTask.CompletedTask; }
        public T? Load<T>(string id) where T : BaseDataObject => _items.TryGetValue((typeof(T), id), out var o) ? (T)o : null;
        public ValueTask<T?> LoadAsync<T>(string id, CancellationToken ct = default) where T : BaseDataObject => ValueTask.FromResult(Load<T>(id));
        public IEnumerable<T> Query<T>(QueryDefinition? q = null) where T : BaseDataObject => _items.Values.OfType<T>();
        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? q = null, CancellationToken ct = default) where T : BaseDataObject => ValueTask.FromResult(Query<T>(q));
        public ValueTask<int> CountAsync<T>(QueryDefinition? q = null, CancellationToken ct = default) where T : BaseDataObject => ValueTask.FromResult(Query<T>(q).Count());
        public void Delete<T>(string id) where T : BaseDataObject => _items.Remove((typeof(T), id));
        public ValueTask DeleteAsync<T>(string id, CancellationToken ct = default) where T : BaseDataObject { Delete<T>(id); return ValueTask.CompletedTask; }
    }
}
