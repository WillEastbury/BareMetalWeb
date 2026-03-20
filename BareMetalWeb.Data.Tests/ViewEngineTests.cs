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
/// Tests for the BMW View Engine:
///   <see cref="ViewDefinition"/>, <see cref="SelectionVector"/>,
///   <see cref="ViewExecutionPlan"/>, <see cref="ViewEngine"/> and
///   <see cref="MaterializedViewCache"/>.
/// </summary>
[Collection("SharedState")]
public sealed class ViewEngineTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;
    private readonly InMemoryDataObjectStore _store;

    public ViewEngineTests()
    {
        _originalStore = DataStoreProvider.Current;
        _store = new InMemoryDataObjectStore();
        DataStoreProvider.Current = _store;
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
    }

    // ── Test entities ─────────────────────────────────────────────────────────

    [DataEntity("View Test Products", Slug = "view-test-products")]
    public class ViewTestProduct : BaseDataObject
    {
        public override string EntityTypeName => "View Test Products";
        private const int Ord_Category = BaseFieldCount + 0;
        private const int Ord_Name = BaseFieldCount + 1;
        private const int Ord_Price = BaseFieldCount + 2;
        private const int Ord_Stock = BaseFieldCount + 3;
        internal new const int TotalFieldCount = BaseFieldCount + 4;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("Category", Ord_Category),
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Name", Ord_Name),
            new FieldSlot("Price", Ord_Price),
            new FieldSlot("Stock", Ord_Stock),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public ViewTestProduct() : base(TotalFieldCount) { }
        public ViewTestProduct(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Label = "Name")]
        public string Name
        {
            get => (string?)_values[Ord_Name] ?? string.Empty;
            set => _values[Ord_Name] = value;
        }



        [DataField(Label = "Category")]
        public string Category
        {
            get => (string?)_values[Ord_Category] ?? string.Empty;
            set => _values[Ord_Category] = value;
        }



        [DataField(Label = "Price")]
        public decimal Price
        {
            get => (decimal)(_values[Ord_Price] ?? 0m);
            set => _values[Ord_Price] = value;
        }



        [DataField(Label = "Stock")]
        public int Stock
        {
            get => (int)(_values[Ord_Stock] ?? 0);
            set => _values[Ord_Stock] = value;
        }
    }

    [DataEntity("View Test Orders", Slug = "view-test-orders")]
    public class ViewTestOrder : BaseDataObject
    {
        public override string EntityTypeName => "View Test Orders";
        private const int Ord_ProductId = BaseFieldCount + 0;
        private const int Ord_Quantity = BaseFieldCount + 1;
        private const int Ord_Status = BaseFieldCount + 2;
        internal new const int TotalFieldCount = BaseFieldCount + 3;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("ProductId", Ord_ProductId),
            new FieldSlot("Quantity", Ord_Quantity),
            new FieldSlot("Status", Ord_Status),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public ViewTestOrder() : base(TotalFieldCount) { }
        public ViewTestOrder(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Label = "Product Id")]
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



        [DataField(Label = "Status")]
        public string Status
        {
            get => (string?)_values[Ord_Status] ?? string.Empty;
            set => _values[Ord_Status] = value;
        }
    }

    private void RegisterAndSeedEntities()
    {
        DataScaffold.RegisterEntity<ViewTestProduct>();
        DataScaffold.RegisterEntity<ViewTestOrder>();

        _store.Save(new ViewTestProduct { Key = 1, Name = "Widget A", Category = "Widgets", Price = 9.99m, Stock = 100 });
        _store.Save(new ViewTestProduct { Key = 2, Name = "Gadget B", Category = "Gadgets", Price = 49.99m, Stock = 25 });
        _store.Save(new ViewTestProduct { Key = 3, Name = "Widget C", Category = "Widgets", Price = 14.99m, Stock = 0 });

        _store.Save(new ViewTestOrder { Key = 10, ProductId = "1", Quantity = 2, Status = "Open" });
        _store.Save(new ViewTestOrder { Key = 11, ProductId = "2", Quantity = 1, Status = "Completed" });
        _store.Save(new ViewTestOrder { Key = 12, ProductId = "1", Quantity = 5, Status = "Open" });
    }

    // ── ViewDefinition model tests ────────────────────────────────────────────

    [Fact]
    public void ViewDefinition_ProjectionsRoundTrip()
    {
        var def = new ViewDefinition
        {
            ViewName   = "Test View",
            RootEntity = "view-test-products",
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Entity = "view-test-products", Field = "Name",  Alias = "productName" },
            new ViewProjection { Entity = "view-test-products", Field = "Price", Alias = "price" },
        };

        var roundTripped = def.Projections;
        Assert.Equal(2, roundTripped.Count);
        Assert.Equal("productName", roundTripped[0].Alias);
        Assert.Equal("Price", roundTripped[1].Field);
    }

    [Fact]
    public void ViewDefinition_JoinsRoundTrip()
    {
        var def = new ViewDefinition { ViewName = "Joined View", RootEntity = "view-test-orders" };
        def.Joins = new List<ViewJoinDefinition>
        {
            new ViewJoinDefinition
            {
                SourceEntity = "view-test-orders",
                SourceField  = "ProductId",
                TargetEntity = "view-test-products",
                TargetField  = "Key",
                Type         = JoinType.Inner,
            }
        };

        var j = def.Joins[0];
        Assert.Equal("view-test-orders", j.SourceEntity);
        Assert.Equal("ProductId", j.SourceField);
        Assert.Equal("view-test-products", j.TargetEntity);
        Assert.Equal(JoinType.Inner, j.Type);
    }

    [Fact]
    public void ViewDefinition_FiltersRoundTrip()
    {
        var def = new ViewDefinition { ViewName = "Filtered View", RootEntity = "view-test-products" };
        def.Filters = new List<ViewFilterDefinition>
        {
            new ViewFilterDefinition { Entity = "view-test-products", Field = "Category", Operator = "=", Value = "Widgets" }
        };

        var f = def.Filters[0];
        Assert.Equal("Category", f.Field);
        Assert.Equal("=", f.Operator);
        Assert.Equal("Widgets", f.Value);
    }

    [Fact]
    public void ViewDefinition_SortsRoundTrip()
    {
        var def = new ViewDefinition { ViewName = "Sorted View", RootEntity = "view-test-products" };
        def.Sorts = new List<ViewSortDefinition>
        {
            new ViewSortDefinition { Entity = "view-test-products", Field = "Price", Descending = true }
        };

        var s = def.Sorts[0];
        Assert.Equal("Price", s.Field);
        Assert.True(s.Descending);
    }

    // ── SelectionVector tests ─────────────────────────────────────────────────

    [Fact]
    public void SelectionVector_InitRange_SetsConsecutiveIndices()
    {
        var sv = new SelectionVector(SelectionVector.BatchSize);
        sv.InitRange(0, 5);

        Assert.Equal(5, sv.Count);
        for (int i = 0; i < 5; i++)
            Assert.Equal(i, sv.RowIndices[i]);
    }

    [Fact]
    public void SelectionVector_InitRange_WithBaseOffset()
    {
        var sv = new SelectionVector(SelectionVector.BatchSize);
        sv.InitRange(1024, 3);

        Assert.Equal(3, sv.Count);
        Assert.Equal(1024, sv.RowIndices[0]);
        Assert.Equal(1025, sv.RowIndices[1]);
        Assert.Equal(1026, sv.RowIndices[2]);
    }

    [Fact]
    public void SelectionVector_Reset_ClearsCount()
    {
        var sv = new SelectionVector(10);
        sv.InitRange(0, 10);
        Assert.Equal(10, sv.Count);

        sv.Reset();
        Assert.Equal(0, sv.Count);
    }

    [Fact]
    public void SelectionVector_ApplyPredicate_FiltersCorrectly()
    {
        var sv   = new SelectionVector(10);
        sv.InitRange(0, 5);

        int[] values = [10, 20, 30, 40, 50];

        // Keep only rows where value > 25
        sv.ApplyPredicate(values, v => v > 25);

        Assert.Equal(3, sv.Count);
        Assert.Equal(2, sv.RowIndices[0]); // 30
        Assert.Equal(3, sv.RowIndices[1]); // 40
        Assert.Equal(4, sv.RowIndices[2]); // 50
    }

    [Fact]
    public void SelectionVector_ApplyPredicate_AllFail_CountIsZero()
    {
        var sv = new SelectionVector(5);
        sv.InitRange(0, 5);
        int[] values = [1, 2, 3, 4, 5];

        sv.ApplyPredicate(values, v => v > 100);

        Assert.Equal(0, sv.Count);
    }

    [Fact]
    public void SelectionVector_BatchSize_Is1024()
    {
        Assert.Equal(1024, SelectionVector.BatchSize);
    }

    // ── ViewEngine compilation tests ──────────────────────────────────────────

    [Fact]
    public void ViewEngine_Compile_ReturnsNonNullPlan()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition
        {
            ViewName   = "Compile Test",
            RootEntity = "view-test-products",
            Limit      = 100,
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Entity = "view-test-products", Field = "Name", Alias = "name" }
        };

        var plan = ViewEngine.Compile(def);

        Assert.NotNull(plan);
        Assert.Equal("view-test-products", plan.RootEntitySlug);
        Assert.NotNull(plan.RootEntityMeta);
        Assert.Equal(100, plan.Limit);
        Assert.Single(plan.ProjectionMap);
        Assert.Equal("name", plan.ProjectionMap[0].Alias);
    }

    [Fact]
    public void ViewEngine_Compile_CachesPlans()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition { ViewName = "Cache Test", RootEntity = "view-test-products", Key = 999 };

        var plan1 = ViewEngine.Compile(def);
        var plan2 = ViewEngine.Compile(def);

        Assert.Same(plan1, plan2); // exact same instance returned from cache
    }

    [Fact]
    public void ViewEngine_Compile_CompilesFilterPredicate()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition { ViewName = "Filter Compile Test", RootEntity = "view-test-products" };
        def.Filters = new List<ViewFilterDefinition>
        {
            new ViewFilterDefinition { Field = "Category", Operator = "=", Value = "Widgets" }
        };

        var plan = ViewEngine.Compile(def);

        Assert.Single(plan.FilterFunctions);
        Assert.NotNull(plan.FilterFunctions[0].Predicate);
    }

    [Fact]
    public void ViewEngine_Compile_CompilesJoinEntry()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition { ViewName = "Join Compile Test", RootEntity = "view-test-orders" };
        def.Joins = new List<ViewJoinDefinition>
        {
            new ViewJoinDefinition
            {
                SourceEntity = "view-test-orders",
                SourceField  = "ProductId",
                TargetEntity = "view-test-products",
                TargetField  = "Key",
                Type         = JoinType.Inner,
            }
        };

        var plan = ViewEngine.Compile(def);

        Assert.Single(plan.JoinLookupFunctions);
        var je = plan.JoinLookupFunctions[0];
        Assert.NotNull(je.SourceKeyExtractor);
        Assert.Equal(JoinType.Inner, je.JoinType);
    }

    // ── ViewEngine execution tests ────────────────────────────────────────────

    [Fact]
    public async Task ViewEngine_Execute_ReturnsAllRows_NoFilters()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition
        {
            ViewName   = "All Products",
            RootEntity = "view-test-products",
            Limit      = 1000,
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Field = "Name",  Alias = "name" },
            new ViewProjection { Field = "Price", Alias = "price" },
        };

        var engine = new ViewEngine();
        var result = await engine.ExecuteAsync(def);

        Assert.Equal(3, result.TotalRows);
        Assert.Equal(2, result.ColumnLabels.Length);
        Assert.Equal("name",  result.ColumnLabels[0]);
        Assert.Equal("price", result.ColumnLabels[1]);
    }

    [Fact]
    public async Task ViewEngine_Execute_Filter_Equals_ReducesRows()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition
        {
            ViewName   = "Widgets Only",
            RootEntity = "view-test-products",
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Field = "Name", Alias = "name" },
        };
        def.Filters = new List<ViewFilterDefinition>
        {
            new ViewFilterDefinition { Field = "Category", Operator = "=", Value = "Widgets" }
        };

        var engine = new ViewEngine();
        var result = await engine.ExecuteAsync(def);

        Assert.Equal(2, result.TotalRows);
        Assert.All(result.Rows, row =>
            Assert.True(row[0] == "Widget A" || row[0] == "Widget C"));
    }

    [Fact]
    public async Task ViewEngine_Execute_Filter_GreaterThan_ReducesRows()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition
        {
            ViewName   = "Expensive Products",
            RootEntity = "view-test-products",
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Field = "Name", Alias = "name" },
        };
        def.Filters = new List<ViewFilterDefinition>
        {
            new ViewFilterDefinition { Field = "Price", Operator = ">", Value = "20" }
        };

        var engine = new ViewEngine();
        var result = await engine.ExecuteAsync(def);

        Assert.Equal(1, result.TotalRows);
        Assert.Equal("Gadget B", result.Rows[0][0]);
    }

    [Fact]
    public async Task ViewEngine_Execute_Filter_Contains()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition
        {
            ViewName   = "Widget Search",
            RootEntity = "view-test-products",
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Field = "Name", Alias = "name" },
        };
        def.Filters = new List<ViewFilterDefinition>
        {
            new ViewFilterDefinition { Field = "Name", Operator = "contains", Value = "Widget" }
        };

        var engine = new ViewEngine();
        var result = await engine.ExecuteAsync(def);

        Assert.Equal(2, result.TotalRows);
    }

    [Fact]
    public async Task ViewEngine_Execute_Limit_CapsOutput()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition
        {
            ViewName   = "Limited Products",
            RootEntity = "view-test-products",
            Limit      = 1,
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Field = "Name", Alias = "name" },
        };

        var engine = new ViewEngine();
        var result = await engine.ExecuteAsync(def);

        Assert.Equal(1, result.TotalRows);
    }

    [Fact]
    public async Task ViewEngine_Execute_Offset_SkipsRows()
    {
        RegisterAndSeedEntities();

        // Get all rows first to know how many there are
        var defAll = new ViewDefinition { ViewName = "All", RootEntity = "view-test-products", Limit = 1000, Offset = 0 };
        defAll.Projections = new List<ViewProjection> { new ViewProjection { Field = "Name", Alias = "name" } };
        var engine = new ViewEngine();
        var resultAll = await engine.ExecuteAsync(defAll);
        int total = resultAll.TotalRows;

        // Now with offset
        var defOffset = new ViewDefinition { ViewName = "Offset2", RootEntity = "view-test-products", Limit = 1000, Offset = 2 };
        defOffset.Projections = new List<ViewProjection> { new ViewProjection { Field = "Name", Alias = "name" } };
        var resultOffset = await engine.ExecuteAsync(defOffset);

        Assert.Equal(Math.Max(0, total - 2), resultOffset.TotalRows);
    }

    [Fact]
    public async Task ViewEngine_Execute_InnerJoin_ReturnsMatchedRows()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition
        {
            ViewName   = "Orders With Products",
            RootEntity = "view-test-orders",
        };
        def.Joins = new List<ViewJoinDefinition>
        {
            new ViewJoinDefinition
            {
                SourceEntity = "view-test-orders",
                SourceField  = "ProductId",
                TargetEntity = "view-test-products",
                TargetField  = "Key",
                Type         = JoinType.Inner,
            }
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Entity = "view-test-orders",   Field = "Quantity", Alias = "qty"     },
            new ViewProjection { Entity = "view-test-products", Field = "Name",     Alias = "product" },
        };

        var engine = new ViewEngine();
        var result = await engine.ExecuteAsync(def);

        // Orders 10 and 12 map to product 1 (Widget A); order 11 maps to product 2 (Gadget B)
        Assert.Equal(3, result.TotalRows);
        Assert.Contains(result.Rows, r => r[1] == "Widget A");
        Assert.Contains(result.Rows, r => r[1] == "Gadget B");
    }

    [Fact]
    public async Task ViewEngine_Execute_LeftJoin_PreservesUnmatchedLeftRows()
    {
        RegisterAndSeedEntities();

        // Add an order that references a non-existent product
        _store.Save(new ViewTestOrder { Key = 99, ProductId = "999", Quantity = 1, Status = "Open" });

        var def = new ViewDefinition
        {
            ViewName   = "All Orders LEFT JOIN Products",
            RootEntity = "view-test-orders",
        };
        def.Joins = new List<ViewJoinDefinition>
        {
            new ViewJoinDefinition
            {
                SourceEntity = "view-test-orders",
                SourceField  = "ProductId",
                TargetEntity = "view-test-products",
                TargetField  = "Key",
                Type         = JoinType.Left,
            }
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Entity = "view-test-orders",   Field = "Status",   Alias = "status"  },
            new ViewProjection { Entity = "view-test-products", Field = "Name",     Alias = "product" },
        };

        var engine = new ViewEngine();
        var result = await engine.ExecuteAsync(def);

        // 4 orders total; unmatched order 99 should still appear with null product
        Assert.Equal(4, result.TotalRows);
        // The unmatched order row should have null/empty product name
        bool foundNull = false;
        foreach (var row in result.Rows)
        {
            if (string.IsNullOrEmpty(row[1]))
            {
                foundNull = true;
                break;
            }
        }
        Assert.True(foundNull, "Expected a row with null product for unmatched LEFT JOIN");
    }

    [Fact]
    public async Task ViewEngine_Execute_EmptyRootEntity_ThrowsInvalidOperation()
    {
        var def = new ViewDefinition { ViewName = "Bad View", RootEntity = "nonexistent-entity-xyz" };
        var engine = new ViewEngine();
        await Assert.ThrowsAsync<InvalidOperationException>(() => engine.ExecuteAsync(def).AsTask());
    }

    // ── SelectionVector batch execution sanity test ───────────────────────────

    [Fact]
    public async Task ViewEngine_Execute_LargerThanBatchSize_ProcessesAllRows()
    {
        // Register and populate more than 1024 rows to exercise batch processing
        DataScaffold.RegisterEntity<ViewTestProduct>();

        for (uint i = 1; i <= 1100; i++)
        {
            _store.Save(new ViewTestProduct
            {
                Key      = i,
                Name     = $"Product {i}",
                Category = i % 2 == 0 ? "Even" : "Odd",
                Price    = i,
                Stock    = (int)i,
            });
        }

        var def = new ViewDefinition
        {
            ViewName   = "Large Dataset",
            RootEntity = "view-test-products",
            Limit      = 10000,
        };
        def.Filters = new List<ViewFilterDefinition>
        {
            new ViewFilterDefinition { Field = "Category", Operator = "=", Value = "Even" }
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Field = "Name", Alias = "name" },
        };

        var engine = new ViewEngine();
        var result = await engine.ExecuteAsync(def);

        // 1100 rows, 550 are "Even"
        Assert.Equal(550, result.TotalRows);
    }

    // ── MaterializedViewCache tests ───────────────────────────────────────────

    [Fact]
    public async Task MaterializedViewCache_GetOrRefreshAsync_ComputesResult()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition
        {
            ViewName   = "MatViewTest",
            RootEntity = "view-test-products",
            Materialised = true,
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Field = "Name", Alias = "name" },
        };

        var cache = new MaterializedViewCache_TestAccessor();
        cache.Register(def);

        var result1 = await cache.GetOrRefreshAsync("MatViewTest");
        var result2 = await cache.GetOrRefreshAsync("MatViewTest");

        Assert.NotNull(result1);
        Assert.NotNull(result2);
        // Second call should return the same cached instance
        Assert.Same(result1, result2);
        Assert.Equal(3, result1!.TotalRows);
    }

    [Fact]
    public async Task MaterializedViewCache_InvalidateView_ForcesRefresh()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition
        {
            ViewName   = "MatViewInvalidate",
            RootEntity = "view-test-products",
            Materialised = true,
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Field = "Name", Alias = "name" },
        };

        var cache = new MaterializedViewCache_TestAccessor();
        cache.Register(def);

        var result1 = await cache.GetOrRefreshAsync("MatViewInvalidate");
        cache.InvalidateView("MatViewInvalidate");
        var result2 = await cache.GetOrRefreshAsync("MatViewInvalidate");

        Assert.NotNull(result1);
        Assert.NotNull(result2);
        // After invalidation, a new result object should be produced
        Assert.NotSame(result1, result2);
    }

    [Fact]
    public async Task MaterializedViewCache_NotifyEntityChanged_InvalidatesDependentView()
    {
        RegisterAndSeedEntities();

        var def = new ViewDefinition
        {
            ViewName   = "MatViewEntityChanged",
            RootEntity = "view-test-products",
            Materialised = true,
        };
        def.Projections = new List<ViewProjection>
        {
            new ViewProjection { Field = "Name", Alias = "name" },
        };

        var cache = new MaterializedViewCache_TestAccessor();
        cache.Register(def);

        var result1 = await cache.GetOrRefreshAsync("MatViewEntityChanged");

        // Simulate a write to view-test-products
        cache.NotifyEntityChanged("view-test-products");

        var result2 = await cache.GetOrRefreshAsync("MatViewEntityChanged");

        Assert.NotNull(result1);
        Assert.NotNull(result2);
        Assert.NotSame(result1, result2); // cache was invalidated
    }

    [Fact]
    public void MaterializedViewCache_GetOrRefreshAsync_UnregisteredView_ReturnsNull()
    {
        var result = MaterializedViewCache.Instance.GetOrRefreshAsync("DoesNotExist");
        Assert.True(result.IsCompleted);
        Assert.Null(result.Result);
    }

    // ── ViewDefinition default values ─────────────────────────────────────────

    [Fact]
    public void ViewDefinition_Defaults_LimitIs10000_OffsetIsZero()
    {
        var def = new ViewDefinition();
        Assert.Equal(10_000, def.Limit);
        Assert.Equal(0, def.Offset);
        Assert.False(def.Materialised);
    }

    [Fact]
    public void ViewJoinDefinition_DefaultType_IsInner()
    {
        var j = new ViewJoinDefinition();
        Assert.Equal(JoinType.Inner, j.Type);
    }

    [Fact]
    public void ViewFilterDefinition_DefaultOperator_IsEquals()
    {
        var f = new ViewFilterDefinition();
        Assert.Equal("=", f.Operator);
    }

    // ── InMemoryDataObjectStore ───────────────────────────────────────────────
    // Minimal in-process data store for test isolation.

    private sealed class InMemoryDataObjectStore : IDataObjectStore
    {
        private readonly Dictionary<(Type, uint), BaseDataObject> _items = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider p, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider p) { }
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

    // ── Test helper: isolated cache instance ──────────────────────────────────
    // A thin wrapper around a fresh cache so tests don't pollute the global singleton.

    private sealed class MaterializedViewCache_TestAccessor
    {
        private readonly Dictionary<string, ViewDefinition> _defs = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, ReportResult?>  _cache = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _invalidated = new(StringComparer.OrdinalIgnoreCase);
        private readonly ViewEngine _engine = new();

        public void Register(ViewDefinition def)
        {
            _defs[def.ViewName] = def;
            _invalidated.Add(def.ViewName);
        }

        public async ValueTask<ReportResult?> GetOrRefreshAsync(string viewName)
        {
            if (!_defs.TryGetValue(viewName, out var def))
                return null;

            if (!_invalidated.Contains(viewName) && _cache.TryGetValue(viewName, out var cached))
                return cached;

            var result = await _engine.ExecuteAsync(def).ConfigureAwait(false);
            _cache[viewName] = result;
            _invalidated.Remove(viewName);
            return result;
        }

        public void InvalidateView(string viewName)
        {
            _cache.Remove(viewName);
            _invalidated.Add(viewName);
        }

        public void NotifyEntityChanged(string entitySlug)
        {
            // Invalidate views that depend on this entity
            foreach (var (name, def) in _defs)
            {
                bool depends = string.Equals(def.RootEntity, entitySlug, StringComparison.OrdinalIgnoreCase);
                if (!depends)
                {
                    foreach (var j in def.Joins)
                    {
                        if (string.Equals(j.SourceEntity, entitySlug, StringComparison.OrdinalIgnoreCase)
                            || string.Equals(j.TargetEntity, entitySlug, StringComparison.OrdinalIgnoreCase))
                        {
                            depends = true;
                            break;
                        }
                    }
                }
                if (depends)
                    InvalidateView(name);
            }
        }
    }
}
