using System;
using System.Linq;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for <see cref="QueryPlanner"/>, <see cref="QueryPlanHistory"/>,
/// and related query-plan types.
/// </summary>
public class QueryPlannerTests
{
    // ── Test entities ────────────────────────────────────────────────────────

    [DataEntity("QueryPlanner Test Products", Slug = "qp-products")]
    private class QueryPlannerTestProduct : BaseDataObject
    {
        public override string EntityTypeName => "QueryPlanner Test Products";
        private const int Ord_Category = BaseFieldCount + 0;
        private const int Ord_Name = BaseFieldCount + 1;
        private const int Ord_Price = BaseFieldCount + 2;
        internal new const int TotalFieldCount = BaseFieldCount + 3;

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
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public QueryPlannerTestProduct() : base(TotalFieldCount) { }
        public QueryPlannerTestProduct(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Label = "Name")]
        [DataIndex]
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
    }

    [DataEntity("QueryPlanner Test Orders", Slug = "qp-orders")]
    private class QueryPlannerTestOrder : BaseDataObject
    {
        public override string EntityTypeName => "QueryPlanner Test Orders";
        private const int Ord_ProductId = BaseFieldCount + 0;
        private const int Ord_Status = BaseFieldCount + 1;
        internal new const int TotalFieldCount = BaseFieldCount + 2;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("ProductId", Ord_ProductId),
            new FieldSlot("Status", Ord_Status),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public QueryPlannerTestOrder() : base(TotalFieldCount) { }
        public QueryPlannerTestOrder(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Label = "Product Id")]
        [DataIndex]
        public string ProductId
        {
            get => (string?)_values[Ord_ProductId] ?? string.Empty;
            set => _values[Ord_ProductId] = value;
        }



        [DataField(Label = "Status")]
        public string Status
        {
            get => (string?)_values[Ord_Status] ?? string.Empty;
            set => _values[Ord_Status] = value;
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static QueryPlan CreateEmptyQueryPlan() => new QueryPlan(
        Steps: Array.Empty<QueryPlanStep>(),
        CanStreamAggregate: false,
        PushedFilters: new System.Collections.Generic.Dictionary<string, QueryDefinition>(),
        JoinOrderOptimised: false,
        MissingIndexRecommendations: Array.Empty<MissingIndexRecommendation>());

    // ── QueryPlanHistory ─────────────────────────────────────────────────────

    [Fact]
    public void QueryPlanHistory_Record_StoresEntry()
    {
        QueryPlanHistory.Clear();

        var plan = CreateEmptyQueryPlan();

        QueryPlanHistory.Record(new QueryPlanEntry
        {
            ExecutedAt     = DateTimeOffset.UtcNow,
            RootEntity     = "orders",
            JoinCount      = 0,
            ResultRowCount = 5,
            ElapsedMs      = 3.14,
            Plan           = plan
        });

        var snapshot = QueryPlanHistory.GetSnapshot();
        Assert.Single(snapshot);
        Assert.Equal("orders", snapshot[0].RootEntity);
        Assert.Equal(5, snapshot[0].ResultRowCount);
        Assert.InRange(snapshot[0].ElapsedMs, 3.13, 3.15);
    }

    [Fact]
    public void QueryPlanHistory_GetSnapshot_ReturnsNewestFirst()
    {
        QueryPlanHistory.Clear();

        var emptyPlan = CreateEmptyQueryPlan();

        QueryPlanHistory.Record(new QueryPlanEntry { ExecutedAt = DateTimeOffset.UtcNow, RootEntity = "first",  Plan = emptyPlan });
        QueryPlanHistory.Record(new QueryPlanEntry { ExecutedAt = DateTimeOffset.UtcNow, RootEntity = "second", Plan = emptyPlan });
        QueryPlanHistory.Record(new QueryPlanEntry { ExecutedAt = DateTimeOffset.UtcNow, RootEntity = "third",  Plan = emptyPlan });

        var snapshot = QueryPlanHistory.GetSnapshot();

        Assert.Equal(3, snapshot.Count);
        Assert.Equal("third",  snapshot[0].RootEntity);
        Assert.Equal("second", snapshot[1].RootEntity);
        Assert.Equal("first",  snapshot[2].RootEntity);
    }

    [Fact]
    public void QueryPlanHistory_Clear_RemovesAllEntries()
    {
        var emptyPlan = CreateEmptyQueryPlan();

        QueryPlanHistory.Record(new QueryPlanEntry { ExecutedAt = DateTimeOffset.UtcNow, RootEntity = "x", Plan = emptyPlan });

        QueryPlanHistory.Clear();

        Assert.Empty(QueryPlanHistory.GetSnapshot());
    }

    [Fact]
    public void QueryPlanHistory_MaxEntries_EvictsOldestWhenFull()
    {
        QueryPlanHistory.Clear();

        var emptyPlan = CreateEmptyQueryPlan();

        // Fill the buffer to capacity plus one
        for (var entryIndex = 0; entryIndex <= QueryPlanHistory.MaxEntries; entryIndex++)
        {
            QueryPlanHistory.Record(new QueryPlanEntry
            {
                ExecutedAt = DateTimeOffset.UtcNow,
                RootEntity = $"entity-{entryIndex}",
                Plan       = emptyPlan
            });
        }

        var snapshot = QueryPlanHistory.GetSnapshot();

        // Should retain exactly MaxEntries
        Assert.Equal(QueryPlanHistory.MaxEntries, snapshot.Count);
        // The oldest entry (entity-0) must have been evicted
        Assert.DoesNotContain(snapshot, e => e.RootEntity == "entity-0");
        // The newest entry must be present
        Assert.Contains(snapshot, e => e.RootEntity == $"entity-{QueryPlanHistory.MaxEntries}");
    }

    // ── QueryPlanner ─────────────────────────────────────────────────────────

    [Fact]
    public void QueryPlanner_Plan_ContainsLoadEntityAndProjectSteps()
    {
        DataScaffold.RegisterEntity<QueryPlannerTestProduct>();
        var planner = new QueryPlanner();

        var query = new ReportQuery().From("qp-products");
        var plan  = planner.Plan(query);

        Assert.Contains(plan.Steps, s => s.StepType == PlanStepType.LoadEntity);
        Assert.Contains(plan.Steps, s => s.StepType == PlanStepType.ProjectAndSort);
    }

    [Fact]
    public void QueryPlanner_Plan_WithJoin_ContainsHashJoinStep()
    {
        DataScaffold.RegisterEntity<QueryPlannerTestProduct>();
        DataScaffold.RegisterEntity<QueryPlannerTestOrder>();
        var planner = new QueryPlanner();

        var query = new ReportQuery()
            .From("qp-orders")
            .Join("qp-orders", "ProductId", "qp-products", "Id");

        var plan = planner.Plan(query);

        Assert.Contains(plan.Steps, s => s.StepType == PlanStepType.HashJoin);
        Assert.Equal(1, plan.Steps.Count(s => s.StepType == PlanStepType.HashJoin));
    }

    [Fact]
    public void QueryPlanner_Plan_FilterOnIndexedField_NoMissingIndexRecommendation()
    {
        DataScaffold.RegisterEntity<QueryPlannerTestProduct>();
        var planner = new QueryPlanner();

        // Name is [DataIndex]-decorated on QpProduct
        var query = new ReportQuery()
            .From("qp-products")
            .Where("qp-products.Name", "=", "Widget");

        var plan = planner.Plan(query);

        // No recommendation for an already-indexed filter field
        Assert.DoesNotContain(plan.MissingIndexRecommendations,
            r => string.Equals(r.FieldName, "Name", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void QueryPlanner_Plan_FilterOnUnindexedField_EmitsMissingIndexRecommendation()
    {
        DataScaffold.RegisterEntity<QueryPlannerTestProduct>();
        var planner = new QueryPlanner();

        // Category is NOT decorated with [DataIndex]
        var query = new ReportQuery()
            .From("qp-products")
            .Where("qp-products.Category", "=", "Electronics");

        var plan = planner.Plan(query);

        Assert.Contains(plan.MissingIndexRecommendations,
            r => string.Equals(r.FieldName, "Category", StringComparison.OrdinalIgnoreCase)
              && string.Equals(r.EntitySlug, "qp-products", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void QueryPlanner_Plan_SortOnUnindexedField_EmitsMissingIndexRecommendation()
    {
        DataScaffold.RegisterEntity<QueryPlannerTestProduct>();
        var planner = new QueryPlanner();

        // Price is NOT decorated with [DataIndex]
        var query = new ReportQuery()
            .From("qp-products")
            .OrderBy("Price");

        var plan = planner.Plan(query);

        Assert.Contains(plan.MissingIndexRecommendations,
            r => string.Equals(r.FieldName, "Price", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void QueryPlanner_Plan_IndexedFields_ReflectsDataIndexAttributes()
    {
        DataScaffold.RegisterEntity<QueryPlannerTestProduct>();
        var planner = new QueryPlanner();

        var query = new ReportQuery().From("qp-products");
        var plan  = planner.Plan(query);

        var loadStep = plan.Steps.First(s => s.StepType == PlanStepType.LoadEntity);

        // Name has [DataIndex]; Category and Price do not
        Assert.Contains("Name", loadStep.IndexedFields);
        Assert.DoesNotContain("Category", loadStep.IndexedFields);
        Assert.DoesNotContain("Price",    loadStep.IndexedFields);
    }

    [Fact]
    public void QueryPlanner_Plan_UnindexedJoinBuildSide_EmitsMissingIndexRecommendation()
    {
        DataScaffold.RegisterEntity<QueryPlannerTestProduct>();
        DataScaffold.RegisterEntity<QueryPlannerTestOrder>();
        var planner = new QueryPlanner();

        // Join on QpProduct.Id — Id is not decorated with [DataIndex] on QpProduct
        var query = new ReportQuery()
            .From("qp-orders")
            .Join("qp-orders", "ProductId", "qp-products", "Id");

        var plan = planner.Plan(query);

        // The build side (qp-products.Id) is unindexed → recommendation expected
        Assert.Contains(plan.MissingIndexRecommendations,
            r => string.Equals(r.EntitySlug, "qp-products", StringComparison.OrdinalIgnoreCase)
              && string.Equals(r.FieldName, "Id", StringComparison.OrdinalIgnoreCase));
    }
}
