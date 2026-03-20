using System;
using System.Collections.Generic;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for <see cref="ColumnStats"/>, <see cref="ColumnStatsRegistry"/>,
/// <see cref="QueryCostEstimator"/>, and clause reordering.
///
/// Structured as:
///   1. Stat builder accuracy — int, long, double, float columns
///   2. Histogram accuracy — bucket boundaries, adaptive bucket count
///   3. Selectivity estimation — all operators
///   4. Clause reordering — most selective first
///   5. QueryCostBreakdown diagnostics
///   6. Edge cases — empty entity, single row, all-same values, deleted rows
///   7. Integration — stats collected via ColumnarStore.Build, staleness tracking
/// </summary>
[Collection("SharedState")]
public sealed class ColumnStatisticsTests : IDisposable
{
    [DataEntity("StatItems")]
    private class StatItem : BaseDataObject
    {
        private const int Ord_DoubleVal = BaseFieldCount + 0;
        private const int Ord_FloatVal = BaseFieldCount + 1;
        private const int Ord_IntVal = BaseFieldCount + 2;
        private const int Ord_LongVal = BaseFieldCount + 3;
        private const int Ord_StrVal = BaseFieldCount + 4;
        internal new const int TotalFieldCount = BaseFieldCount + 5;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("DoubleVal", Ord_DoubleVal),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("FloatVal", Ord_FloatVal),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("IntVal", Ord_IntVal),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("LongVal", Ord_LongVal),
            new FieldSlot("StrVal", Ord_StrVal),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public StatItem() : base(TotalFieldCount) { }
        public StatItem(string createdBy) : base(TotalFieldCount, createdBy) { }

        [DataField]
        public int IntVal
        {
            get => (int)(_values[Ord_IntVal] ?? 0);
            set => _values[Ord_IntVal] = value;
        }

        [DataField]
        public long LongVal
        {
            get => (long)(_values[Ord_LongVal] ?? 0L);
            set => _values[Ord_LongVal] = value;
        }

        [DataField]
        public double DoubleVal
        {
            get => (double)(_values[Ord_DoubleVal] ?? 0.0);
            set => _values[Ord_DoubleVal] = value;
        }

        [DataField]
        public float FloatVal
        {
            get => (float)(_values[Ord_FloatVal] ?? 0f);
            set => _values[Ord_FloatVal] = value;
        }

        [DataField]
        public string StrVal
        {
            get => (string?)_values[Ord_StrVal] ?? string.Empty;
            set => _values[Ord_StrVal] = value;
        }
    }

    public ColumnStatisticsTests()
    {
        DataScaffold.RegisterEntity<StatItem>();
    }

    public void Dispose() { }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static List<StatItem> MakeRows(int count, Func<int, StatItem> factory)
    {
        var list = new List<StatItem>(count);
        for (int i = 0; i < count; i++)
            list.Add(factory(i));
        return list;
    }

    private static DataEntityMetadata GetMeta() =>
        DataScaffold.GetEntityByType(typeof(StatItem))!;

    private static IReadOnlyDictionary<string, ColumnStats> BuildAndGetStats(List<StatItem> rows)
    {
        var meta = GetMeta();
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);
        return ColumnarStore.StatsRegistry.GetStats(meta.Name);
    }

    // ── 1. Stat builder accuracy ─────────────────────────────────────────────

    [Fact]
    public void IntStats_MinMaxDistinctRowCount()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = 10 + (i % 50),   // values 10..59, 50 distinct
            LongVal = i, DoubleVal = i, FloatVal = i
        });

        var stats = BuildAndGetStats(rows);
        Assert.True(stats.TryGetValue("IntVal", out var s));
        Assert.Equal(300, s.RowCount);
        Assert.Equal(50, s.DistinctCount);
        Assert.Equal(10L, s.MinValue);
        Assert.Equal(59L, s.MaxValue);
        Assert.False(s.IsFloatingPoint);
        Assert.Equal(0, s.NullCount);
    }

    [Fact]
    public void LongStats_MinMaxDistinct()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            LongVal = 1000L + (i % 100),  // 100 distinct
            IntVal = i, DoubleVal = i, FloatVal = i
        });

        var stats = BuildAndGetStats(rows);
        Assert.True(stats.TryGetValue("LongVal", out var s));
        Assert.Equal(300, s.RowCount);
        Assert.Equal(100, s.DistinctCount);
        Assert.Equal(1000L, s.MinValue);
        Assert.Equal(1099L, s.MaxValue);
        Assert.False(s.IsFloatingPoint);
    }

    [Fact]
    public void DoubleStats_MinMaxDistinct_IsFloatingPoint()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            DoubleVal = 1.0 + (i % 25) * 0.1,  // 25 distinct
            IntVal = i, LongVal = i, FloatVal = i
        });

        var stats = BuildAndGetStats(rows);
        Assert.True(stats.TryGetValue("DoubleVal", out var s));
        Assert.Equal(300, s.RowCount);
        Assert.Equal(25, s.DistinctCount);
        Assert.True(s.IsFloatingPoint);
        Assert.Equal(BitConverter.DoubleToInt64Bits(1.0), s.MinValue);
        Assert.Equal(BitConverter.DoubleToInt64Bits(1.0 + 24 * 0.1), s.MaxValue);
    }

    [Fact]
    public void FloatStats_MinMaxDistinct_CorrectBitCast()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            FloatVal = 2.0f + (i % 30) * 0.5f,  // 30 distinct
            IntVal = i, LongVal = i, DoubleVal = i
        });

        var stats = BuildAndGetStats(rows);
        Assert.True(stats.TryGetValue("FloatVal", out var s));
        Assert.Equal(300, s.RowCount);
        Assert.Equal(30, s.DistinctCount);
        Assert.True(s.IsFloatingPoint);
        // Verify correct SingleToInt32Bits cast (NOT DoubleToInt64Bits which was the bug)
        Assert.Equal((long)BitConverter.SingleToInt32Bits(2.0f), s.MinValue);
        Assert.Equal((long)BitConverter.SingleToInt32Bits(2.0f + 29 * 0.5f), s.MaxValue);
    }

    [Fact]
    public void NullCount_CountsInvalidRows_NotZeroValues()
    {
        // Build with 300 rows, some have IntVal = 0 — NullCount should be 0
        // because all rows are valid (validity bit set)
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = i % 5 == 0 ? 0 : i,  // 60 zeros, but all rows are valid
            LongVal = i, DoubleVal = i, FloatVal = i
        });

        var stats = BuildAndGetStats(rows);
        Assert.True(stats.TryGetValue("IntVal", out var s));
        // NullCount should be 0 because all 300 rows have their validity bit set
        Assert.Equal(0, s.NullCount);
    }

    // ── 2. Histogram accuracy ────────────────────────────────────────────────

    [Fact]
    public void IntHistogram_BuildsWhenEnoughDistinct()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = i,  // 300 distinct
            LongVal = i, DoubleVal = i, FloatVal = i
        });

        var stats = BuildAndGetStats(rows);
        var s = stats["IntVal"];
        Assert.NotNull(s.HistogramBoundaries);
        // Adaptive: min(64, 300, 300) = 64 buckets → 65 boundaries
        Assert.Equal(65, s.HistogramBoundaries!.Length);
        // First boundary = min, last = max
        Assert.Equal(0L, s.HistogramBoundaries[0]);
        Assert.Equal(299L, s.HistogramBoundaries[^1]);
    }

    [Fact]
    public void IntHistogram_AdaptsBucketCount_WhenFewDistinct()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = i % 10,  // only 10 distinct
            LongVal = i, DoubleVal = i, FloatVal = i
        });

        var stats = BuildAndGetStats(rows);
        var s = stats["IntVal"];
        Assert.NotNull(s.HistogramBoundaries);
        // Adaptive: min(64, 10, 300) = 10 buckets → 11 boundaries
        Assert.Equal(11, s.HistogramBoundaries!.Length);
    }

    [Fact]
    public void IntHistogram_Null_WhenTooFewRows()
    {
        var rows = MakeRows(5, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = i, LongVal = i, DoubleVal = i, FloatVal = i
        });

        var stats = BuildAndGetStats(rows);
        var s = stats["IntVal"];
        // 5 rows < MinRowsForHistogram (8)
        Assert.Null(s.HistogramBoundaries);
    }

    [Fact]
    public void DoubleHistogram_BuildsCorrectly()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            DoubleVal = i * 1.5,  // 300 distinct
            IntVal = i, LongVal = i, FloatVal = i
        });

        var stats = BuildAndGetStats(rows);
        var s = stats["DoubleVal"];
        Assert.NotNull(s.HistogramBoundaries);
        Assert.True(s.HistogramBoundaries!.Length > 1);
    }

    [Fact]
    public void FloatHistogram_BuildsCorrectly()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            FloatVal = i * 0.3f,  // 300 distinct
            IntVal = i, LongVal = i, DoubleVal = i
        });

        var stats = BuildAndGetStats(rows);
        var s = stats["FloatVal"];
        Assert.NotNull(s.HistogramBoundaries);
        Assert.True(s.HistogramBoundaries!.Length > 1);
    }

    [Fact]
    public void LongHistogram_BuildsCorrectly()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            LongVal = i * 7L,
            IntVal = i, DoubleVal = i, FloatVal = i
        });

        var stats = BuildAndGetStats(rows);
        var s = stats["LongVal"];
        Assert.NotNull(s.HistogramBoundaries);
    }

    // ── 3. Selectivity estimation ────────────────────────────────────────────

    [Fact]
    public void Selectivity_Equals_ReturnsOneOverDistinct()
    {
        var s = new ColumnStats { RowCount = 1000, DistinctCount = 50 };
        var clause = new QueryClause { Field = "x", Operator = QueryOperator.Equals, Value = 42 };
        double sel = QueryCostEstimator.EstimateSelectivity(clause, s);
        Assert.Equal(1.0 / 50, sel);
    }

    [Fact]
    public void Selectivity_NotEquals_ReturnsComplement()
    {
        var s = new ColumnStats { RowCount = 1000, DistinctCount = 50 };
        var clause = new QueryClause { Field = "x", Operator = QueryOperator.NotEquals, Value = 42 };
        double sel = QueryCostEstimator.EstimateSelectivity(clause, s);
        Assert.Equal(1.0 - (1.0 / 50), sel, 6);
    }

    [Fact]
    public void Selectivity_GreaterThan_UsesLinearInterpolation()
    {
        // Range [0, 100], target 75 → fraction above = 0.25
        var s = new ColumnStats { RowCount = 1000, DistinctCount = 100, MinValue = 0, MaxValue = 100 };
        var clause = new QueryClause { Field = "x", Operator = QueryOperator.GreaterThan, Value = 75 };
        double sel = QueryCostEstimator.EstimateSelectivity(clause, s);
        Assert.InRange(sel, 0.20, 0.30);
    }

    [Fact]
    public void Selectivity_LessThan_UsesLinearInterpolation()
    {
        // Range [0, 100], target 25 → fraction below = 0.25
        var s = new ColumnStats { RowCount = 1000, DistinctCount = 100, MinValue = 0, MaxValue = 100 };
        var clause = new QueryClause { Field = "x", Operator = QueryOperator.LessThan, Value = 25 };
        double sel = QueryCostEstimator.EstimateSelectivity(clause, s);
        Assert.InRange(sel, 0.20, 0.30);
    }

    [Fact]
    public void Selectivity_Contains_ReturnsHeuristic()
    {
        var s = new ColumnStats { RowCount = 1000, DistinctCount = 100 };
        var clause = new QueryClause { Field = "x", Operator = QueryOperator.Contains, Value = "test" };
        Assert.Equal(0.10, QueryCostEstimator.EstimateSelectivity(clause, s));
    }

    [Fact]
    public void Selectivity_StartsWith_ReturnsHeuristic()
    {
        var s = new ColumnStats { RowCount = 1000, DistinctCount = 100 };
        var clause = new QueryClause { Field = "x", Operator = QueryOperator.StartsWith, Value = "A" };
        Assert.Equal(0.05, QueryCostEstimator.EstimateSelectivity(clause, s));
    }

    [Fact]
    public void Selectivity_In_ScalesByListSize()
    {
        var s = new ColumnStats { RowCount = 1000, DistinctCount = 50 };
        var clause = new QueryClause { Field = "x", Operator = QueryOperator.In, Value = "a,b,c,d,e" };
        double sel = QueryCostEstimator.EstimateSelectivity(clause, s);
        Assert.Equal(5.0 / 50, sel, 6);
    }

    [Fact]
    public void Selectivity_NoStats_ReturnsOne()
    {
        var s = default(ColumnStats); // RowCount == 0
        var clause = new QueryClause { Field = "x", Operator = QueryOperator.Equals, Value = 42 };
        Assert.Equal(1.0, QueryCostEstimator.EstimateSelectivity(clause, s));
    }

    // ── 4. Clause reordering ─────────────────────────────────────────────────

    [Fact]
    public void OrderClauses_MostSelectiveFirst()
    {
        var statsMap = new Dictionary<string, ColumnStats>
        {
            ["Name"]  = new ColumnStats { RowCount = 1000, DistinctCount = 3 },    // 1/3 = 0.33
            ["Age"]   = new ColumnStats { RowCount = 1000, DistinctCount = 100 },  // 1/100 = 0.01
            ["Score"] = new ColumnStats { RowCount = 1000, DistinctCount = 10 },   // 1/10 = 0.10
        };

        var clauses = new List<QueryClause>
        {
            new() { Field = "Name", Operator = QueryOperator.Equals, Value = "Alice" },
            new() { Field = "Age", Operator = QueryOperator.Equals, Value = 30 },
            new() { Field = "Score", Operator = QueryOperator.Equals, Value = 5.0 },
        };

        var order = QueryCostEstimator.OrderClausesBySelectivity(clauses, statsMap);

        // Most selective (Age, 1/100) should come first
        Assert.Equal(1, order[0]); // Age
        Assert.Equal(2, order[1]); // Score
        Assert.Equal(0, order[2]); // Name
    }

    [Fact]
    public void OrderClauses_SingleClause_ReturnsSameOrder()
    {
        var statsMap = new Dictionary<string, ColumnStats>
        {
            ["Age"] = new ColumnStats { RowCount = 1000, DistinctCount = 50 },
        };

        var clauses = new List<QueryClause>
        {
            new() { Field = "Age", Operator = QueryOperator.Equals, Value = 25 },
        };

        var order = QueryCostEstimator.OrderClausesBySelectivity(clauses, statsMap);
        Assert.Single(order);
        Assert.Equal(0, order[0]);
    }

    // ── 5. QueryCostBreakdown ────────────────────────────────────────────────

    [Fact]
    public void EstimateCost_ProducesBreakdown()
    {
        var statsMap = new Dictionary<string, ColumnStats>
        {
            ["Age"] = new ColumnStats { RowCount = 1000, DistinctCount = 50 },
        };

        var clauses = new List<QueryClause>
        {
            new() { Field = "Age", Operator = QueryOperator.Equals, Value = 30 },
        };

        var breakdown = QueryCostEstimator.EstimateCost(1000, clauses, statsMap);

        Assert.Equal(1000, breakdown.TotalRows);
        Assert.Equal(1.0 / 50, breakdown.TotalSelectivity, 6);
        Assert.Equal(20, breakdown.EstimatedResultRows); // 1000 * 0.02 = 20
        Assert.NotNull(breakdown.ClauseDetails);
        Assert.Single(breakdown.ClauseDetails);
        Assert.Equal("Age", breakdown.ClauseDetails[0].Field);
        Assert.True(breakdown.ClauseDetails[0].HasStats);
    }

    [Fact]
    public void EstimateCost_MultiClause_MultipliesSelectivities()
    {
        var statsMap = new Dictionary<string, ColumnStats>
        {
            ["Age"]   = new ColumnStats { RowCount = 1000, DistinctCount = 50 },
            ["Score"] = new ColumnStats { RowCount = 1000, DistinctCount = 100 },
        };

        var clauses = new List<QueryClause>
        {
            new() { Field = "Age", Operator = QueryOperator.Equals, Value = 30 },
            new() { Field = "Score", Operator = QueryOperator.Equals, Value = 5.0 },
        };

        var breakdown = QueryCostEstimator.EstimateCost(1000, clauses, statsMap);
        // 1/50 * 1/100 = 0.0002
        Assert.Equal(0.0002, breakdown.TotalSelectivity, 6);
    }

    // ── 6. Edge cases ────────────────────────────────────────────────────────

    [Fact]
    public void Stats_SingleRow_NoHistogram()
    {
        var rows = MakeRows(1, i => new StatItem
        {
            Key = 1, IntVal = 42, LongVal = 42, DoubleVal = 42.0, FloatVal = 42f
        });

        var stats = BuildAndGetStats(rows);
        var s = stats["IntVal"];
        Assert.Equal(1, s.RowCount);
        Assert.Equal(1, s.DistinctCount);
        Assert.Null(s.HistogramBoundaries);
    }

    [Fact]
    public void Stats_AllSameValues_DistinctIsOne()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = 99, LongVal = 99, DoubleVal = 99.0, FloatVal = 99f
        });

        var stats = BuildAndGetStats(rows);
        Assert.Equal(1, stats["IntVal"].DistinctCount);
        Assert.Equal(1, stats["LongVal"].DistinctCount);
        Assert.Equal(1, stats["DoubleVal"].DistinctCount);
        Assert.Equal(1, stats["FloatVal"].DistinctCount);
    }

    [Fact]
    public void Stats_AllSameValues_NoHistogram()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = 7, LongVal = 7, DoubleVal = 7.0, FloatVal = 7f
        });

        var stats = BuildAndGetStats(rows);
        // distinct < 2 → no histogram
        Assert.Null(stats["IntVal"].HistogramBoundaries);
        Assert.Null(stats["DoubleVal"].HistogramBoundaries);
    }

    [Fact]
    public void EmptyEntity_ReturnsEmptyStats()
    {
        var stats = ColumnarStore.StatsRegistry.GetStats("nonexistent_entity_xyz");
        Assert.Empty(stats);
    }

    [Fact]
    public void Selectivity_DegenerateRange_ReturnsFiftyPercent()
    {
        // MinValue == MaxValue → degenerate range
        var s = new ColumnStats { RowCount = 100, DistinctCount = 1, MinValue = 50, MaxValue = 50 };
        var clause = new QueryClause { Field = "x", Operator = QueryOperator.GreaterThan, Value = 50 };
        Assert.Equal(0.5, QueryCostEstimator.EstimateSelectivity(clause, s));
    }

    // ── 7. Integration: ColumnarStore.Build + staleness ───────────────────────

    [Fact]
    public void Build_CollectsStats_Automatically()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = i, LongVal = i * 2, DoubleVal = i * 0.1, FloatVal = i * 0.01f
        });

        var meta = GetMeta();
        var store = new ColumnarStore(300);
        store.Build(rows, meta);

        var stats = ColumnarStore.StatsRegistry.GetStats(meta.Name);
        Assert.True(stats.ContainsKey("IntVal"));
        Assert.True(stats.ContainsKey("LongVal"));
        Assert.True(stats.ContainsKey("DoubleVal"));
        Assert.True(stats.ContainsKey("FloatVal"));
    }

    [Fact]
    public void GetRowCount_ReturnsValidCount()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = i, LongVal = i, DoubleVal = i, FloatVal = i
        });

        var meta = GetMeta();
        var store = new ColumnarStore(300);
        store.Build(rows, meta);

        int rc = ColumnarStore.StatsRegistry.GetRowCount(meta.Name);
        Assert.Equal(300, rc);
    }

    [Fact]
    public void UpsertRow_MarksStaleness()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = i, LongVal = i, DoubleVal = i, FloatVal = i
        });

        var meta = GetMeta();
        var store = new ColumnarStore(300);
        store.Build(rows, meta);

        Assert.False(ColumnarStore.StatsRegistry.IsStale(meta.Name));

        var newItem = new StatItem { Key = 999, IntVal = 999 };
        store.UpsertRow(newItem, meta);

        Assert.True(ColumnarStore.StatsRegistry.IsStale(meta.Name));
    }

    [Fact]
    public void RemoveRow_MarksStaleness()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = i, LongVal = i, DoubleVal = i, FloatVal = i
        });

        var meta = GetMeta();
        var store = new ColumnarStore(300);
        store.Build(rows, meta);

        Assert.False(ColumnarStore.StatsRegistry.IsStale(meta.Name));

        store.RemoveRow(1);

        Assert.True(ColumnarStore.StatsRegistry.IsStale(meta.Name));
    }

    [Fact]
    public void Rebuild_ClearsStaleness()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = i, LongVal = i, DoubleVal = i, FloatVal = i
        });

        var meta = GetMeta();
        var store = new ColumnarStore(300);
        store.Build(rows, meta);

        store.UpsertRow(new StatItem { Key = 999, IntVal = 999 }, meta);
        Assert.True(ColumnarStore.StatsRegistry.IsStale(meta.Name));

        // Rebuild clears staleness
        store.Build(rows, meta);
        Assert.False(ColumnarStore.StatsRegistry.IsStale(meta.Name));
    }

    // ── 8. Clause reordering integration (results unchanged) ─────────────────

    [Fact]
    public void ClauseReordering_DoesNotAffectResults()
    {
        var rows = MakeRows(300, i => new StatItem
        {
            Key = (uint)(i + 1),
            IntVal = i % 50,
            LongVal = i,
            DoubleVal = i * 0.5,
            FloatVal = i * 0.01f,
            StrVal = i.ToString()
        });

        var meta = GetMeta();
        var store = new ColumnarStore(300);
        store.Build(rows, meta);

        // Multi-clause query: Age AND Score range
        var query = new QueryDefinition
        {
            Clauses =
            {
                new QueryClause { Field = "IntVal", Operator = QueryOperator.Equals, Value = 25 },
                new QueryClause { Field = "LongVal", Operator = QueryOperator.GreaterThanOrEqual, Value = 0L },
            }
        };

        var vectorized = ColumnQueryExecutor.Filter<StatItem>(rows, query);

        // Compare with brute-force scalar evaluation
        var evaluator = new DataQueryEvaluator();
        var scalar = evaluator.FilterBatch(rows, query);

        Assert.Equal(scalar.Count, vectorized.Count);
        for (int i = 0; i < scalar.Count; i++)
            Assert.Equal(scalar[i].Key, vectorized[i].Key);
    }

    // ── 9. EstimateResultRows ────────────────────────────────────────────────

    [Fact]
    public void EstimateResultRows_MultipliesSelectivities()
    {
        var statsMap = new Dictionary<string, ColumnStats>
        {
            ["A"] = new ColumnStats { RowCount = 1000, DistinctCount = 10 },  // 1/10
            ["B"] = new ColumnStats { RowCount = 1000, DistinctCount = 5 },   // 1/5
        };

        var clauses = new List<QueryClause>
        {
            new() { Field = "A", Operator = QueryOperator.Equals, Value = 1 },
            new() { Field = "B", Operator = QueryOperator.Equals, Value = 2 },
        };

        double est = QueryCostEstimator.EstimateResultRows(1000, clauses, statsMap);
        Assert.Equal(1000.0 * (1.0 / 10) * (1.0 / 5), est, 6);  // 20.0
    }

    // ── 10. ShouldUseColumnarPath ────────────────────────────────────────────

    [Fact]
    public void ShouldUseColumnarPath_ReturnsTrueForLargeTable()
    {
        var statsMap = new Dictionary<string, ColumnStats>
        {
            ["A"] = new ColumnStats { RowCount = 10000, DistinctCount = 100 },
        };
        var clauses = new List<QueryClause>
        {
            new() { Field = "A", Operator = QueryOperator.Equals, Value = 1 },
        };

        Assert.True(QueryCostEstimator.ShouldUseColumnarPath(10000, clauses, statsMap));
    }
}
