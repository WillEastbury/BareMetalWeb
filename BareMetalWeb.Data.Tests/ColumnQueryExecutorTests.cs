using System;
using System.Collections.Generic;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for <see cref="ColumnQueryExecutor"/> — the batch-vectorised column scan.
///
/// Tests are structured at three levels:
///   1. Eligibility check — correct threshold/shape gating.
///   2. Single-clause column scans — equality, range, NotEquals for int/long/double/string.
///   3. Multi-clause AND composition — bitmask intersection.
///   4. Pagination — skip/top.
///   5. Edge cases — empty result, all-match, below threshold (scalar fallback).
/// </summary>
[Collection("SharedState")]
public sealed class ColumnQueryExecutorTests : IDisposable
{
    // ── Minimal entity used in all tests ─────────────────────────────────

    [DataEntity("SampleItems")]
    private class SampleItem : BaseDataObject
    {
        public override string EntityTypeName => "SampleItems";
        private const int Ord_Age = BaseFieldCount + 0;
        private const int Ord_BigNum = BaseFieldCount + 1;
        private const int Ord_Name = BaseFieldCount + 2;
        private const int Ord_Ratio = BaseFieldCount + 3;
        private const int Ord_Score = BaseFieldCount + 4;
        internal new const int TotalFieldCount = BaseFieldCount + 5;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("Age", Ord_Age),
            new FieldSlot("BigNum", Ord_BigNum),
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Name", Ord_Name),
            new FieldSlot("Ratio", Ord_Ratio),
            new FieldSlot("Score", Ord_Score),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public SampleItem() : base(TotalFieldCount) { }
        public SampleItem(string createdBy) : base(TotalFieldCount, createdBy) { }

        [DataField]
        public string Name
        {
            get => (string?)_values[Ord_Name] ?? string.Empty;
            set => _values[Ord_Name] = value;
        }

        [DataField]
        public int Age
        {
            get => (int)(_values[Ord_Age] ?? 0);
            set => _values[Ord_Age] = value;
        }

        [DataField]
        public double Score
        {
            get => (double)(_values[Ord_Score] ?? 0.0);
            set => _values[Ord_Score] = value;
        }

        [DataField]
        public long BigNum
        {
            get => (long)(_values[Ord_BigNum] ?? 0L);
            set => _values[Ord_BigNum] = value;
        }

        [DataField]
        public float Ratio
        {
            get => (float)(_values[Ord_Ratio] ?? 0f);
            set => _values[Ord_Ratio] = value;
        }
    }

    private static readonly Random _rng = new(42); // reserved for future randomised test helpers

    public ColumnQueryExecutorTests()
    {
        DataScaffold.RegisterEntity<SampleItem>();
    }

    public void Dispose() { }

    // ── Test data helpers ──────────────────────────────────────────────────

    private static List<SampleItem> MakeRows(int count)
    {
        var list = new List<SampleItem>(count);
        for (int i = 0; i < count; i++)
        {
            list.Add(new SampleItem
            {
                Key    = (uint)(i + 1),
                Name   = i % 3 == 0 ? "Alice" : (i % 3 == 1 ? "Bob" : "Carol"),
                Age    = 20 + (i % 50),
                Score  = Math.Round(i * 0.5, 2),
                BigNum = (long)i * 1_000_000,
                Ratio  = i * 0.01f,
            });
        }
        return list;
    }

    // ── 1. Eligibility ────────────────────────────────────────────────────

    [Fact]
    public void IsEligible_BelowThreshold_ReturnsFalse()
    {
        var rows  = MakeRows(ColumnQueryExecutor.VectorizationThreshold - 1);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 } } };
        Assert.False(ColumnQueryExecutor.IsEligible(rows, query));
    }

    [Fact]
    public void IsEligible_AtThreshold_ReturnsTrue()
    {
        var rows  = MakeRows(ColumnQueryExecutor.VectorizationThreshold);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 } } };
        Assert.True(ColumnQueryExecutor.IsEligible(rows, query));
    }

    [Fact]
    public void IsEligible_WithNestedGroups_ReturnsFalse()
    {
        var rows  = MakeRows(1000);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 } },
            Groups  = { new QueryGroup() }
        };
        Assert.False(ColumnQueryExecutor.IsEligible(rows, query));
    }

    [Fact]
    public void IsEligible_NullQuery_ReturnsFalse()
    {
        var rows = MakeRows(1000);
        Assert.False(ColumnQueryExecutor.IsEligible(rows, null));
    }

    // ── 2. Int column scans ───────────────────────────────────────────────

    [Fact]
    public void Filter_IntEquals_ReturnsCorrectRows()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r => Assert.Equal(30, r.Age));
        // Every row with Age == 30: rows where (20 + i % 50) == 30, i.e. i % 50 == 10
        int expected = rows.Count(r => r.Age == 30);
        Assert.Equal(expected, result.Count);
    }

    [Fact]
    public void Filter_IntNotEquals_ExcludesMatchingRows()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.NotEquals, Value = 30 } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r => Assert.NotEqual(30, r.Age));
        int expected = rows.Count(r => r.Age != 30);
        Assert.Equal(expected, result.Count);
    }

    [Fact]
    public void Filter_IntGreaterThan_ReturnsCorrectRows()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThan, Value = 50 } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r => Assert.True(r.Age > 50));
        int expected = rows.Count(r => r.Age > 50);
        Assert.Equal(expected, result.Count);
    }

    [Fact]
    public void Filter_IntLessThan_ReturnsCorrectRows()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.LessThan, Value = 25 } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r => Assert.True(r.Age < 25));
        int expected = rows.Count(r => r.Age < 25);
        Assert.Equal(expected, result.Count);
    }

    [Fact]
    public void Filter_IntGreaterThanOrEqual_ReturnsCorrectRows()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThanOrEqual, Value = 60 } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r => Assert.True(r.Age >= 60));
        int expected = rows.Count(r => r.Age >= 60);
        Assert.Equal(expected, result.Count);
    }

    [Fact]
    public void Filter_IntLessThanOrEqual_ReturnsCorrectRows()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.LessThanOrEqual, Value = 22 } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r => Assert.True(r.Age <= 22));
        int expected = rows.Count(r => r.Age <= 22);
        Assert.Equal(expected, result.Count);
    }

    // ── 3. Long column scan ───────────────────────────────────────────────

    [Fact]
    public void Filter_LongEquals_ReturnsCorrectRows()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "BigNum", Operator = QueryOperator.Equals, Value = 10_000_000L } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r => Assert.Equal(10_000_000L, r.BigNum));
        int expected = rows.Count(r => r.BigNum == 10_000_000L);
        Assert.Equal(expected, result.Count);
    }

    [Fact]
    public void Filter_LongGreaterThan_ReturnsCorrectRows()
    {
        var rows  = MakeRows(512);
        const long threshold = 400_000_000L;
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "BigNum", Operator = QueryOperator.GreaterThan, Value = threshold } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r => Assert.True(r.BigNum > threshold));
        int expected = rows.Count(r => r.BigNum > threshold);
        Assert.Equal(expected, result.Count);
    }

    // ── 4. Double column scan ─────────────────────────────────────────────

    [Fact]
    public void Filter_DoubleEquals_ReturnsCorrectRows()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Score", Operator = QueryOperator.Equals, Value = 50.0 } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r => Assert.Equal(50.0, r.Score));
        int expected = rows.Count(r => r.Score == 50.0);
        Assert.Equal(expected, result.Count);
    }

    [Fact]
    public void Filter_DoubleLessThan_ReturnsCorrectRows()
    {
        var rows  = MakeRows(512);
        const double threshold = 10.0;
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Score", Operator = QueryOperator.LessThan, Value = threshold } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r => Assert.True(r.Score < threshold));
        int expected = rows.Count(r => r.Score < threshold);
        Assert.Equal(expected, result.Count);
    }

    // ── 5. String column (scalar fallback path) ───────────────────────────

    [Fact]
    public void Filter_StringEquals_ReturnsCorrectRows()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Alice" } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r => Assert.Equal("Alice", r.Name, StringComparer.OrdinalIgnoreCase));
        int expected = rows.Count(r => r.Name.Equals("Alice", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(expected, result.Count);
    }

    [Fact]
    public void Filter_StringContains_ReturnsCorrectRows()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Contains, Value = "ol" } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r => Assert.Contains("ol", r.Name, StringComparison.OrdinalIgnoreCase));
        int expected = rows.Count(r => r.Name.Contains("ol", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(expected, result.Count);
    }

    // ── 6. Multi-clause AND composition ──────────────────────────────────

    [Fact]
    public void Filter_TwoClauses_AndLogic_ReturnsIntersection()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition
        {
            Clauses =
            {
                new QueryClause { Field = "Age",   Operator = QueryOperator.GreaterThanOrEqual, Value = 40 },
                new QueryClause { Field = "Score", Operator = QueryOperator.LessThan,           Value = 100.0 },
            }
        };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r =>
        {
            Assert.True(r.Age   >= 40);
            Assert.True(r.Score <  100.0);
        });
        int expected = rows.Count(r => r.Age >= 40 && r.Score < 100.0);
        Assert.Equal(expected, result.Count);
    }

    [Fact]
    public void Filter_ThreeClauses_AndLogic_ReturnsIntersection()
    {
        var rows  = MakeRows(1024);
        var query = new QueryDefinition
        {
            Clauses =
            {
                new QueryClause { Field = "Name",   Operator = QueryOperator.Equals,      Value = "Bob"  },
                new QueryClause { Field = "Age",    Operator = QueryOperator.GreaterThan, Value = 30     },
                new QueryClause { Field = "BigNum", Operator = QueryOperator.LessThan,    Value = 500_000_000L },
            }
        };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.All(result, r =>
        {
            Assert.Equal("Bob", r.Name, StringComparer.OrdinalIgnoreCase);
            Assert.True(r.Age    > 30);
            Assert.True(r.BigNum < 500_000_000L);
        });
        int expected = rows.Count(r =>
            r.Name.Equals("Bob", StringComparison.OrdinalIgnoreCase)
            && r.Age    > 30
            && r.BigNum < 500_000_000L);
        Assert.Equal(expected, result.Count);
    }

    // ── 7. Empty-result short-circuit ─────────────────────────────────────

    [Fact]
    public void Filter_NoMatchingRows_ReturnsEmpty()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 999 } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.Empty(result);
    }

    // ── 8. All-match ──────────────────────────────────────────────────────

    [Fact]
    public void Filter_AllRowsMatch_ReturnsAllRows()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThanOrEqual, Value = 0 } } };
        var result = ColumnQueryExecutor.Filter(rows, query);
        Assert.Equal(rows.Count, result.Count);
    }

    // ── 9. Pagination ─────────────────────────────────────────────────────

    [Fact]
    public void Filter_SkipAndTop_ReturnsCorrectPage()
    {
        var rows  = MakeRows(512);
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThanOrEqual, Value = 0 } } };
        // Get all matching rows first, then compare a page.
        var all  = ColumnQueryExecutor.Filter(rows, query);
        var page = ColumnQueryExecutor.Filter(rows, query, skip: 10, top: 20);
        Assert.Equal(20, page.Count);
        for (int i = 0; i < page.Count; i++)
            Assert.Equal(all[10 + i].Key, page[i].Key);
    }

    [Fact]
    public void Filter_SkipBeyondResults_ReturnsEmpty()
    {
        var rows  = MakeRows(300);
        // Age == 30 has limited matches
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 } } };
        var all  = ColumnQueryExecutor.Filter(rows, query);
        var page = ColumnQueryExecutor.Filter(rows, query, skip: all.Count + 100, top: 10);
        Assert.Empty(page);
    }

    // ── 10. Correctness: results agree with scalar DataQueryEvaluator ──────

    [Fact]
    public void Filter_IntRange_MatchesScalarEvaluator()
    {
        var rows      = MakeRows(512);
        var evaluator = new DataQueryEvaluator();
        var query     = new QueryDefinition
        {
            Clauses =
            {
                new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThan,     Value = 35 },
                new QueryClause { Field = "Age", Operator = QueryOperator.LessThanOrEqual, Value = 55 },
            }
        };

        // Scalar reference
        var scalarResult = new List<SampleItem>();
        foreach (var r in rows)
            if (evaluator.Matches(r, query)) scalarResult.Add(r);

        // Vectorised result
        var vectorResult = ColumnQueryExecutor.Filter(rows, query);

        Assert.Equal(scalarResult.Count, vectorResult.Count);
        for (int i = 0; i < scalarResult.Count; i++)
            Assert.Equal(scalarResult[i].Key, vectorResult[i].Key);
    }

    [Fact]
    public void Filter_DoubleAndIntMixed_MatchesScalarEvaluator()
    {
        var rows      = MakeRows(512);
        var evaluator = new DataQueryEvaluator();
        var query     = new QueryDefinition
        {
            Clauses =
            {
                new QueryClause { Field = "Age",   Operator = QueryOperator.LessThan,          Value = 40  },
                new QueryClause { Field = "Score", Operator = QueryOperator.GreaterThanOrEqual, Value = 5.0 },
            }
        };

        var scalarResult = new List<SampleItem>();
        foreach (var r in rows)
            if (evaluator.Matches(r, query)) scalarResult.Add(r);

        var vectorResult = ColumnQueryExecutor.Filter(rows, query);

        Assert.Equal(scalarResult.Count, vectorResult.Count);
        for (int i = 0; i < scalarResult.Count; i++)
            Assert.Equal(scalarResult[i].Key, vectorResult[i].Key);
    }

    // ── 11. DataQueryEvaluator.FilterBatch delegates correctly ────────────

    [Fact]
    public void DataQueryEvaluator_FilterBatch_AboveThreshold_UsesVectorisedPath()
    {
        var rows      = MakeRows(ColumnQueryExecutor.VectorizationThreshold);
        var evaluator = new DataQueryEvaluator();
        var query     = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 } } };

        var result = evaluator.FilterBatch(rows, query);
        Assert.All(result, r => Assert.Equal(30, r.Age));
        int expected = rows.Count(r => r.Age == 30);
        Assert.Equal(expected, result.Count);
    }

    [Fact]
    public void DataQueryEvaluator_FilterBatch_BelowThreshold_UsesScalarPath()
    {
        var rows      = MakeRows(ColumnQueryExecutor.VectorizationThreshold - 1);
        var evaluator = new DataQueryEvaluator();
        var query     = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 } } };

        var result = evaluator.FilterBatch(rows, query);
        Assert.All(result, r => Assert.Equal(30, r.Age));
        int expected = rows.Count(r => r.Age == 30);
        Assert.Equal(expected, result.Count);
    }

    [Fact]
    public void DataQueryEvaluator_FilterBatch_NullQuery_ReturnsSlice()
    {
        var rows      = MakeRows(100);
        var evaluator = new DataQueryEvaluator();

        var result = evaluator.FilterBatch(rows, null, skip: 5, top: 10);
        Assert.Equal(10, result.Count);
        for (int i = 0; i < 10; i++)
            Assert.Equal(rows[5 + i].Key, result[i].Key);
    }

    // ── 12. DataLayerCapabilities reports column query path ───────────────

    [Fact]
    public void DataLayerCapabilities_Describe_ContainsColumnQuerySection()
    {
        string desc = DataLayerCapabilities.Describe();
        Assert.Contains("Column query scan", desc, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DataLayerCapabilities_ColumnQueryPath_IsNonEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(DataLayerCapabilities.ColumnQueryPath));
    }

    [Fact]
    public void DataLayerCapabilities_ColumnQueryPath_ContainsThreshold()
    {
        string path = DataLayerCapabilities.ColumnQueryPath;
        Assert.Contains(ColumnQueryExecutor.VectorizationThreshold.ToString(), path);
    }

    // ── ColumnarStore tests ──────────────────────────────────────────────────

    [Fact]
    public void ColumnarStore_Build_PopulatesIntColumn()
    {
        var rows = MakeRows(300);
        var meta = DataScaffold.GetEntityByType(typeof(SampleItem))!;
        var store = new ColumnarStore(rows.Count);

        store.Build(rows, meta);

        Assert.Equal(300, store.RowCount);
        Assert.True(store.HasColumn("Age"));
        Assert.True(store.HasColumn("Score"));
        Assert.True(store.HasColumn("BigNum"));
        Assert.True(store.HasColumn("Ratio"));
        Assert.False(store.HasColumn("Name")); // strings not stored
    }

    [Fact]
    public void ColumnarStore_ScanInt_EqualsMatchesColumnQueryExecutor()
    {
        var rows = MakeRows(512);
        var meta = DataScaffold.GetEntityByType(typeof(SampleItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        // Scan for Age == 25 via columnar store
        int wordCount = (store.RowCount + 63) >> 6;
        var bitmask = store.ScanClause("Age", QueryOperator.Equals, 25, wordCount);
        Assert.NotNull(bitmask);

        // Count matching rows from bitmask
        int columnarHits = 0;
        for (int i = 0; i < bitmask!.Length; i++)
            columnarHits += System.Numerics.BitOperations.PopCount(bitmask[i]);

        // Compare with ColumnQueryExecutor
        var query = new QueryDefinition { Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 25 } } };
        var cqeResult = ColumnQueryExecutor.Filter(rows, query);

        Assert.Equal(cqeResult.Count, columnarHits);
    }

    [Fact]
    public void ColumnarStore_ScanInt_GreaterThan()
    {
        var rows = MakeRows(512);
        var meta = DataScaffold.GetEntityByType(typeof(SampleItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        int wordCount = (store.RowCount + 63) >> 6;
        var bitmask = store.ScanClause("Age", QueryOperator.GreaterThan, 60, wordCount);
        Assert.NotNull(bitmask);

        int hits = 0;
        for (int i = 0; i < bitmask!.Length; i++)
            hits += System.Numerics.BitOperations.PopCount(bitmask[i]);

        // Age ranges 20-69 (20 + i%50), so >60 means ages 61-69 = values where i%50 ∈ [41..49]
        int expected = rows.Count(r => r.Age > 60);
        Assert.Equal(expected, hits);
    }

    [Fact]
    public void ColumnarStore_ScanDouble_LessThanOrEqual()
    {
        var rows = MakeRows(300);
        var meta = DataScaffold.GetEntityByType(typeof(SampleItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        int wordCount = (store.RowCount + 63) >> 6;
        var bitmask = store.ScanClause("Score", QueryOperator.LessThanOrEqual, 10.0, wordCount);
        Assert.NotNull(bitmask);

        int hits = 0;
        for (int i = 0; i < bitmask!.Length; i++)
            hits += System.Numerics.BitOperations.PopCount(bitmask[i]);

        int expected = rows.Count(r => r.Score <= 10.0);
        Assert.Equal(expected, hits);
    }

    [Fact]
    public void ColumnarStore_ScanLong_NotEquals()
    {
        var rows = MakeRows(300);
        var meta = DataScaffold.GetEntityByType(typeof(SampleItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        int wordCount = (store.RowCount + 63) >> 6;
        var bitmask = store.ScanClause("BigNum", QueryOperator.NotEquals, 0L, wordCount);
        Assert.NotNull(bitmask);

        int hits = 0;
        for (int i = 0; i < bitmask!.Length; i++)
            hits += System.Numerics.BitOperations.PopCount(bitmask[i]);

        // Row 0 has BigNum=0, rest are non-zero
        int expected = rows.Count(r => r.BigNum != 0);
        Assert.Equal(expected, hits);
    }

    [Fact]
    public void ColumnarStore_ScanNonexistentField_ReturnsNull()
    {
        var rows = MakeRows(300);
        var meta = DataScaffold.GetEntityByType(typeof(SampleItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        int wordCount = (store.RowCount + 63) >> 6;
        var result = store.ScanClause("NonExistent", QueryOperator.Equals, 42, wordCount);
        Assert.Null(result);
    }

    [Fact]
    public void ColumnarStore_Invalidate_IncrementsVersion()
    {
        var rows = MakeRows(300);
        var meta = DataScaffold.GetEntityByType(typeof(SampleItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        long v1 = store.Version;
        store.Invalidate();
        long v2 = store.Version;

        Assert.True(v2 > v1);
    }

    [Fact]
    public void ColumnarStore_GetKeyAtRow_MatchesOriginal()
    {
        var rows = MakeRows(300);
        var meta = DataScaffold.GetEntityByType(typeof(SampleItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        for (int i = 0; i < rows.Count; i++)
            Assert.Equal(rows[i].Key, store.GetKeyAtRow(i));
    }

    [Fact]
    public void ColumnarStore_MultiClause_AndComposition()
    {
        var rows = MakeRows(512);
        var meta = DataScaffold.GetEntityByType(typeof(SampleItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        int n = store.RowCount;
        int wordCount = (n + 63) >> 6;

        // Age > 30 AND Score < 50.0
        var mask1 = store.ScanClause("Age", QueryOperator.GreaterThan, 30, wordCount)!;
        var mask2 = store.ScanClause("Score", QueryOperator.LessThan, 50.0, wordCount)!;

        // AND in place
        for (int i = 0; i < wordCount; i++) mask1[i] &= mask2[i];

        int hits = 0;
        for (int i = 0; i < mask1.Length; i++)
            hits += System.Numerics.BitOperations.PopCount(mask1[i]);

        int expected = rows.Count(r => r.Age > 30 && r.Score < 50.0);
        Assert.Equal(expected, hits);
    }
}
