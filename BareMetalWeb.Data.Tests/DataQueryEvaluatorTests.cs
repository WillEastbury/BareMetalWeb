using System;
using System.Collections.Generic;
using System.Linq;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[Collection("SharedState")]
public class DataQueryEvaluatorTests : IDisposable
{
    [DataEntity("TestItems")]
    private class TestItem : BaseDataObject
    {
        private const int Ord_Age = BaseFieldCount + 0;
        private const int Ord_Name = BaseFieldCount + 1;
        private const int Ord_NullableField = BaseFieldCount + 2;
        private const int Ord_Price = BaseFieldCount + 3;
        private const int Ord_Tags = BaseFieldCount + 4;
        internal new const int TotalFieldCount = BaseFieldCount + 5;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("Age", Ord_Age),
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Name", Ord_Name),
            new FieldSlot("NullableField", Ord_NullableField),
            new FieldSlot("Price", Ord_Price),
            new FieldSlot("Tags", Ord_Tags),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TestItem() : base(TotalFieldCount) { }
        public TestItem(string createdBy) : base(TotalFieldCount, createdBy) { }

        public string Name
        {
            get => (string?)_values[Ord_Name] ?? string.Empty;
            set => _values[Ord_Name] = value;
        }

        public int Age
        {
            get => (int)(_values[Ord_Age] ?? 0);
            set => _values[Ord_Age] = value;
        }

        public decimal Price
        {
            get => (decimal)(_values[Ord_Price] ?? 0m);
            set => _values[Ord_Price] = value;
        }

        public string? NullableField
        {
            get => (string?)_values[Ord_NullableField];
            set => _values[Ord_NullableField] = value;
        }

        public List<string> Tags
        {
            get => (List<string>?)_values[Ord_Tags] ?? new();
            set => _values[Ord_Tags] = value;
        }
    }

    private readonly DataQueryEvaluator _evaluator = new();

    public DataQueryEvaluatorTests()
    {
        DataScaffold.RegisterEntity<TestItem>();
    }

    public void Dispose() { }

    private TestItem CreateItem(string name = "Alice", int age = 30, decimal price = 9.99m,
        string? nullableField = null, List<string>? tags = null)
    {
        return new TestItem
        {
            Name = name,
            Age = age,
            Price = price,
            NullableField = nullableField,
            Tags = tags ?? new List<string>()
        };
    }

    // ── Null / empty query ──────────────────────────────────────────

    [Fact]
    public void Matches_NullQuery_ReturnsTrue()
    {
        var item = CreateItem();
        Assert.True(_evaluator.Matches(item, null));
    }

    [Fact]
    public void Matches_EmptyQuery_ReturnsTrue()
    {
        var item = CreateItem();
        var query = new QueryDefinition();
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── Equals ──────────────────────────────────────────────────────

    [Fact]
    public void Equals_StringMatch_ReturnsTrue()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Alice" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Equals_StringMismatch_ReturnsFalse()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Bob" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Equals_StringIsCaseInsensitive()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "alice" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Equals_IntMatch_ReturnsTrue()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Equals_IntFromString_ReturnsTrue()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = "30" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── NotEquals ───────────────────────────────────────────────────

    [Fact]
    public void NotEquals_DifferentValue_ReturnsTrue()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.NotEquals, Value = "Bob" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void NotEquals_SameValue_ReturnsFalse()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.NotEquals, Value = "Alice" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── Contains ────────────────────────────────────────────────────

    [Fact]
    public void Contains_SubstringMatch_ReturnsTrue()
    {
        var item = CreateItem("Alice Wonderland");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Contains, Value = "Wonder" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Contains_SubstringCaseInsensitive_ReturnsTrue()
    {
        var item = CreateItem("Alice Wonderland");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Contains, Value = "wonder" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Contains_SubstringMismatch_ReturnsFalse()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Contains, Value = "Bob" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Contains_NullMemberValue_ReturnsFalse()
    {
        var item = CreateItem(nullableField: null);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "NullableField", Operator = QueryOperator.Contains, Value = "x" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── StartsWith ──────────────────────────────────────────────────

    [Fact]
    public void StartsWith_PrefixMatch_ReturnsTrue()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.StartsWith, Value = "Ali" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void StartsWith_CaseInsensitive_ReturnsTrue()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.StartsWith, Value = "ali" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void StartsWith_Mismatch_ReturnsFalse()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.StartsWith, Value = "Bob" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── EndsWith ────────────────────────────────────────────────────

    [Fact]
    public void EndsWith_SuffixMatch_ReturnsTrue()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.EndsWith, Value = "ice" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void EndsWith_CaseInsensitive_ReturnsTrue()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.EndsWith, Value = "ICE" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void EndsWith_Mismatch_ReturnsFalse()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.EndsWith, Value = "xyz" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── GreaterThan / LessThan ──────────────────────────────────────

    [Fact]
    public void GreaterThan_WhenGreater_ReturnsTrue()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThan, Value = 20 } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void GreaterThan_WhenEqual_ReturnsFalse()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThan, Value = 30 } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void LessThan_WhenLess_ReturnsTrue()
    {
        var item = CreateItem(age: 20);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.LessThan, Value = 30 } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void LessThan_WhenEqual_ReturnsFalse()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.LessThan, Value = 30 } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── GreaterThanOrEqual / LessThanOrEqual ────────────────────────

    [Fact]
    public void GreaterThanOrEqual_WhenEqual_ReturnsTrue()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThanOrEqual, Value = 30 } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void GreaterThanOrEqual_WhenLess_ReturnsFalse()
    {
        var item = CreateItem(age: 20);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThanOrEqual, Value = 30 } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void LessThanOrEqual_WhenEqual_ReturnsTrue()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.LessThanOrEqual, Value = 30 } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void LessThanOrEqual_WhenGreater_ReturnsFalse()
    {
        var item = CreateItem(age: 40);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.LessThanOrEqual, Value = 30 } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── In / NotIn ──────────────────────────────────────────────────

    [Fact]
    public void In_ValueInCommaSeparatedList_ReturnsTrue()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.In, Value = "Alice,Bob,Charlie" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void In_ValueNotInList_ReturnsFalse()
    {
        var item = CreateItem("Dave");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.In, Value = "Alice,Bob,Charlie" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void In_BracketSyntax_ReturnsTrue()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.In, Value = "[10, 20, 30]" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void NotIn_ValueNotInList_ReturnsTrue()
    {
        var item = CreateItem("Dave");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.NotIn, Value = "Alice,Bob" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void NotIn_ValueInList_ReturnsFalse()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.NotIn, Value = "Alice,Bob" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── Null / empty field handling ─────────────────────────────────

    [Fact]
    public void Equals_NullFieldValue_NullTarget_ReturnsTrue()
    {
        var item = CreateItem(nullableField: null);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "NullableField", Operator = QueryOperator.Equals, Value = null } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Equals_NullFieldValue_NonNullTarget_ReturnsFalse()
    {
        var item = CreateItem(nullableField: null);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "NullableField", Operator = QueryOperator.Equals, Value = "something" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Clause_EmptyFieldName_ReturnsFalse()
    {
        var item = CreateItem();
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "", Operator = QueryOperator.Equals, Value = "x" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Clause_WhitespaceFieldName_ReturnsFalse()
    {
        var item = CreateItem();
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "   ", Operator = QueryOperator.Equals, Value = "x" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Clause_NonExistentField_ReturnsFalse()
    {
        var item = CreateItem();
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "DoesNotExist", Operator = QueryOperator.Equals, Value = "x" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── Case-insensitive field lookup ───────────────────────────────

    [Fact]
    public void FieldName_IsCaseInsensitive()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "name", Operator = QueryOperator.Equals, Value = "Alice" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── AND logic (multiple clauses) ────────────────────────────────

    [Fact]
    public void AndLogic_AllClausesMatch_ReturnsTrue()
    {
        var item = CreateItem("Alice", 30);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.And,
            Clauses =
            {
                new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Alice" },
                new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 }
            }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void AndLogic_OneClauseFails_ReturnsFalse()
    {
        var item = CreateItem("Alice", 30);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.And,
            Clauses =
            {
                new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Alice" },
                new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 99 }
            }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── OR logic (multiple clauses) ─────────────────────────────────

    [Fact]
    public void OrLogic_OneClauseMatches_ReturnsTrue()
    {
        var item = CreateItem("Alice", 30);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.Or,
            Clauses =
            {
                new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Bob" },
                new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 }
            }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void OrLogic_NoClausesMatch_ReturnsFalse()
    {
        var item = CreateItem("Alice", 30);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.Or,
            Clauses =
            {
                new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Bob" },
                new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 99 }
            }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── QueryGroup nesting ──────────────────────────────────────────

    [Fact]
    public void NestedGroup_AndWithOrSubgroup_MatchesCorrectly()
    {
        // (Name == "Alice") AND (Age == 30 OR Age == 40)
        var item = CreateItem("Alice", 30);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.And,
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Alice" } },
            Groups =
            {
                new QueryGroup
                {
                    Logic = QueryGroupLogic.Or,
                    Clauses =
                    {
                        new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 },
                        new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 40 }
                    }
                }
            }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void NestedGroup_AndWithFailingSubgroup_ReturnsFalse()
    {
        // (Name == "Alice") AND (Age == 50 OR Age == 60) → false
        var item = CreateItem("Alice", 30);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.And,
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Alice" } },
            Groups =
            {
                new QueryGroup
                {
                    Logic = QueryGroupLogic.Or,
                    Clauses =
                    {
                        new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 50 },
                        new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 60 }
                    }
                }
            }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void NestedGroup_OrWithMatchingSubgroup_ReturnsTrue()
    {
        // (Name == "Bob") OR (Age == 30 AND Name == "Alice")
        var item = CreateItem("Alice", 30);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.Or,
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Bob" } },
            Groups =
            {
                new QueryGroup
                {
                    Logic = QueryGroupLogic.And,
                    Clauses =
                    {
                        new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 },
                        new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Alice" }
                    }
                }
            }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void NestedGroup_DeeplyNested_EvaluatesRecursively()
    {
        // AND( Name=="Alice", OR( AND(Age==30, Price>5), Age==99 ) )
        var item = CreateItem("Alice", 30, 9.99m);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.And,
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Alice" } },
            Groups =
            {
                new QueryGroup
                {
                    Logic = QueryGroupLogic.Or,
                    Groups =
                    {
                        new QueryGroup
                        {
                            Logic = QueryGroupLogic.And,
                            Clauses =
                            {
                                new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 },
                                new QueryClause { Field = "Price", Operator = QueryOperator.GreaterThan, Value = 5m }
                            }
                        }
                    },
                    Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 99 } }
                }
            }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── Edge cases: filtering collections ───────────────────────────

    [Fact]
    public void Matches_AllRecordsMatch_ReturnsAll()
    {
        var items = new[]
        {
            CreateItem("Alice", 30),
            CreateItem("Bob", 25),
            CreateItem("Charlie", 35)
        };
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThan, Value = 0 } }
        };

        var results = items.Where(i => _evaluator.Matches(i, query)).ToList();
        Assert.Equal(3, results.Count);
    }

    [Fact]
    public void Matches_NoRecordsMatch_ReturnsEmpty()
    {
        var items = new[]
        {
            CreateItem("Alice", 30),
            CreateItem("Bob", 25)
        };
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThan, Value = 100 } }
        };

        var results = items.Where(i => _evaluator.Matches(i, query)).ToList();
        Assert.Empty(results);
    }

    [Fact]
    public void Matches_SomeRecordsMatch_ReturnsSubset()
    {
        var items = new[]
        {
            CreateItem("Alice", 30),
            CreateItem("Bob", 25),
            CreateItem("Charlie", 35)
        };
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThanOrEqual, Value = 30 } }
        };

        var results = items.Where(i => _evaluator.Matches(i, query)).ToList();
        Assert.Equal(2, results.Count);
        Assert.All(results, r => Assert.True(r.Age >= 30));
    }

    // ── Decimal comparisons ─────────────────────────────────────────

    [Fact]
    public void GreaterThan_Decimal_ReturnsTrue()
    {
        var item = CreateItem(price: 15.50m);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Price", Operator = QueryOperator.GreaterThan, Value = "10.00" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void LessThan_Decimal_ReturnsTrue()
    {
        var item = CreateItem(price: 5.00m);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Price", Operator = QueryOperator.LessThan, Value = "10.00" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── ApplySorts ──────────────────────────────────────────────────

    [Fact]
    public void ApplySorts_NullQuery_ReturnsSameOrder()
    {
        var items = new[] { CreateItem("B"), CreateItem("A"), CreateItem("C") };
        var result = _evaluator.ApplySorts(items, null).ToList();
        Assert.Equal("B", result[0].Name);
        Assert.Equal("A", result[1].Name);
        Assert.Equal("C", result[2].Name);
    }

    [Fact]
    public void ApplySorts_AscendingByName_SortsCorrectly()
    {
        var items = new[] { CreateItem("Charlie"), CreateItem("Alice"), CreateItem("Bob") };
        var query = new QueryDefinition
        {
            Sorts = { new SortClause { Field = "Name", Direction = SortDirection.Asc } }
        };
        var result = _evaluator.ApplySorts(items, query).ToList();
        Assert.Equal("Alice", result[0].Name);
        Assert.Equal("Bob", result[1].Name);
        Assert.Equal("Charlie", result[2].Name);
    }

    [Fact]
    public void ApplySorts_DescendingByAge_SortsCorrectly()
    {
        var items = new[] { CreateItem(age: 20), CreateItem(age: 40), CreateItem(age: 30) };
        var query = new QueryDefinition
        {
            Sorts = { new SortClause { Field = "Age", Direction = SortDirection.Desc } }
        };
        var result = _evaluator.ApplySorts(items, query).ToList();
        Assert.Equal(40, result[0].Age);
        Assert.Equal(30, result[1].Age);
        Assert.Equal(20, result[2].Age);
    }

    [Fact]
    public void ApplySorts_MultipleSorts_AppliesThenBy()
    {
        var items = new[]
        {
            CreateItem("Alice", 30),
            CreateItem("Alice", 20),
            CreateItem("Bob", 25)
        };
        var query = new QueryDefinition
        {
            Sorts =
            {
                new SortClause { Field = "Name", Direction = SortDirection.Asc },
                new SortClause { Field = "Age", Direction = SortDirection.Asc }
            }
        };
        var result = _evaluator.ApplySorts(items, query).ToList();
        Assert.Equal("Alice", result[0].Name);
        Assert.Equal(20, result[0].Age);
        Assert.Equal("Alice", result[1].Name);
        Assert.Equal(30, result[1].Age);
        Assert.Equal("Bob", result[2].Name);
    }

    [Fact]
    public void ApplySorts_EmptySortsList_ReturnsSameOrder()
    {
        var items = new[] { CreateItem("B"), CreateItem("A") };
        var query = new QueryDefinition();
        var result = _evaluator.ApplySorts(items, query).ToList();
        Assert.Equal("B", result[0].Name);
        Assert.Equal("A", result[1].Name);
    }

    // ── StartsWith / EndsWith on null values ────────────────────────

    [Fact]
    public void StartsWith_NullMemberValue_ReturnsFalse()
    {
        var item = CreateItem(nullableField: null);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "NullableField", Operator = QueryOperator.StartsWith, Value = "x" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void EndsWith_NullMemberValue_ReturnsFalse()
    {
        var item = CreateItem(nullableField: null);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "NullableField", Operator = QueryOperator.EndsWith, Value = "x" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── In with null value ──────────────────────────────────────────

    [Fact]
    public void In_NullRawValue_ReturnsFalse()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.In, Value = null } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── OR logic with empty clauses and groups ──────────────────────

    [Fact]
    public void OrLogic_NoClauses_NoGroups_ReturnsFalse()
    {
        var item = CreateItem();
        var query = new QueryDefinition { Logic = QueryGroupLogic.Or };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void AndLogic_NoClauses_NoGroups_ReturnsTrue()
    {
        var item = CreateItem();
        var query = new QueryDefinition { Logic = QueryGroupLogic.And };
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── Debug hook ──────────────────────────────────────────────────

    [Fact]
    public void DebugHook_CalledOnMissingField()
    {
        var messages = new List<string>();
        var evaluator = new DataQueryEvaluator(msg => messages.Add(msg));
        var item = CreateItem();
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Missing", Operator = QueryOperator.Equals, Value = "x" } }
        };

        evaluator.Matches(item, query);

        Assert.Single(messages);
        Assert.Contains("Missing", messages[0]);
    }

    // ── NotEquals – additional coverage ─────────────────────────────

    [Fact]
    public void NotEquals_IntDifferentValue_ReturnsTrue()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.NotEquals, Value = 99 } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void NotEquals_IntSameValue_ReturnsFalse()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.NotEquals, Value = 30 } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void NotEquals_CaseInsensitiveString_ReturnsFalse()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.NotEquals, Value = "alice" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void NotEquals_NullFieldNonNullTarget_ReturnsTrue()
    {
        var item = CreateItem(nullableField: null);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "NullableField", Operator = QueryOperator.NotEquals, Value = "something" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void NotEquals_NullFieldNullTarget_ReturnsFalse()
    {
        var item = CreateItem(nullableField: null);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "NullableField", Operator = QueryOperator.NotEquals, Value = null } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── Equals – decimal coercion ───────────────────────────────────

    [Fact]
    public void Equals_DecimalMatch_ReturnsTrue()
    {
        var item = CreateItem(price: 9.99m);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Price", Operator = QueryOperator.Equals, Value = 9.99m } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Equals_DecimalFromString_ReturnsTrue()
    {
        var item = CreateItem(price: 9.99m);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Price", Operator = QueryOperator.Equals, Value = "9.99" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── Contains – collection member ────────────────────────────────

    [Fact]
    public void Contains_ListContainsValue_ReturnsTrue()
    {
        var item = CreateItem(tags: new List<string> { "alpha", "beta", "gamma" });
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Tags", Operator = QueryOperator.Contains, Value = "beta" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Contains_ListDoesNotContainValue_ReturnsFalse()
    {
        var item = CreateItem(tags: new List<string> { "alpha", "beta" });
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Tags", Operator = QueryOperator.Contains, Value = "delta" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void Contains_NullTargetValue_ReturnsFalse()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Contains, Value = null } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── GreaterThan / LessThan – string coercion & string comparison ─

    [Fact]
    public void GreaterThan_IntFromString_ReturnsTrue()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThan, Value = "20" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void LessThan_IntFromString_ReturnsTrue()
    {
        var item = CreateItem(age: 20);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.LessThan, Value = "30" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void GreaterThan_WhenLess_ReturnsFalse()
    {
        var item = CreateItem(age: 10);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThan, Value = 20 } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void LessThan_WhenGreater_ReturnsFalse()
    {
        var item = CreateItem(age: 40);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.LessThan, Value = 30 } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void GreaterThan_StringComparison_ReturnsTrue()
    {
        var item = CreateItem("banana");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.GreaterThan, Value = "apple" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void LessThan_StringComparison_ReturnsTrue()
    {
        var item = CreateItem("apple");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.LessThan, Value = "banana" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── GreaterThanOrEqual / LessThanOrEqual – additional boundary ──

    [Fact]
    public void GreaterThanOrEqual_WhenGreater_ReturnsTrue()
    {
        var item = CreateItem(age: 40);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThanOrEqual, Value = 30 } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void LessThanOrEqual_WhenLess_ReturnsTrue()
    {
        var item = CreateItem(age: 20);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.LessThanOrEqual, Value = 30 } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void GreaterThanOrEqual_DecimalFromString_ReturnsTrue()
    {
        var item = CreateItem(price: 10.00m);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Price", Operator = QueryOperator.GreaterThanOrEqual, Value = "10.00" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void LessThanOrEqual_DecimalFromString_ReturnsTrue()
    {
        var item = CreateItem(price: 10.00m);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Price", Operator = QueryOperator.LessThanOrEqual, Value = "10.00" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── Comparison with null values ─────────────────────────────────

    [Fact]
    public void GreaterThan_NullFieldValue_ReturnsFalse()
    {
        var item = CreateItem(nullableField: null);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "NullableField", Operator = QueryOperator.GreaterThan, Value = "a" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void LessThan_NullFieldValue_ReturnsTrue()
    {
        var item = CreateItem(nullableField: null);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "NullableField", Operator = QueryOperator.LessThan, Value = "a" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── In / NotIn – additional formats ─────────────────────────────

    [Fact]
    public void In_QuotedBracketSyntax_ReturnsTrue()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.In, Value = "[\"Alice\", \"Bob\"]" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void In_EmptyBracketList_ReturnsFalse()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.In, Value = "[]" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void In_IntCommaSeparated_ReturnsTrue()
    {
        var item = CreateItem(age: 25);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.In, Value = "20,25,30" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void In_IntCommaSeparated_ReturnsFalse()
    {
        var item = CreateItem(age: 99);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.In, Value = "20,25,30" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void NotIn_BracketSyntax_ReturnsTrue()
    {
        var item = CreateItem("Dave");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.NotIn, Value = "[Alice, Bob]" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void NotIn_NullRawValue_ReturnsTrue()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.NotIn, Value = null } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── AND / OR logic – groups only (no top-level clauses) ─────────

    [Fact]
    public void AndLogic_GroupsOnly_AllMatch_ReturnsTrue()
    {
        var item = CreateItem("Alice", 30);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.And,
            Groups =
            {
                new QueryGroup
                {
                    Logic = QueryGroupLogic.And,
                    Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Alice" } }
                },
                new QueryGroup
                {
                    Logic = QueryGroupLogic.And,
                    Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 } }
                }
            }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void AndLogic_GroupsOnly_OneFails_ReturnsFalse()
    {
        var item = CreateItem("Alice", 30);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.And,
            Groups =
            {
                new QueryGroup
                {
                    Logic = QueryGroupLogic.And,
                    Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Alice" } }
                },
                new QueryGroup
                {
                    Logic = QueryGroupLogic.And,
                    Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 99 } }
                }
            }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void OrLogic_GroupsOnly_OneMatches_ReturnsTrue()
    {
        var item = CreateItem("Alice", 30);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.Or,
            Groups =
            {
                new QueryGroup
                {
                    Logic = QueryGroupLogic.And,
                    Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Bob" } }
                },
                new QueryGroup
                {
                    Logic = QueryGroupLogic.And,
                    Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 30 } }
                }
            }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void OrLogic_GroupsOnly_NoneMatch_ReturnsFalse()
    {
        var item = CreateItem("Alice", 30);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.Or,
            Groups =
            {
                new QueryGroup
                {
                    Logic = QueryGroupLogic.And,
                    Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Bob" } }
                },
                new QueryGroup
                {
                    Logic = QueryGroupLogic.And,
                    Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 99 } }
                }
            }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── Nested group: OR with both failing clause and subgroup ───────

    [Fact]
    public void NestedGroup_OrTopLevel_AllFail_ReturnsFalse()
    {
        var item = CreateItem("Alice", 30);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.Or,
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Bob" } },
            Groups =
            {
                new QueryGroup
                {
                    Logic = QueryGroupLogic.And,
                    Clauses =
                    {
                        new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Charlie" },
                        new QueryClause { Field = "Age", Operator = QueryOperator.Equals, Value = 99 }
                    }
                }
            }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── ApplySorts – whitespace field skipped ────────────────────────

    [Fact]
    public void ApplySorts_WhitespaceField_ReturnsSameOrder()
    {
        var items = new[] { CreateItem("B"), CreateItem("A") };
        var query = new QueryDefinition
        {
            Sorts = { new SortClause { Field = "   ", Direction = SortDirection.Asc } }
        };
        var result = _evaluator.ApplySorts(items, query).ToList();
        Assert.Equal("B", result[0].Name);
        Assert.Equal("A", result[1].Name);
    }

    // ── Edge case: single-item collection ───────────────────────────

    [Fact]
    public void Matches_SingleItemMatch_ReturnsSingleResult()
    {
        var items = new[] { CreateItem("Alice", 30) };
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Alice" } }
        };

        var results = items.Where(i => _evaluator.Matches(i, query)).ToList();
        Assert.Single(results);
    }

    [Fact]
    public void Matches_SingleItemNoMatch_ReturnsEmpty()
    {
        var items = new[] { CreateItem("Alice", 30) };
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.Equals, Value = "Bob" } }
        };

        var results = items.Where(i => _evaluator.Matches(i, query)).ToList();
        Assert.Empty(results);
    }

    // ── Equals non-null field with null target ──────────────────────

    [Fact]
    public void Equals_NonNullFieldValue_NullTarget_ReturnsFalse()
    {
        var item = CreateItem(nullableField: "hello");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "NullableField", Operator = QueryOperator.Equals, Value = null } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── StartsWith / EndsWith on non-string type ────────────────────

    [Fact]
    public void StartsWith_NonStringType_ReturnsFalse()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.StartsWith, Value = "3" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    [Fact]
    public void EndsWith_NonStringType_ReturnsFalse()
    {
        var item = CreateItem(age: 30);
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Age", Operator = QueryOperator.EndsWith, Value = "0" } }
        };
        Assert.False(_evaluator.Matches(item, query));
    }

    // ── Contains on list – case insensitive ─────────────────────────

    [Fact]
    public void Contains_ListCaseInsensitive_ReturnsTrue()
    {
        var item = CreateItem(tags: new List<string> { "Alpha", "Beta" });
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Tags", Operator = QueryOperator.Contains, Value = "alpha" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── In with single-quoted bracket tokens ────────────────────────

    [Fact]
    public void In_SingleQuotedBracketSyntax_ReturnsTrue()
    {
        var item = CreateItem("Alice");
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Name", Operator = QueryOperator.In, Value = "['Alice', 'Bob']" } }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    // ── Multiple operators combined with AND ────────────────────────

    [Fact]
    public void AndLogic_MixedOperators_AllMatch_ReturnsTrue()
    {
        var item = CreateItem("Alice Wonderland", 30, 9.99m);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.And,
            Clauses =
            {
                new QueryClause { Field = "Name", Operator = QueryOperator.StartsWith, Value = "Alice" },
                new QueryClause { Field = "Name", Operator = QueryOperator.Contains, Value = "Wonder" },
                new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThanOrEqual, Value = 30 },
                new QueryClause { Field = "Price", Operator = QueryOperator.LessThan, Value = 20m }
            }
        };
        Assert.True(_evaluator.Matches(item, query));
    }

    [Fact]
    public void AndLogic_MixedOperators_OneFails_ReturnsFalse()
    {
        var item = CreateItem("Alice Wonderland", 30, 9.99m);
        var query = new QueryDefinition
        {
            Logic = QueryGroupLogic.And,
            Clauses =
            {
                new QueryClause { Field = "Name", Operator = QueryOperator.StartsWith, Value = "Alice" },
                new QueryClause { Field = "Name", Operator = QueryOperator.Contains, Value = "Wonder" },
                new QueryClause { Field = "Age", Operator = QueryOperator.GreaterThan, Value = 30 }
            }
        };
        Assert.False(_evaluator.Matches(item, query));
    }
}
