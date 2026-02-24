using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Data.ExpressionEngine;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for expression engine relationship traversal: dot-notation, RelatedLookup, and QueryLookup.
/// </summary>
public class ExpressionRelationshipTests
{
    // ── Test lookup resolver ──────────────────────────────────────────────────

    /// <summary>
    /// In-memory resolver for unit testing without DataScaffold.
    /// </summary>
    private sealed class TestLookupResolver : ILookupResolver
    {
        // FK field name → (target field name → value)
        public Dictionary<string, Dictionary<string, object?>> RelatedEntities { get; } = new();

        // entity slug → list of records (each record is field→value dict)
        public Dictionary<string, List<Dictionary<string, object?>>> EntityData { get; } = new();

        public ValueTask<object?> ResolveRelatedFieldAsync(
            string currentEntitySlug,
            string foreignKeyField,
            string targetField,
            IReadOnlyDictionary<string, object?> context,
            CancellationToken cancellationToken = default)
        {
            if (!context.TryGetValue(foreignKeyField, out var fkValue) || fkValue == null)
                return new ValueTask<object?>((object?)null);

            var key = foreignKeyField + ":" + fkValue;
            if (RelatedEntities.TryGetValue(key, out var fields) &&
                fields.TryGetValue(targetField, out var value))
                return new ValueTask<object?>(value);

            return new ValueTask<object?>((object?)null);
        }

        public ValueTask<object?> QueryLookupAsync(
            string entitySlug,
            IReadOnlyList<(string Field, object? Value)> filters,
            string returnField,
            CancellationToken cancellationToken = default)
        {
            if (!EntityData.TryGetValue(entitySlug, out var records))
                return new ValueTask<object?>((object?)null);

            foreach (var record in records)
            {
                bool matches = true;
                foreach (var (field, value) in filters)
                {
                    if (!record.TryGetValue(field, out var recordValue) ||
                        !string.Equals(recordValue?.ToString(), value?.ToString(), StringComparison.OrdinalIgnoreCase))
                    {
                        matches = false;
                        break;
                    }
                }
                if (matches && record.TryGetValue(returnField, out var result))
                    return new ValueTask<object?>(result);
            }

            return new ValueTask<object?>((object?)null);
        }
    }

    // ── Parser: dot-notation ────────────────────────────────────────────────

    [Fact]
    public void Parser_DotNotation_ParsesToDotAccessNode()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("Customer.DiscountLevel");

        var dotNode = Assert.IsType<DotAccessNode>(ast);
        Assert.Equal("Customer", dotNode.LookupField);
        Assert.Single(dotNode.Path);
        Assert.Equal("DiscountLevel", dotNode.Path[0]);
    }

    [Fact]
    public void Parser_DotNotation_InArithmeticExpression()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("UnitPrice * (1 - CustomerId.DiscountLevel)");

        // Should parse without error; the dot access is inside a binary expression
        Assert.IsType<BinaryOpNode>(ast);
    }

    [Fact]
    public void Parser_RelatedLookup_ParsesAsFunctionNode()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("RelatedLookup('CustomerId', 'DiscountLevel')");

        var fn = Assert.IsType<FunctionNode>(ast);
        Assert.Equal("RelatedLookup", fn.FunctionName);
        Assert.Equal(2, fn.Arguments.Count);
    }

    [Fact]
    public void Parser_QueryLookup_ParsesAsFunctionNode()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("QueryLookup('pricingdata', 'CustomerID', CustomerId, 'ProductID', ProductId, 'DiscountPercentage')");

        var fn = Assert.IsType<FunctionNode>(ast);
        Assert.Equal("QueryLookup", fn.FunctionName);
        Assert.Equal(6, fn.Arguments.Count);
    }

    // ── DotAccessNode async evaluation ──────────────────────────────────────

    [Fact]
    public async Task DotAccess_ResolvesRelatedField()
    {
        var resolver = new TestLookupResolver();
        resolver.RelatedEntities["CustomerId:cust-1"] = new Dictionary<string, object?>
        {
            ["DiscountLevel"] = 0.15m,
            ["Name"] = "Acme Corp"
        };

        var context = new Dictionary<string, object?>
        {
            ["__entitySlug"] = "orders",
            ["CustomerId"] = "cust-1",
            ["Amount"] = 100m
        };

        var parser = new ExpressionParser();
        var ast = parser.Parse("CustomerId.DiscountLevel");

        var result = await ast.EvaluateAsync(context, resolver);
        Assert.Equal(0.15m, result);
    }

    [Fact]
    public async Task DotAccess_ReturnsNull_WhenFkIsNull()
    {
        var resolver = new TestLookupResolver();
        var context = new Dictionary<string, object?>
        {
            ["__entitySlug"] = "orders",
            ["CustomerId"] = null
        };

        var parser = new ExpressionParser();
        var ast = parser.Parse("CustomerId.Name");

        var result = await ast.EvaluateAsync(context, resolver);
        Assert.Null(result);
    }

    // ── RelatedLookup function ──────────────────────────────────────────────

    [Fact]
    public async Task RelatedLookup_ResolvesField()
    {
        var resolver = new TestLookupResolver();
        resolver.RelatedEntities["CustomerId:cust-2"] = new Dictionary<string, object?>
        {
            ["CreditLimit"] = 50000m
        };

        var context = new Dictionary<string, object?>
        {
            ["__entitySlug"] = "orders",
            ["CustomerId"] = "cust-2"
        };

        var parser = new ExpressionParser();
        var ast = parser.Parse("RelatedLookup('CustomerId', 'CreditLimit')");

        var result = await ast.EvaluateAsync(context, resolver);
        Assert.Equal(50000m, result);
    }

    [Fact]
    public void RelatedLookup_SyncEvaluate_Throws()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("RelatedLookup('CustomerId', 'Name')");

        var context = new Dictionary<string, object?>
        {
            ["__entitySlug"] = "orders",
            ["CustomerId"] = "c1"
        };

        Assert.Throws<InvalidOperationException>(() => ast.Evaluate(context));
    }

    // ── QueryLookup function ────────────────────────────────────────────────

    [Fact]
    public async Task QueryLookup_FindsMatchingRecord()
    {
        var resolver = new TestLookupResolver();
        resolver.EntityData["pricingdata"] = new List<Dictionary<string, object?>>
        {
            new() { ["CustomerID"] = "c1", ["ProductID"] = "p1", ["DiscountPercentage"] = 10m },
            new() { ["CustomerID"] = "c1", ["ProductID"] = "p2", ["DiscountPercentage"] = 15m },
            new() { ["CustomerID"] = "c2", ["ProductID"] = "p1", ["DiscountPercentage"] = 5m }
        };

        var context = new Dictionary<string, object?>
        {
            ["__entitySlug"] = "orderlines",
            ["CustomerId"] = "c1",
            ["ProductId"] = "p2"
        };

        var parser = new ExpressionParser();
        var ast = parser.Parse("QueryLookup('pricingdata', 'CustomerID', CustomerId, 'ProductID', ProductId, 'DiscountPercentage')");

        var result = await ast.EvaluateAsync(context, resolver);
        Assert.Equal(15m, result);
    }

    [Fact]
    public async Task QueryLookup_ReturnsNull_WhenNoMatch()
    {
        var resolver = new TestLookupResolver();
        resolver.EntityData["pricingdata"] = new List<Dictionary<string, object?>>
        {
            new() { ["CustomerID"] = "c1", ["ProductID"] = "p1", ["DiscountPercentage"] = 10m }
        };

        var context = new Dictionary<string, object?>
        {
            ["__entitySlug"] = "orderlines",
            ["CustomerId"] = "c99",
            ["ProductId"] = "p99"
        };

        var parser = new ExpressionParser();
        var ast = parser.Parse("QueryLookup('pricingdata', 'CustomerID', CustomerId, 'ProductID', ProductId, 'DiscountPercentage')");

        var result = await ast.EvaluateAsync(context, resolver);
        Assert.Null(result);
    }

    // ── Compound expressions with lookups ───────────────────────────────────

    [Fact]
    public async Task CompoundExpression_DotAccess_InArithmetic()
    {
        var resolver = new TestLookupResolver();
        resolver.RelatedEntities["CustomerId:c1"] = new Dictionary<string, object?>
        {
            ["DiscountLevel"] = 0.10m
        };

        var context = new Dictionary<string, object?>
        {
            ["__entitySlug"] = "orderlines",
            ["CustomerId"] = "c1",
            ["UnitPrice"] = 100m,
            ["Quantity"] = 5m
        };

        var parser = new ExpressionParser();
        // Total = Quantity * UnitPrice * (1 - Customer.DiscountLevel)
        var ast = parser.Parse("Quantity * UnitPrice * (1 - CustomerId.DiscountLevel)");

        var result = await ast.EvaluateAsync(context, resolver);
        Assert.Equal(450m, result);
    }

    // ── JavaScript codegen ──────────────────────────────────────────────────

    [Fact]
    public void DotAccess_ToJavaScript_GeneratesBmwRelatedLookup()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("CustomerId.DiscountLevel");

        var js = ast.ToJavaScript();
        Assert.Contains("bmwRelatedLookup", js);
        Assert.Contains("CustomerId", js);
        Assert.Contains("DiscountLevel", js);
    }

    [Fact]
    public void RelatedLookup_ToJavaScript_GeneratesBmwRelatedLookup()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("RelatedLookup('CustomerId', 'Name')");

        var js = ast.ToJavaScript();
        Assert.Contains("bmwRelatedLookup", js);
    }

    [Fact]
    public void QueryLookup_ToJavaScript_GeneratesBmwQueryLookup()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("QueryLookup('pricing', 'CustID', CustomerId, 'Discount')");

        var js = ast.ToJavaScript();
        Assert.Contains("bmwQueryLookup", js);
    }

    // ── Existing expression compatibility ───────────────────────────────────

    [Fact]
    public void ExistingExpressions_StillWork()
    {
        var parser = new ExpressionParser();

        // Simple arithmetic
        var ast1 = parser.Parse("Quantity * UnitPrice");
        var ctx = new Dictionary<string, object?> { ["Quantity"] = 3m, ["UnitPrice"] = 10m };
        Assert.Equal(30m, ast1.Evaluate(ctx));

        // Function call
        var ast2 = parser.Parse("Round(Quantity * UnitPrice, 2)");
        Assert.Equal(30m, ast2.Evaluate(ctx));

        // If function
        var ast3 = parser.Parse("If(Quantity > 2, UnitPrice * 0.9, UnitPrice)");
        Assert.Equal(9.0m, ast3.Evaluate(ctx));
    }

    [Fact]
    public async Task ExistingExpressions_WorkWithAsyncToo()
    {
        var parser = new ExpressionParser();
        var ast = parser.Parse("Quantity * UnitPrice");
        var ctx = new Dictionary<string, object?> { ["Quantity"] = 3m, ["UnitPrice"] = 10m };

        // Async evaluation should produce same result even without a resolver
        var result = await ast.EvaluateAsync(ctx, null);
        Assert.Equal(30m, result);
    }
}
