using System.Collections.Generic;
using Xunit;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Tests that lookup API route patterns are matched correctly and that
/// specific literal segments (_field, _aggregate) are distinguished from
/// parameterized segments ({id}).
/// </summary>
public class LookupRouteMatchingTests
{
    [Fact]
    public void TryMatch_LookupEntityById_MatchesCorrectly()
    {
        var result = RouteMatching.TryMatch(
            "/api/_lookup/product/prod-123",
            "/api/_lookup/{type}/{id}",
            out var parameters);

        Assert.True(result);
        Assert.Equal("product", parameters["type"]);
        Assert.Equal("prod-123", parameters["id"]);
    }

    [Fact]
    public void TryMatch_LookupEntityQuery_MatchesCorrectly()
    {
        var result = RouteMatching.TryMatch(
            "/api/_lookup/product",
            "/api/_lookup/{type}",
            out var parameters);

        Assert.True(result);
        Assert.Equal("product", parameters["type"]);
    }

    [Fact]
    public void TryMatch_LookupFieldRoute_MatchesCorrectly()
    {
        var result = RouteMatching.TryMatch(
            "/api/_lookup/product/_field/prod-123/Price",
            "/api/_lookup/{type}/_field/{id}/{fieldName}",
            out var parameters);

        Assert.True(result);
        Assert.Equal("product", parameters["type"]);
        Assert.Equal("prod-123", parameters["id"]);
        Assert.Equal("Price", parameters["fieldName"]);
    }

    [Fact]
    public void TryMatch_LookupAggregateRoute_MatchesCorrectly()
    {
        var result = RouteMatching.TryMatch(
            "/api/_lookup/product/_aggregate",
            "/api/_lookup/{type}/_aggregate",
            out var parameters);

        Assert.True(result);
        Assert.Equal("product", parameters["type"]);
    }

    [Fact]
    public void TryMatch_FieldRoute_DoesNotMatchIdRoute()
    {
        // The _field route should NOT match the {type}/{id} template
        // because _field/prod-123/Price has more segments
        var result = RouteMatching.TryMatch(
            "/api/_lookup/product/_field/prod-123/Price",
            "/api/_lookup/{type}/{id}",
            out _);

        Assert.False(result);
    }

    [Fact]
    public void TryMatch_AggregateRoute_MatchesIdRouteIfCheckedFirst()
    {
        // The _aggregate path DOES match {type}/{id} pattern (with id="_aggregate")
        // This is why _aggregate route must be registered before {type}/{id}
        var result = RouteMatching.TryMatch(
            "/api/_lookup/product/_aggregate",
            "/api/_lookup/{type}/{id}",
            out var parameters);

        Assert.True(result);
        Assert.Equal("_aggregate", parameters["id"]);
    }

    [Fact]
    public void TryMatch_AggregateRoute_MatchesOwnPattern()
    {
        // When checked against its own pattern, it should match correctly
        var result = RouteMatching.TryMatch(
            "/api/_lookup/product/_aggregate",
            "/api/_lookup/{type}/_aggregate",
            out var parameters);

        Assert.True(result);
        Assert.Equal("product", parameters["type"]);
    }

    [Fact]
    public void TryMatch_LookupRoutes_CaseInsensitive()
    {
        var result = RouteMatching.TryMatch(
            "/API/_LOOKUP/Product/PROD-123",
            "/api/_lookup/{type}/{id}",
            out var parameters);

        Assert.True(result);
        Assert.Equal("Product", parameters["type"]);
        Assert.Equal("PROD-123", parameters["id"]);
    }

    [Fact]
    public void TryMatch_LookupWithEncodedId_MatchesCorrectly()
    {
        var result = RouteMatching.TryMatch(
            "/api/_lookup/product/id%20with%20spaces",
            "/api/_lookup/{type}/{id}",
            out var parameters);

        Assert.True(result);
        Assert.Equal("product", parameters["type"]);
        Assert.Equal("id%20with%20spaces", parameters["id"]);
    }
}
