using BareMetalWeb.Host;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class NumericRouteTableTests
{
    private static RouteHandlerData MakeHandler(string label = "test")
    {
        return new RouteHandlerData(null, _ => ValueTask.CompletedTask);
    }

    [Fact]
    public void Build_AssignsSequentialIds_SortedByKey()
    {
        var routes = new Dictionary<string, RouteHandlerData>
        {
            ["GET /login"] = MakeHandler(),
            ["GET /"] = MakeHandler(),
            ["POST /logout"] = MakeHandler()
        };

        var table = new NumericRouteTable();
        table.Build(routes);

        Assert.Equal(3, table.Count);
        // Sorted: "GET /" < "GET /login" < "POST /logout"
        Assert.Equal("GET /", table.GetRouteKey(0));
        Assert.Equal("GET /login", table.GetRouteKey(1));
        Assert.Equal("POST /logout", table.GetRouteKey(2));
    }

    [Fact]
    public void TryLookup_ValidId_ReturnsHandler()
    {
        var routes = new Dictionary<string, RouteHandlerData>
        {
            ["GET /test"] = MakeHandler()
        };

        var table = new NumericRouteTable();
        table.Build(routes);

        Assert.True(table.TryLookup(0, out var data));
        Assert.NotNull(data.Handler);
    }

    [Fact]
    public void TryLookup_OutOfRange_ReturnsFalse()
    {
        var routes = new Dictionary<string, RouteHandlerData>
        {
            ["GET /test"] = MakeHandler()
        };

        var table = new NumericRouteTable();
        table.Build(routes);

        Assert.False(table.TryLookup(1, out _));
        Assert.False(table.TryLookup(-1, out _));
        Assert.False(table.TryLookup(999, out _));
    }

    [Fact]
    public void TryLookup_EmptyTable_ReturnsFalse()
    {
        var table = new NumericRouteTable();
        table.Build(new Dictionary<string, RouteHandlerData>());

        Assert.False(table.TryLookup(0, out _));
        Assert.Equal(0, table.Count);
    }

    [Fact]
    public void GetRouteKey_ValidId_ReturnsKey()
    {
        var routes = new Dictionary<string, RouteHandlerData>
        {
            ["GET /hello"] = MakeHandler()
        };

        var table = new NumericRouteTable();
        table.Build(routes);

        Assert.Equal("GET /hello", table.GetRouteKey(0));
    }

    [Fact]
    public void GetRouteKey_InvalidId_ReturnsNull()
    {
        var table = new NumericRouteTable();
        table.Build(new Dictionary<string, RouteHandlerData> { ["GET /x"] = MakeHandler() });

        Assert.Null(table.GetRouteKey(5));
        Assert.Null(table.GetRouteKey(-1));
    }

    [Fact]
    public void GetAllEntries_ReturnsAllRoutes()
    {
        var routes = new Dictionary<string, RouteHandlerData>
        {
            ["GET /a"] = MakeHandler(),
            ["POST /b"] = MakeHandler(),
            ["DELETE /c"] = MakeHandler()
        };

        var table = new NumericRouteTable();
        table.Build(routes);

        var entries = table.GetAllEntries();
        Assert.Equal(3, entries.Length);
    }

    [Fact]
    public void Build_IsDeterministic_AcrossMultipleBuilds()
    {
        var routes = new Dictionary<string, RouteHandlerData>
        {
            ["POST /b"] = MakeHandler(),
            ["GET /a"] = MakeHandler(),
            ["DELETE /c"] = MakeHandler()
        };

        var table1 = new NumericRouteTable();
        table1.Build(routes);

        var table2 = new NumericRouteTable();
        table2.Build(routes);

        for (int i = 0; i < 3; i++)
        {
            Assert.Equal(table1.GetRouteKey(i), table2.GetRouteKey(i));
        }
    }

    [Fact]
    public void Build_Rebuild_UpdatesTable()
    {
        var table = new NumericRouteTable();

        var routes1 = new Dictionary<string, RouteHandlerData>
        {
            ["GET /old"] = MakeHandler()
        };
        table.Build(routes1);
        Assert.Equal(1, table.Count);
        Assert.Equal("GET /old", table.GetRouteKey(0));

        var routes2 = new Dictionary<string, RouteHandlerData>
        {
            ["GET /new1"] = MakeHandler(),
            ["GET /new2"] = MakeHandler()
        };
        table.Build(routes2);
        Assert.Equal(2, table.Count);
        Assert.Equal("GET /new1", table.GetRouteKey(0));
    }
}

public class NumericRouteIdParserTests
{
    [Theory]
    [InlineData("0", 0)]
    [InlineData("1", 1)]
    [InlineData("42", 42)]
    [InlineData("123", 123)]
    [InlineData("9999", 9999)]
    public void ParseRouteId_ValidDigits_ReturnsInteger(string input, int expected)
    {
        Assert.Equal(expected, NumericRouteTable.ParseRouteId(input.AsSpan()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a")]
    [InlineData("/path")]
    [InlineData("abc123")]
    [InlineData("-1")]
    public void ParseRouteId_NonDigitStart_ReturnsNegativeOne(string input)
    {
        Assert.Equal(-1, NumericRouteTable.ParseRouteId(input.AsSpan()));
    }

    [Fact]
    public void ParseRouteId_DigitsFollowedBySlash_StopsAtSlash()
    {
        Assert.Equal(42, NumericRouteTable.ParseRouteId("42/extra".AsSpan()));
    }

    [Fact]
    public void ParseRouteId_DigitsFollowedByQuery_StopsAtQuery()
    {
        Assert.Equal(7, NumericRouteTable.ParseRouteId("7?param=1".AsSpan()));
    }

    [Fact]
    public void ParseRouteId_DigitsFollowedBySpace_StopsAtSpace()
    {
        Assert.Equal(99, NumericRouteTable.ParseRouteId("99 HTTP/1.1".AsSpan()));
    }

    [Fact]
    public void ParseRouteId_SingleDigit_Works()
    {
        Assert.Equal(0, NumericRouteTable.ParseRouteId("0".AsSpan()));
        Assert.Equal(9, NumericRouteTable.ParseRouteId("9".AsSpan()));
    }

    [Fact]
    public void ParseRouteId_EmptySpan_ReturnsNegativeOne()
    {
        Assert.Equal(-1, NumericRouteTable.ParseRouteId(ReadOnlySpan<char>.Empty));
    }

    [Fact]
    public void ParseRouteId_LargeNumber_Parses()
    {
        Assert.Equal(65535, NumericRouteTable.ParseRouteId("65535".AsSpan()));
    }
}
