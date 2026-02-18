using System.Collections.Generic;
using BareMetalWeb.Core;
using BareMetalWeb.Rendering;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class RouteInfoHelpersTests
{
    private static RouteHandlerData CreateRouteHandler(string[] keys, string[] values)
    {
        var pageInfo = new PageInfo(
            new PageMetaData(null!, 200),
            new PageContext(keys, values));
        return new RouteHandlerData(pageInfo, _ => System.Threading.Tasks.Task.CompletedTask);
    }

    [Fact]
    public void InjectRouteParameters_AddsParametersToPageContext()
    {
        var handler = CreateRouteHandler(new[] { "title" }, new[] { "Hello" });
        var routeParams = new Dictionary<string, string> { { "id", "42" } };

        var result = RouteInfoHelpers.InjectRouteParametersIntoPageInfo(handler, routeParams);

        Assert.Equal(2, result.PageInfo!.PageContext.PageMetaDataKeys.Length);
        Assert.Equal("id", result.PageInfo!.PageContext.PageMetaDataKeys[1]);
        Assert.Equal("42", result.PageInfo!.PageContext.PageMetaDataValues[1]);
    }

    [Fact]
    public void InjectRouteParameters_HtmlEncodesValues()
    {
        var handler = CreateRouteHandler(System.Array.Empty<string>(), System.Array.Empty<string>());
        var routeParams = new Dictionary<string, string> { { "name", "<script>alert(1)</script>" } };

        var result = RouteInfoHelpers.InjectRouteParametersIntoPageInfo(handler, routeParams);

        Assert.Equal("&lt;script&gt;alert(1)&lt;/script&gt;", result.PageInfo!.PageContext.PageMetaDataValues[0]);
    }

    [Fact]
    public void InjectRouteParameters_EmptyParams_ReturnsOriginal()
    {
        var handler = CreateRouteHandler(new[] { "title" }, new[] { "Hello" });
        var routeParams = new Dictionary<string, string>();

        var result = RouteInfoHelpers.InjectRouteParametersIntoPageInfo(handler, routeParams);

        Assert.Same(handler.PageInfo, result.PageInfo);
    }

    [Fact]
    public void InjectRouteParameters_NullParams_ReturnsOriginal()
    {
        var handler = CreateRouteHandler(new[] { "title" }, new[] { "Hello" });

        var result = RouteInfoHelpers.InjectRouteParametersIntoPageInfo(handler, null!);

        Assert.Same(handler.PageInfo, result.PageInfo);
    }

    [Fact]
    public void InjectRouteParameters_MultipleParams_AllAdded()
    {
        var handler = CreateRouteHandler(System.Array.Empty<string>(), System.Array.Empty<string>());
        var routeParams = new Dictionary<string, string>
        {
            { "type", "Customer" },
            { "id", "abc-123" }
        };

        var result = RouteInfoHelpers.InjectRouteParametersIntoPageInfo(handler, routeParams);

        Assert.Equal(2, result.PageInfo!.PageContext.PageMetaDataKeys.Length);
    }

    [Fact]
    public void InjectRouteParameters_PreservesExistingKeys()
    {
        var handler = CreateRouteHandler(new[] { "existing" }, new[] { "value" });
        var routeParams = new Dictionary<string, string> { { "new", "param" } };

        var result = RouteInfoHelpers.InjectRouteParametersIntoPageInfo(handler, routeParams);

        Assert.Equal("existing", result.PageInfo!.PageContext.PageMetaDataKeys[0]);
        Assert.Equal("value", result.PageInfo!.PageContext.PageMetaDataValues[0]);
        Assert.Equal("new", result.PageInfo!.PageContext.PageMetaDataKeys[1]);
        Assert.Equal("param", result.PageInfo!.PageContext.PageMetaDataValues[1]);
    }
}
