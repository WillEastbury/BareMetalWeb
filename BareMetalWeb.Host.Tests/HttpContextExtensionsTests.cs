using Microsoft.AspNetCore.Http;
using BareMetalWeb.Core;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class HttpContextExtensionsTests
{
    private static HttpContext CreateContext()
    {
        return new DefaultHttpContext();
    }

    // --- Cookie Extensions ---

    [Fact]
    public void GetCookie_NoCookies_ReturnsNull()
    {
        var context = CreateContext();
        Assert.Null(context.GetCookie("missing"));
    }

    [Fact]
    public void SetCookie_AppendsCookieToResponse()
    {
        var context = CreateContext();
        context.SetCookie("session", "abc123");
        Assert.True(context.Response.Headers.ContainsKey("Set-Cookie"));
    }

    [Fact]
    public void DeleteCookie_AppendsDeletionCookie()
    {
        var context = CreateContext();
        context.DeleteCookie("session");
        Assert.True(context.Response.Headers.ContainsKey("Set-Cookie"));
    }

    // --- CSP Extensions ---

    [Fact]
    public void GenerateCspNonce_ReturnsBase64String()
    {
        var context = CreateContext();
        var nonce = context.GenerateCspNonce();
        Assert.False(string.IsNullOrWhiteSpace(nonce));
        // Base64 of 16 bytes = 24 chars
        Assert.Equal(24, nonce.Length);
    }

    [Fact]
    public void GenerateCspNonce_StoresInContextItems()
    {
        var context = CreateContext();
        var nonce = context.GenerateCspNonce();
        Assert.Equal(nonce, context.Items["BareMetalWeb.CspNonce"]);
    }

    [Fact]
    public void GetCspNonce_ReturnsExistingNonce()
    {
        var context = CreateContext();
        var nonce1 = context.GenerateCspNonce();
        var nonce2 = context.GetCspNonce();
        Assert.Equal(nonce1, nonce2);
    }

    [Fact]
    public void GetCspNonce_GeneratesIfMissing()
    {
        var context = CreateContext();
        var nonce = context.GetCspNonce();
        Assert.False(string.IsNullOrWhiteSpace(nonce));
    }

    [Fact]
    public void GenerateCspNonce_DifferentPerCall()
    {
        var context1 = CreateContext();
        var context2 = CreateContext();
        var nonce1 = context1.GenerateCspNonce();
        var nonce2 = context2.GenerateCspNonce();
        Assert.NotEqual(nonce1, nonce2);
    }

    // --- PageInfo Extensions ---

    [Fact]
    public void SetAndGetPageMetaData_RoundTrips()
    {
        var context = CreateContext();
        var meta = new PageMetaData(null!, 200, "Public");
        context.SetPageMetaData(meta);
        Assert.Same(meta, context.GetPageMetaData());
    }

    [Fact]
    public void GetPageMetaData_NoData_ReturnsNull()
    {
        var context = CreateContext();
        Assert.Null(context.GetPageMetaData());
    }

    [Fact]
    public void SetAndGetPageContext_RoundTrips()
    {
        var context = CreateContext();
        var pageContext = new PageContext(new[] { "k" }, new[] { "v" });
        context.SetPageContext(pageContext);
        Assert.Same(pageContext, context.GetPageContext());
    }

    [Fact]
    public void SetPageInfo_SetsMetaDataAndContext()
    {
        var context = CreateContext();
        var pageInfo = new PageInfo(
            new PageMetaData(null!, 200),
            new PageContext(new[] { "a" }, new[] { "b" }));
        context.SetPageInfo(pageInfo);

        Assert.NotNull(context.GetPageMetaData());
        Assert.NotNull(context.GetPageContext());
    }

    [Fact]
    public void GetPageInfo_NoData_ReturnsNull()
    {
        var context = CreateContext();
        Assert.Null(context.GetPageInfo());
    }

    [Fact]
    public void GetPageInfo_WithBothSet_ReturnsPageInfo()
    {
        var context = CreateContext();
        var pageInfo = new PageInfo(
            new PageMetaData(null!, 200),
            new PageContext(new[] { "k" }, new[] { "v" }));
        context.SetPageInfo(pageInfo);

        var result = context.GetPageInfo();
        Assert.NotNull(result);
        Assert.Equal("k", result!.PageContext.PageMetaDataKeys[0]);
    }

    // --- String Value Operations ---

    [Fact]
    public void SetStringValue_AddsNewKey()
    {
        var context = CreateContext();
        context.SetStringValue("title", "Hello");
        var pc = context.GetPageContext();
        Assert.Contains("title", pc!.PageMetaDataKeys);
    }

    [Fact]
    public void SetStringValue_UpdatesExistingKey()
    {
        var context = CreateContext();
        context.SetStringValue("title", "Hello");
        context.SetStringValue("title", "World");
        var pc = context.GetPageContext();
        var idx = System.Array.IndexOf(pc!.PageMetaDataKeys, "title");
        Assert.Equal("World", pc.PageMetaDataValues[idx]);
    }

    [Fact]
    public void AddStringValue_AllowsDuplicateKeys()
    {
        var context = CreateContext();
        context.AddStringValue("tag", "a");
        context.AddStringValue("tag", "b");
        var pc = context.GetPageContext();
        var count = pc!.PageMetaDataKeys.Count(k => k == "tag");
        Assert.Equal(2, count);
    }

    [Fact]
    public void RemoveStringValue_RemovesKey()
    {
        var context = CreateContext();
        context.SetStringValue("title", "Hello");
        context.SetStringValue("subtitle", "World");
        context.RemoveStringValue("title");
        var pc = context.GetPageContext();
        Assert.DoesNotContain("title", pc!.PageMetaDataKeys);
        Assert.Contains("subtitle", pc.PageMetaDataKeys);
    }

    // --- Loop Operations ---

    [Fact]
    public void SetLoop_AddsLoop()
    {
        var context = CreateContext();
        var items = new[] { new Dictionary<string, string> { { "name", "A" } } as IReadOnlyDictionary<string, string> };
        context.SetLoop("items", items);
        var pc = context.GetPageContext();
        Assert.Single(pc!.TemplateLoops!);
        Assert.Equal("items", pc.TemplateLoops![0].Key);
    }

    [Fact]
    public void SetLoop_ReplacesExistingLoop()
    {
        var context = CreateContext();
        var items1 = new[] { new Dictionary<string, string> { { "n", "1" } } as IReadOnlyDictionary<string, string> };
        var items2 = new[] { new Dictionary<string, string> { { "n", "2" } } as IReadOnlyDictionary<string, string> };
        context.SetLoop("data", items1);
        context.SetLoop("data", items2);
        var pc = context.GetPageContext();
        Assert.Single(pc!.TemplateLoops!);
        Assert.Equal("2", pc.TemplateLoops![0].Items[0]["n"]);
    }

    [Fact]
    public void SetLoopValues_CreatesSimpleLoop()
    {
        var context = CreateContext();
        context.SetLoopValues("names", "name", new[] { "Alice", "Bob" });
        var pc = context.GetPageContext();
        Assert.Equal(2, pc!.TemplateLoops![0].Items.Count);
        Assert.Equal("Alice", pc.TemplateLoops![0].Items[0]["name"]);
    }

    [Fact]
    public void AddLoopItem_AppendsToExistingLoop()
    {
        var context = CreateContext();
        var item1 = new Dictionary<string, string> { { "v", "1" } } as IReadOnlyDictionary<string, string>;
        var item2 = new Dictionary<string, string> { { "v", "2" } } as IReadOnlyDictionary<string, string>;
        context.SetLoop("list", new[] { item1 });
        context.AddLoopItem("list", item2);
        var pc = context.GetPageContext();
        Assert.Equal(2, pc!.TemplateLoops![0].Items.Count);
    }

    [Fact]
    public void AddLoopItem_CreatesNewLoopIfMissing()
    {
        var context = CreateContext();
        var item = new Dictionary<string, string> { { "v", "1" } } as IReadOnlyDictionary<string, string>;
        context.AddLoopItem("newloop", item);
        var pc = context.GetPageContext();
        Assert.Equal("newloop", pc!.TemplateLoops![0].Key);
    }

    // --- Table Operations ---

    [Fact]
    public void AddTable_SetsColumnsAndRows()
    {
        var context = CreateContext();
        context.AddTable(new[] { "Name", "Age" }, new[] { new[] { "Alice", "30" } });
        var pc = context.GetPageContext();
        Assert.Equal(2, pc!.TableColumnTitles!.Length);
        Assert.Single(pc.TableData!);
    }

    [Fact]
    public void AddTableColumnTitle_AppendsTitle()
    {
        var context = CreateContext();
        context.AddTableColumnTitle("Col1");
        context.AddTableColumnTitle("Col2");
        var pc = context.GetPageContext();
        Assert.Equal(2, pc!.TableColumnTitles!.Length);
    }

    [Fact]
    public void AddTableHeader_SetsAllTitles()
    {
        var context = CreateContext();
        context.AddTableHeader(new[] { "A", "B", "C" });
        var pc = context.GetPageContext();
        Assert.Equal(3, pc!.TableColumnTitles!.Length);
    }

    [Fact]
    public void AddTableRow_AppendsRow()
    {
        var context = CreateContext();
        context.AddTableRow(new[] { "1", "2" });
        context.AddTableRow(new[] { "3", "4" });
        var pc = context.GetPageContext();
        Assert.Equal(2, pc!.TableData!.Length);
    }

    // --- Form Operations ---

    [Fact]
    public void AddFormDefinition_SetsForm()
    {
        var context = CreateContext();
        var form = new FormDefinition("/submit", "POST", "Save", System.Array.Empty<FormField>());
        context.AddFormDefinition(form);
        var pc = context.GetPageContext();
        Assert.NotNull(pc!.FormDefinition);
        Assert.Equal("/submit", pc.FormDefinition!.Action);
    }

    // --- App Extensions ---

    [Fact]
    public void SetAndGetApp_RoundTrips()
    {
        var context = CreateContext();
        Assert.Null(context.GetApp());
    }
}
