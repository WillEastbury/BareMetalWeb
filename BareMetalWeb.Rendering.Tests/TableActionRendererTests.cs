using System.Net;
using BareMetalWeb.Core;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Rendering.Tests;

public class TableActionRendererTests
{
    [Fact]
    public void RenderAction_NonCsrfAction_RendersAnchorTag()
    {
        var action = new TableRowAction("/edit/1", "Edit", "bi-pencil", "btn-primary");

        var html = TableActionRenderer.RenderAction(action);

        Assert.Contains("<a ", html);
        Assert.Contains("href=\"/edit/1\"", html);
        Assert.Contains("title=\"Edit\"", html);
        Assert.Contains("aria-label=\"Edit\"", html);
        Assert.Contains("bi-pencil", html);
        Assert.Contains("btn-primary", html);
        Assert.DoesNotContain("<form", html);
    }

    [Fact]
    public void RenderAction_CsrfActionWithToken_RendersFormWithHiddenFields()
    {
        var action = new TableRowAction("/delete/1", "Delete", "bi-trash", "btn-danger",
            RequiresCsrf: true, CsrfReturnUrl: "/list");

        var html = TableActionRenderer.RenderAction(action, csrfToken: "test-token-123");

        Assert.Contains("<form", html);
        Assert.Contains("method=\"post\"", html);
        Assert.Contains("action=\"/delete/1\"", html);
        Assert.Contains($"name=\"{CsrfProtection.FormFieldName}\"", html);
        Assert.Contains("value=\"test-token-123\"", html);
        Assert.Contains("name=\"returnUrl\"", html);
        Assert.Contains("value=\"/list\"", html);
        Assert.Contains("<button type=\"submit\"", html);
        Assert.Contains("bi-trash", html);
        Assert.Contains("btn-danger", html);
    }

    [Fact]
    public void RenderAction_CsrfActionWithoutToken_FallsBackToAnchorTag()
    {
        var action = new TableRowAction("/delete/1", "Delete", "bi-trash", "btn-danger",
            RequiresCsrf: true);

        var html = TableActionRenderer.RenderAction(action, csrfToken: null);

        Assert.Contains("<a ", html);
        Assert.Contains("href=\"/delete/1\"", html);
        Assert.DoesNotContain("<form", html);
        Assert.DoesNotContain(CsrfProtection.FormFieldName, html);
    }

    [Fact]
    public void RenderAction_CsrfActionWithEmptyToken_FallsBackToAnchorTag()
    {
        var action = new TableRowAction("/delete/1", "Delete", "bi-trash", "btn-danger",
            RequiresCsrf: true);

        var html = TableActionRenderer.RenderAction(action, csrfToken: "   ");

        Assert.Contains("<a ", html);
        Assert.DoesNotContain("<form", html);
    }

    [Fact]
    public void RenderAction_HtmlEncodesSpecialCharacters()
    {
        var action = new TableRowAction("/edit?id=1&type=2", "Edit <item>", "bi-pencil", "btn-primary");

        var html = TableActionRenderer.RenderAction(action);

        Assert.Contains(WebUtility.HtmlEncode("/edit?id=1&type=2"), html);
        Assert.Contains(WebUtility.HtmlEncode("Edit <item>"), html);
    }

    [Fact]
    public void RenderRowActions_NullActions_ReturnsEmpty()
    {
        var html = TableActionRenderer.RenderRowActions(null);

        Assert.Equal(string.Empty, html);
    }

    [Fact]
    public void RenderRowActions_EmptyActionsList_ReturnsEmpty()
    {
        var actions = new TableRowActions(new List<TableRowAction>());

        var html = TableActionRenderer.RenderRowActions(actions);

        Assert.Equal(string.Empty, html);
    }

    [Fact]
    public void RenderRowActions_MultipleActions_RendersAll()
    {
        var actions = new TableRowActions(new List<TableRowAction>
        {
            new("/edit/1", "Edit", "bi-pencil", "btn-primary"),
            new("/view/1", "View", "bi-eye", "btn-info"),
            new("/delete/1", "Delete", "bi-trash", "btn-danger", RequiresCsrf: true)
        });

        var html = TableActionRenderer.RenderRowActions(actions, csrfToken: "tok");

        Assert.Contains("bi-pencil", html);
        Assert.Contains("bi-eye", html);
        Assert.Contains("bi-trash", html);
        // Two anchors + one form
        Assert.Contains("<a ", html);
        Assert.Contains("<form", html);
    }

    [Fact]
    public void RenderAction_CsrfWithNullReturnUrl_RendersEmptyReturnUrlValue()
    {
        var action = new TableRowAction("/delete/1", "Delete", "bi-trash", "btn-danger",
            RequiresCsrf: true, CsrfReturnUrl: null);

        var html = TableActionRenderer.RenderAction(action, csrfToken: "tok");

        Assert.Contains("<form", html);
        Assert.Contains("name=\"returnUrl\" value=\"\"", html);
    }

    [Fact]
    public void RenderAction_NonCsrfAction_IncludesAriaHiddenOnIcon()
    {
        var action = new TableRowAction("/view/1", "View", "bi-eye", "btn-info");

        var html = TableActionRenderer.RenderAction(action);

        Assert.Contains("aria-hidden=\"true\"", html);
    }

    [Fact]
    public void RenderAction_NonCsrfAction_IncludesMeSpacingClass()
    {
        var action = new TableRowAction("/view/1", "View", "bi-eye", "btn-info");

        var html = TableActionRenderer.RenderAction(action);

        Assert.Contains("me-1", html);
    }
}
