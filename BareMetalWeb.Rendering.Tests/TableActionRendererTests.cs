using BareMetalWeb.Core;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Rendering.Tests;

/// <summary>
/// Security tests for TableActionRenderer to prevent HTML attribute injection attacks.
/// Tests verify that all user-supplied fields (ButtonClass, IconClass, Url, Title) are properly HTML-encoded.
/// </summary>
public class TableActionRendererTests
{
    [Fact]
    public void RenderAction_NonCsrfBranch_EncodesButtonClassToPreventAttributeInjection()
    {
        // Arrange - malicious ButtonClass attempting attribute injection
        var maliciousButtonClass = "btn-danger\" onclick=\"alert('XSS')\" data-evil=\"";
        var action = new TableRowAction(
            Url: "/test",
            Title: "Test Action",
            IconClass: "bi-trash",
            ButtonClass: maliciousButtonClass,
            RequiresCsrf: false
        );

        // Act
        var result = TableActionRenderer.RenderAction(action, csrfToken: null);

        // Assert - HTML entities should be encoded, not executable
        Assert.Contains("&quot;", result); // Double quotes should be encoded
        Assert.DoesNotContain("onclick=\"alert", result); // Should not contain unencoded onclick
        Assert.DoesNotContain("data-evil=\"", result); // Should not contain unencoded data attribute
        
        // Verify the malicious class value is encoded
        Assert.Contains("btn-danger&quot; onclick=&quot;alert(&#39;XSS&#39;)&quot; data-evil=&quot;", result);
    }

    [Fact]
    public void RenderAction_CsrfBranchWithoutToken_EncodesButtonClassToPreventAttributeInjection()
    {
        // Arrange - test the branch where CSRF is required but no token provided (line 23)
        var maliciousButtonClass = "btn-primary\"><script>alert('XSS')</script><div class=\"";
        var action = new TableRowAction(
            Url: "/delete",
            Title: "Delete",
            IconClass: "bi-trash",
            ButtonClass: maliciousButtonClass,
            RequiresCsrf: true // Requires CSRF but we'll pass null token
        );

        // Act
        var result = TableActionRenderer.RenderAction(action, csrfToken: null);

        // Assert - script tags should be encoded
        Assert.Contains("&lt;script&gt;", result); // Script tags should be encoded
        Assert.DoesNotContain("<script>alert", result); // Should not contain unencoded script
        Assert.Contains("btn-primary&quot;&gt;&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;&lt;div class=&quot;", result);
    }

    [Fact]
    public void RenderAction_CsrfBranchWithToken_EncodesButtonClassToPreventAttributeInjection()
    {
        // Arrange - test the CSRF form branch (line 33)
        var maliciousButtonClass = "btn-warning\" formaction=\"/evil\" ";
        var action = new TableRowAction(
            Url: "/submit",
            Title: "Submit",
            IconClass: "bi-check",
            ButtonClass: maliciousButtonClass,
            RequiresCsrf: true,
            CsrfReturnUrl: "/return"
        );

        // Act
        var result = TableActionRenderer.RenderAction(action, csrfToken: "valid-token");

        // Assert - formaction should be encoded
        Assert.Contains("&quot;", result); // Quotes should be encoded
        Assert.DoesNotContain("formaction=\"/evil\"", result); // Should not contain unencoded formaction
        Assert.Contains("btn-warning&quot; formaction=&quot;/evil&quot;", result);
        
        // Verify the result is a form (CSRF branch)
        Assert.Contains("<form", result);
        Assert.Contains("<button", result);
    }

    [Fact]
    public void RenderAction_NonCsrfBranch_EncodeIconClassToPreventAttributeInjection()
    {
        // Arrange
        var maliciousIconClass = "bi-trash\" style=\"display:none\" data-hack=\"";
        var action = new TableRowAction(
            Url: "/test",
            Title: "Test",
            IconClass: maliciousIconClass,
            ButtonClass: "btn-primary",
            RequiresCsrf: false
        );

        // Act
        var result = TableActionRenderer.RenderAction(action, csrfToken: null);

        // Assert - style and data attributes should be encoded
        Assert.Contains("&quot;", result);
        Assert.DoesNotContain("style=\"display:none\"", result);
        Assert.Contains("bi-trash&quot; style=&quot;display:none&quot; data-hack=&quot;", result);
    }

    [Fact]
    public void RenderAction_NonCsrfBranch_EncodeUrlToPreventJavaScriptInjection()
    {
        // Arrange
        var maliciousUrl = "javascript:alert('XSS')";
        var action = new TableRowAction(
            Url: maliciousUrl,
            Title: "Test",
            IconClass: "bi-test",
            ButtonClass: "btn-primary",
            RequiresCsrf: false
        );

        // Act
        var result = TableActionRenderer.RenderAction(action, csrfToken: null);

        // Assert - single quotes should be encoded, preventing script execution
        Assert.Contains("javascript:alert(&#39;XSS&#39;)", result); // Apostrophes encoded
        Assert.DoesNotContain("href=\"javascript:alert('XSS')\"", result); // Should not have unencoded apostrophes
    }

    [Fact]
    public void RenderAction_NonCsrfBranch_EncodeTitleToPreventAttributeInjection()
    {
        // Arrange
        var maliciousTitle = "Delete\" onmouseover=\"alert('XSS')";
        var action = new TableRowAction(
            Url: "/test",
            Title: maliciousTitle,
            IconClass: "bi-test",
            ButtonClass: "btn-primary",
            RequiresCsrf: false
        );

        // Act
        var result = TableActionRenderer.RenderAction(action, csrfToken: null);

        // Assert
        Assert.Contains("&quot;", result);
        Assert.DoesNotContain("onmouseover=\"alert", result);
        Assert.Contains("Delete&quot; onmouseover=&quot;alert(&#39;XSS&#39;)", result);
    }

    [Fact]
    public void RenderAction_CsrfBranch_EncodesReturnUrlToPreventAttributeInjection()
    {
        // Arrange
        var maliciousReturnUrl = "/return\" onclick=\"alert('XSS')\" \"";
        var action = new TableRowAction(
            Url: "/submit",
            Title: "Submit",
            IconClass: "bi-check",
            ButtonClass: "btn-primary",
            RequiresCsrf: true,
            CsrfReturnUrl: maliciousReturnUrl
        );

        // Act
        var result = TableActionRenderer.RenderAction(action, csrfToken: "valid-token");

        // Assert
        Assert.Contains("&quot;", result);
        Assert.DoesNotContain("onclick=\"alert", result);
        Assert.Contains("/return&quot; onclick=&quot;alert(&#39;XSS&#39;)&quot; &quot;", result);
    }

    [Fact]
    public void RenderRowActions_NullActions_ReturnsEmptyString()
    {
        // Act
        var result = TableActionRenderer.RenderRowActions(null, csrfToken: null);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void RenderRowActions_EmptyActionsList_ReturnsEmptyString()
    {
        // Arrange
        var actions = new TableRowActions(new List<TableRowAction>());

        // Act
        var result = TableActionRenderer.RenderRowActions(actions, csrfToken: null);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void RenderRowActions_MultipleActions_EncodesAllActionsSafely()
    {
        // Arrange
        var maliciousClass = "btn-danger\" onclick=\"evil()";
        var actions = new TableRowActions(new List<TableRowAction>
        {
            new TableRowAction("/edit", "Edit", "bi-pencil", maliciousClass, RequiresCsrf: false),
            new TableRowAction("/delete", "Delete", "bi-trash", maliciousClass, RequiresCsrf: true)
        });

        // Act
        var result = TableActionRenderer.RenderRowActions(actions, csrfToken: "token");

        // Assert - both actions should be encoded
        Assert.DoesNotContain("onclick=\"evil()\"", result);
        // Should appear twice (once per action), encoded
        var encodedPattern = "btn-danger&quot; onclick=&quot;evil()";
        Assert.Contains(encodedPattern, result);
        
        // Verify we got multiple actions rendered
        Assert.Contains("bi-pencil", result);
        Assert.Contains("bi-trash", result);
    }

    [Fact]
    public void RenderAction_ComplexAttackVector_AllFieldsEncoded()
    {
        // Arrange - complex multi-vector attack
        var action = new TableRowAction(
            Url: "\"><script>alert('url')</script><a href=\"",
            Title: "\"><img src=x onerror=\"alert('title')\">",
            IconClass: "\" onload=\"alert('icon')\" class=\"",
            ButtonClass: "\" autofocus onfocus=\"alert('button')\" class=\"",
            RequiresCsrf: false
        );

        // Act
        var result = TableActionRenderer.RenderAction(action, csrfToken: null);

        // Assert - dangerous HTML tags and quote-breaking should be encoded
        // Note: event handler names like "onerror" may appear in output, but they're safe
        // because the surrounding quotes are encoded, preventing attribute injection
        Assert.DoesNotContain("<script>", result);
        Assert.DoesNotContain("<img ", result);
        
        // All dangerous characters should be encoded
        Assert.Contains("&lt;script&gt;", result);
        Assert.Contains("&lt;img ", result);
        Assert.Contains("&quot;", result); // Quotes are encoded, preventing attribute escape
        
        // Verify no unencoded quotes that would allow attribute escape
        // The pattern '" on' would indicate an unencoded quote breaking out of an attribute
        Assert.DoesNotContain("\" on", result);
        Assert.DoesNotContain("' on", result);
    }

    [Fact]
    public void RenderAction_LegitimateBootstrapClasses_RendersCorrectly()
    {
        // Arrange - test with normal, safe values
        var action = new TableRowAction(
            Url: "/edit/123",
            Title: "Edit Item",
            IconClass: "bi-pencil-square",
            ButtonClass: "btn-primary btn-sm",
            RequiresCsrf: false
        );

        // Act
        var result = TableActionRenderer.RenderAction(action, csrfToken: null);

        // Assert - legitimate values should pass through (they don't need encoding)
        Assert.Contains("btn-primary btn-sm", result);
        Assert.Contains("bi-pencil-square", result);
        Assert.Contains("/edit/123", result);
        Assert.Contains("Edit Item", result);
        Assert.Contains("class=\"btn btn-sm btn-primary btn-sm me-1\"", result);
    }
}
