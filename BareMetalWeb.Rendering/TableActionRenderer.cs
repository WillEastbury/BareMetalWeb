using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using BareMetalWeb.Core;

namespace BareMetalWeb.Rendering;

/// <summary>
/// Renders structured table row actions to HTML, injecting CSRF tokens where needed.
/// This keeps security concerns (CSRF) in the Host/Rendering layer, not the Data layer.
/// </summary>
public static class TableActionRenderer
{
    /// <summary>
    /// Renders a single action to an HTML button or form.
    /// </summary>
    public static string RenderAction(TableRowAction action, string? csrfToken = null)
    {
        if (action.RequiresCsrf && string.IsNullOrWhiteSpace(csrfToken))
        {
            // Action requires CSRF but no token provided - render without form for safety
            return $"<a class=\"btn btn-sm {action.ButtonClass} me-1\" href=\"{WebUtility.HtmlEncode(action.Url)}\" title=\"{WebUtility.HtmlEncode(action.Title)}\" aria-label=\"{WebUtility.HtmlEncode(action.Title)}\"><i class=\"bi {WebUtility.HtmlEncode(action.IconClass)}\" aria-hidden=\"true\"></i></a>";
        }

        if (action.RequiresCsrf)
        {
            var safeUrl = WebUtility.HtmlEncode(action.Url);
            var safeToken = WebUtility.HtmlEncode(csrfToken!);
            var safeReturnUrl = WebUtility.HtmlEncode(action.CsrfReturnUrl ?? string.Empty);
            var safeTitle = WebUtility.HtmlEncode(action.Title);
            var safeIconClass = WebUtility.HtmlEncode(action.IconClass);
            var safeButtonClass = WebUtility.HtmlEncode(action.ButtonClass);

            return $"""
                <form class="d-inline" method="post" action="{safeUrl}">
                    <input type="hidden" name="{CsrfProtection.FormFieldName}" value="{safeToken}" />
                    <input type="hidden" name="returnUrl" value="{safeReturnUrl}" />
                    <button type="submit" class="btn btn-sm {safeButtonClass} me-1" title="{safeTitle}" aria-label="{safeTitle}">
                        <i class="bi {safeIconClass}" aria-hidden="true"></i>
                    </button>
                </form>
                """;
        }

        // Regular link for actions that don't require CSRF
        var safeUrl2 = WebUtility.HtmlEncode(action.Url);
        var safeTitle2 = WebUtility.HtmlEncode(action.Title);
        var safeIconClass2 = WebUtility.HtmlEncode(action.IconClass);
        return $"<a class=\"btn btn-sm {action.ButtonClass} me-1\" href=\"{safeUrl2}\" title=\"{safeTitle2}\" aria-label=\"{safeTitle2}\"><i class=\"bi {safeIconClass2}\" aria-hidden=\"true\"></i></a>";
    }

    /// <summary>
    /// Renders all actions for a table row to an HTML string.
    /// </summary>
    public static string RenderRowActions(TableRowActions? actions, string? csrfToken = null)
    {
        if (actions == null || actions.Actions.Count == 0)
            return string.Empty;

        var sb = new StringBuilder();
        foreach (var action in actions.Actions)
        {
            sb.Append(RenderAction(action, csrfToken));
        }

        return sb.ToString();
    }
}
