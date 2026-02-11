namespace BareMetalWeb.Core;

/// <summary>
/// Represents a single action button/form for a table row.
/// This separates action metadata from rendering concerns.
/// </summary>
public record TableRowAction(
    string Url,
    string Title,
    string IconClass,
    string ButtonClass,
    bool RequiresCsrf = false,
    string? CsrfReturnUrl = null)
{
}

/// <summary>
/// Represents all actions for a single table row.
/// </summary>
public record TableRowActions(
    List<TableRowAction> Actions)
{
}
