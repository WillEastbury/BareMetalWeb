using System;

namespace BareMetalWeb.Data;

/// <summary>
/// Specifies that a property is a calculated field with a client-side and server-side expression.
/// Unlike ComputedField (which does lookups/aggregations), CalculatedField evaluates simple
/// expressions from fields on the same entity, both client-side (JavaScript) and server-side (C#).
/// </summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class CalculatedFieldAttribute : Attribute
{
    /// <summary>
    /// The expression to evaluate (e.g., "Quantity * UnitPrice" or "FirstName + ' ' + LastName").
    /// Expression can reference other properties on the same entity by name.
    /// Supports: +, -, *, /, %, parentheses, string concat, and basic functions.
    /// </summary>
    public string Expression { get; set; } = string.Empty;

    /// <summary>
    /// Optional: Format string for display (e.g., "C2" for currency, "P2" for percentage).
    /// </summary>
    public string? DisplayFormat { get; set; }
}
