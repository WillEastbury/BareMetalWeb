using System;
using System.Text.RegularExpressions;

namespace BareMetalWeb.Data;

/// <summary>
/// Base class for field validation attributes.
/// </summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = true)]
public abstract class ValidationAttribute : Attribute
{
    /// <summary>Custom error message. If null, a default message is generated.</summary>
    public string? ErrorMessage { get; set; }

    /// <summary>Validate the given value. Returns null if valid, or an error message if invalid.</summary>
    public abstract string? Validate(string fieldLabel, object? value);
}

/// <summary>Enforces a minimum string length.</summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class MinLengthAttribute : ValidationAttribute
{
    public int Length { get; }
    public MinLengthAttribute(int length) => Length = length;

    public override string? Validate(string fieldLabel, object? value)
    {
        var s = value?.ToString();
        if (string.IsNullOrEmpty(s)) return null; // Required handles emptiness
        if (s.Length < Length)
            return ErrorMessage ?? $"{fieldLabel} must be at least {Length} characters.";
        return null;
    }
}

/// <summary>Enforces a maximum string length.</summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class MaxLengthAttribute : ValidationAttribute
{
    public int Length { get; }
    public MaxLengthAttribute(int length) => Length = length;

    public override string? Validate(string fieldLabel, object? value)
    {
        var s = value?.ToString();
        if (string.IsNullOrEmpty(s)) return null;
        if (s.Length > Length)
            return ErrorMessage ?? $"{fieldLabel} must be at most {Length} characters.";
        return null;
    }
}

/// <summary>Enforces a numeric range.</summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class RangeAttribute : ValidationAttribute
{
    public double Min { get; }
    public double Max { get; }
    public RangeAttribute(double min, double max) { Min = min; Max = max; }

    public override string? Validate(string fieldLabel, object? value)
    {
        if (value == null) return null;
        if (!double.TryParse(value.ToString(), out var num)) return null; // Type validation handles parse errors
        if (num < Min || num > Max)
            return ErrorMessage ?? $"{fieldLabel} must be between {Min} and {Max}.";
        return null;
    }
}

/// <summary>Validates against a regex pattern.</summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = true)]
public sealed class RegexPatternAttribute : ValidationAttribute
{
    public string Pattern { get; }
    public RegexPatternAttribute(string pattern) => Pattern = pattern;

    public override string? Validate(string fieldLabel, object? value)
    {
        var s = value?.ToString();
        if (string.IsNullOrEmpty(s)) return null;
        if (!Regex.IsMatch(s, Pattern))
            return ErrorMessage ?? $"{fieldLabel} does not match the required format.";
        return null;
    }
}

/// <summary>Validates email address format.</summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class EmailAddressAttribute : ValidationAttribute
{
    private static readonly Regex EmailRegex = new(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled);

    public override string? Validate(string fieldLabel, object? value)
    {
        var s = value?.ToString();
        if (string.IsNullOrEmpty(s)) return null;
        if (!EmailRegex.IsMatch(s))
            return ErrorMessage ?? $"{fieldLabel} must be a valid email address.";
        return null;
    }
}

/// <summary>Validates URL format.</summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class UrlAttribute : ValidationAttribute
{
    public override string? Validate(string fieldLabel, object? value)
    {
        var s = value?.ToString();
        if (string.IsNullOrEmpty(s)) return null;
        if (!Uri.TryCreate(s, UriKind.Absolute, out var uri) ||
            (uri.Scheme != "http" && uri.Scheme != "https"))
            return ErrorMessage ?? $"{fieldLabel} must be a valid URL.";
        return null;
    }
}

/// <summary>Validates phone number format.</summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class PhoneAttribute : ValidationAttribute
{
    private static readonly Regex PhoneRegex = new(@"^[\+]?[\d\s\-\(\)\.]{7,20}$", RegexOptions.Compiled);

    public override string? Validate(string fieldLabel, object? value)
    {
        var s = value?.ToString();
        if (string.IsNullOrEmpty(s)) return null;
        if (!PhoneRegex.IsMatch(s))
            return ErrorMessage ?? $"{fieldLabel} must be a valid phone number.";
        return null;
    }
}

/// <summary>
/// Expression-based validation rule. Uses the ExpressionParser to evaluate a boolean expression.
/// Can reference any field on the entity (cross-field validation).
/// Apply to a property or to the class for entity-level rules.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Class, Inherited = true, AllowMultiple = true)]
public sealed class ValidationRuleAttribute : Attribute
{
    /// <summary>
    /// Boolean expression to evaluate (e.g., "EndDate > StartDate", "Quantity > 0").
    /// Must evaluate to a truthy value for the entity to be valid.
    /// </summary>
    public string Expression { get; }

    /// <summary>Error message to display when the rule fails.</summary>
    public string Message { get; }

    public ValidationRuleAttribute(string expression, string message)
    {
        Expression = expression;
        Message = message;
    }
}
