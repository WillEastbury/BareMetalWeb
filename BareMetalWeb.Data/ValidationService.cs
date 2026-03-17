using System;
using System.Collections.Generic;
using BareMetalWeb.Core;
using BareMetalWeb.Data.ExpressionEngine;

namespace BareMetalWeb.Data;

/// <summary>
/// Validation configuration for a single field, built from attributes at registration time.
/// </summary>
public sealed record ValidationConfig(
    int? MinLength,
    int? MaxLength,
    double? RangeMin,
    double? RangeMax,
    string? RegexPattern,
    string? RegexMessage,
    bool IsEmail,
    bool IsUrl,
    bool IsPhone,
    IReadOnlyList<ValidationAttribute> CustomValidators,
    IReadOnlyList<ValidationRuleAttribute> ExpressionRules
);

/// <summary>
/// Server-side validation service. Validates field values using metadata-driven rules
/// and expression-based cross-field rules via the ExpressionParser.
/// All validation config is built at entity registration time — zero runtime reflection.
/// </summary>
public static class ValidationService
{
    /// <summary>
    /// Validate a single field value using its ValidationConfig.
    /// Returns a list of error messages (empty if valid).
    /// </summary>
    public static List<string> ValidateField(DataFieldMetadata field, object? value)
    {
        var errors = new List<string>();
        var config = field.Validation;
        if (config == null) return errors;

        // Run each attribute-based validator
        foreach (var validator in config.CustomValidators)
        {
            var error = validator.Validate(field.Label, value);
            if (error != null)
                errors.Add(error);
        }

        return errors;
    }

    /// <summary>
    /// Validate all fields on an entity instance using attribute validators and expression rules.
    /// Returns per-field errors and entity-level errors.
    /// </summary>
    public static ValidationResult ValidateEntity(DataEntityMetadata metadata, object instance)
    {
        var fieldErrors = new Dictionary<string, List<string>>();
        var entityErrors = new List<string>();

        // Build context for expression evaluation (all field values)
        var context = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var field in metadata.Fields)
        {
            try
            {
                context[field.Name] = field.GetValueFn(instance);
            }
            catch
            {
                context[field.Name] = null;
            }
        }

        // Validate each field
        foreach (var field in metadata.Fields)
        {
            // Skip computed and calculated fields
            if (field.Computed != null || field.Calculated != null || field.ReadOnly)
                continue;

            var value = context.GetValueOrDefault(field.Name);
            var errors = ValidateField(field, value);

            // Evaluate per-field expression rules
            if (field.Validation?.ExpressionRules != null)
            {
                foreach (var rule in field.Validation.ExpressionRules)
                {
                    if (!EvaluateExpressionRule(rule.Expression, context))
                        errors.Add(rule.Message);
                }
            }

            if (errors.Count > 0)
                fieldErrors[field.Name] = errors;
        }

        // Evaluate entity-level expression rules (stored in metadata at registration time)
        if (metadata.EntityValidationRules != null)
        {
            foreach (var rule in metadata.EntityValidationRules)
            {
                if (!EvaluateExpressionRule(rule.Expression, context))
                    entityErrors.Add(rule.Message);
            }
        }

        return new ValidationResult(fieldErrors, entityErrors);
    }

    /// <summary>
    /// Evaluate an expression rule and return true if it passes (truthy result).
    /// </summary>
    private static bool EvaluateExpressionRule(string expression, Dictionary<string, object?> context)
    {
        try
        {
            var parser = new ExpressionParser();
            var ast = parser.Parse(expression);
            var result = ast.Evaluate(context);
            return IsTruthy(result);
        }
        catch
        {
            // If expression fails to parse/evaluate, treat as passing
            // (don't block saves due to bad validation expressions)
            return true;
        }
    }

    private static bool IsTruthy(object? value)
    {
        if (value == null) return false;
        if (value is bool b) return b;
        if (value is string s) return !string.IsNullOrEmpty(s);
        if (decimal.TryParse(value.ToString(), out var num)) return num != 0;
        return true;
    }

    /// <summary>
    /// Generate a JavaScript expression for a validation rule (for client-side validation).
    /// </summary>
    public static string? GenerateJavaScriptRule(string expression)
    {
        try
        {
            var parser = new ExpressionParser();
            var ast = parser.Parse(expression);
            return ast.ToJavaScript();
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>
/// Result of entity validation containing per-field and entity-level errors.
/// </summary>
public sealed class ValidationResult
{
    public Dictionary<string, List<string>> FieldErrors { get; }
    public List<string> EntityErrors { get; }
    public bool IsValid => FieldErrors.Count == 0 && EntityErrors.Count == 0;

    public ValidationResult(Dictionary<string, List<string>> fieldErrors, List<string> entityErrors)
    {
        FieldErrors = fieldErrors;
        EntityErrors = entityErrors;
    }

    /// <summary>
    /// Flatten all errors into a single list of messages.
    /// </summary>
    public List<string> AllErrors()
    {
        var all = new List<string>();
        foreach (var kvp in FieldErrors)
            all.AddRange(kvp.Value);
        all.AddRange(EntityErrors);
        return all;
    }
}
