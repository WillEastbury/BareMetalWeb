using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
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
/// Server-side validation service. Validates field values using attribute-based rules
/// and expression-based cross-field rules via the ExpressionParser.
/// </summary>
public static class ValidationService
{
    private static readonly ConcurrentDictionary<Type, IReadOnlyList<ValidationRuleAttribute>> _entityRulesCache = new();

    /// <summary>
    /// Build a ValidationConfig from a property's attributes.
    /// Called at registration time only (not per-request).
    /// </summary>
    [RequiresUnreferencedCode("Attribute scanning requires property metadata to be preserved.")]
    public static ValidationConfig? BuildValidationConfig(PropertyInfo property)
    {
        var validators = new List<ValidationAttribute>();
        foreach (var attr in property.GetCustomAttributes())
        {
            if (attr is ValidationAttribute va)
                validators.Add(va);
        }

        var expressionRules = new List<ValidationRuleAttribute>();
        foreach (var rule in property.GetCustomAttributes<ValidationRuleAttribute>())
            expressionRules.Add(rule);

        if (validators.Count == 0 && expressionRules.Count == 0)
            return null;

        int? minLength = null;
        int? maxLength = null;
        double? rangeMin = null;
        double? rangeMax = null;
        string? regexPattern = null;
        string? regexMessage = null;
        bool isEmail = false;
        bool isUrl = false;
        bool isPhone = false;

        foreach (var v in validators)
        {
            switch (v)
            {
                case MinLengthAttribute ml:
                    minLength = ml.Length;
                    break;
                case MaxLengthAttribute mx:
                    maxLength = mx.Length;
                    break;
                case RangeAttribute r:
                    rangeMin = r.Min;
                    rangeMax = r.Max;
                    break;
                case RegexPatternAttribute rp:
                    regexPattern = rp.Pattern;
                    regexMessage = rp.ErrorMessage;
                    break;
                case EmailAddressAttribute:
                    isEmail = true;
                    break;
                case UrlAttribute:
                    isUrl = true;
                    break;
                case PhoneAttribute:
                    isPhone = true;
                    break;
            }
        }

        return new ValidationConfig(
            minLength, maxLength, rangeMin, rangeMax,
            regexPattern, regexMessage,
            isEmail, isUrl, isPhone,
            validators, expressionRules
        );
    }

    /// <summary>
    /// Get entity-level validation rules (applied to the class, not individual properties).
    /// Results are cached per type to avoid repeated attribute scanning.
    /// </summary>
    [RequiresUnreferencedCode("Attribute scanning requires entity type metadata to be preserved.")]
    public static IReadOnlyList<ValidationRuleAttribute> GetEntityRules(Type entityType)
    {
        return _entityRulesCache.GetOrAdd(entityType, static t =>
        {
            var rules = new List<ValidationRuleAttribute>();
            foreach (var rule in t.GetCustomAttributes<ValidationRuleAttribute>())
                rules.Add(rule);
            return rules;
        });
    }

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

        // Evaluate entity-level expression rules
        var entityRules = GetEntityRules(metadata.Type);
        foreach (var rule in entityRules)
        {
            if (!EvaluateExpressionRule(rule.Expression, context))
                entityErrors.Add(rule.Message);
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
