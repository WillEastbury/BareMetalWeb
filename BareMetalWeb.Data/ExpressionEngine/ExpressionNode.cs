using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace BareMetalWeb.Data.ExpressionEngine;

/// <summary>
/// Abstract syntax tree node for expressions.
/// </summary>
public abstract class ExpressionNode
{
    public abstract object? Evaluate(IReadOnlyDictionary<string, object?> context);
    public abstract string ToJavaScript();

    /// <summary>
    /// Async evaluation supporting relationship traversal via <see cref="ILookupResolver"/>.
    /// Default implementation delegates to synchronous <see cref="Evaluate"/>.
    /// </summary>
    public virtual ValueTask<object?> EvaluateAsync(
        IReadOnlyDictionary<string, object?> context,
        ILookupResolver? resolver,
        CancellationToken cancellationToken = default)
    {
        return new ValueTask<object?>(Evaluate(context));
    }
}

/// <summary>
/// Literal value (number, string, boolean).
/// </summary>
public sealed class LiteralNode : ExpressionNode
{
    public object? Value { get; }

    public LiteralNode(object? value)
    {
        Value = value;
    }

    public override object? Evaluate(IReadOnlyDictionary<string, object?> context)
    {
        return Value;
    }

    public override string ToJavaScript()
    {
        return Value switch
        {
            null => "null",
            string s => $"'{s.Replace("'", "\\'")}'",
            bool b => b ? "true" : "false",
            decimal d => d.ToString(System.Globalization.CultureInfo.InvariantCulture),
            double d => d.ToString(System.Globalization.CultureInfo.InvariantCulture),
            float f => f.ToString(System.Globalization.CultureInfo.InvariantCulture),
            _ => Value.ToString() ?? "null"
        };
    }
}

/// <summary>
/// Field reference (e.g., "Quantity", "UnitPrice").
/// </summary>
public sealed class FieldNode : ExpressionNode
{
    public string FieldName { get; }

    public FieldNode(string fieldName)
    {
        FieldName = fieldName;
    }

    public override object? Evaluate(IReadOnlyDictionary<string, object?> context)
    {
        if (context.TryGetValue(FieldName, out var value))
            return value;
        throw new InvalidOperationException($"Field '{FieldName}' not found in context.");
    }

    public override string ToJavaScript()
    {
        return $"parseFieldValue('{FieldName}')";
    }
}

/// <summary>
/// Binary operation (+, -, *, /, %).
/// </summary>
public sealed class BinaryOpNode : ExpressionNode
{
    public ExpressionNode Left { get; }
    public string Operator { get; }
    public ExpressionNode Right { get; }

    public BinaryOpNode(ExpressionNode left, string op, ExpressionNode right)
    {
        Left = left;
        Operator = op;
        Right = right;
    }

    public override object? Evaluate(IReadOnlyDictionary<string, object?> context)
    {
        var leftValue = Left.Evaluate(context);
        var rightValue = Right.Evaluate(context);

        if (Operator == "+" && (leftValue is string || rightValue is string))
        {
            return (leftValue?.ToString() ?? "") + (rightValue?.ToString() ?? "");
        }

        var left = ConvertToDecimal(leftValue);
        var right = ConvertToDecimal(rightValue);

        return Operator switch
        {
            "+" => left + right,
            "-" => left - right,
            "*" => left * right,
            "/" => right != 0 ? left / right : throw new DivideByZeroException(),
            "%" => right != 0 ? left % right : throw new DivideByZeroException(),
            ">" => (object)(left > right),
            "<" => (object)(left < right),
            ">=" => (object)(left >= right),
            "<=" => (object)(left <= right),
            "==" => (object)(left == right),
            "!=" => (object)(left != right),
            _ => throw new InvalidOperationException($"Unknown operator: {Operator}")
        };
    }

    public override string ToJavaScript()
    {
        return $"({Left.ToJavaScript()} {Operator} {Right.ToJavaScript()})";
    }

    public override async ValueTask<object?> EvaluateAsync(
        IReadOnlyDictionary<string, object?> context,
        ILookupResolver? resolver,
        CancellationToken cancellationToken = default)
    {
        var leftValue = await Left.EvaluateAsync(context, resolver, cancellationToken);
        var rightValue = await Right.EvaluateAsync(context, resolver, cancellationToken);

        if (Operator == "+" && (leftValue is string || rightValue is string))
            return (leftValue?.ToString() ?? "") + (rightValue?.ToString() ?? "");

        var left = ConvertToDecimal(leftValue);
        var right = ConvertToDecimal(rightValue);

        return Operator switch
        {
            "+" => left + right,
            "-" => left - right,
            "*" => left * right,
            "/" => right != 0 ? left / right : throw new DivideByZeroException(),
            "%" => right != 0 ? left % right : throw new DivideByZeroException(),
            ">" => (object)(left > right),
            "<" => (object)(left < right),
            ">=" => (object)(left >= right),
            "<=" => (object)(left <= right),
            "==" => (object)(left == right),
            "!=" => (object)(left != right),
            _ => throw new InvalidOperationException($"Unknown operator: {Operator}")
        };
    }

    private static decimal ConvertToDecimal(object? value)
    {
        if (value == null) return 0m;
        if (value is decimal d) return d;
        if (value is int i) return i;
        if (value is long l) return l;
        if (value is double dbl) return (decimal)dbl;
        if (value is float f) return (decimal)f;
        if (value is DateTime dt) return dt.Ticks;
        if (value is DateTimeOffset dto) return dto.Ticks;
        if (value is DateOnly dateOnly) return dateOnly.DayNumber;
        if (value is TimeOnly timeOnly) return timeOnly.Ticks;
        if (value is string s && decimal.TryParse(s, out var result)) return result;
        return 0m;
    }
}

/// <summary>
/// Unary operation (-, +).
/// </summary>
public sealed class UnaryOpNode : ExpressionNode
{
    public string Operator { get; }
    public ExpressionNode Operand { get; }

    public UnaryOpNode(string op, ExpressionNode operand)
    {
        Operator = op;
        Operand = operand;
    }

    public override object? Evaluate(IReadOnlyDictionary<string, object?> context)
    {
        var value = Operand.Evaluate(context);
        var numValue = ConvertToDecimal(value);

        return Operator switch
        {
            "-" => -numValue,
            "+" => numValue,
            _ => throw new InvalidOperationException($"Unknown unary operator: {Operator}")
        };
    }

    public override string ToJavaScript()
    {
        return $"{Operator}{Operand.ToJavaScript()}";
    }

    private static decimal ConvertToDecimal(object? value)
    {
        if (value == null) return 0m;
        if (value is decimal d) return d;
        if (value is int i) return i;
        if (value is long l) return l;
        if (value is double dbl) return (decimal)dbl;
        if (value is float f) return (decimal)f;
        if (value is string s && decimal.TryParse(s, out var result)) return result;
        return 0m;
    }
}

/// <summary>
/// Function call (Round, Min, Max, Abs, If).
/// </summary>
public sealed class FunctionNode : ExpressionNode
{
    public string FunctionName { get; }
    public IReadOnlyList<ExpressionNode> Arguments { get; }

    public FunctionNode(string functionName, IReadOnlyList<ExpressionNode> arguments)
    {
        FunctionName = functionName;
        Arguments = arguments;
    }

    public override object? Evaluate(IReadOnlyDictionary<string, object?> context)
    {
        return FunctionName.ToLowerInvariant() switch
        {
            "round" => EvaluateRound(context),
            "min" => EvaluateMin(context),
            "max" => EvaluateMax(context),
            "abs" => EvaluateAbs(context),
            "if" => EvaluateIf(context),
            "relatedlookup" => throw new InvalidOperationException("RelatedLookup requires async evaluation via EvaluateAsync."),
            "querylookup" => throw new InvalidOperationException("QueryLookup requires async evaluation via EvaluateAsync."),
            "lookupmultilevel" => throw new InvalidOperationException("LookupMultiLevel requires async evaluation via EvaluateAsync."),
            _ => throw new InvalidOperationException($"Unknown function: {FunctionName}")
        };
    }

    public override async ValueTask<object?> EvaluateAsync(
        IReadOnlyDictionary<string, object?> context,
        ILookupResolver? resolver,
        CancellationToken cancellationToken = default)
    {
        return FunctionName.ToLowerInvariant() switch
        {
            "round" => EvaluateRound(context),
            "min" => EvaluateMin(context),
            "max" => EvaluateMax(context),
            "abs" => EvaluateAbs(context),
            "if" => EvaluateIf(context),
            "relatedlookup" => await EvaluateRelatedLookupAsync(context, resolver, cancellationToken),
            "querylookup" => await EvaluateQueryLookupAsync(context, resolver, cancellationToken),
            "lookupmultilevel" => await EvaluateQueryLookupAsync(context, resolver, cancellationToken),
            _ => throw new InvalidOperationException($"Unknown function: {FunctionName}")
        };
    }

    public override string ToJavaScript()
    {
        var args = string.Join(", ", System.Linq.Enumerable.Select(Arguments, a => a.ToJavaScript()));

        return FunctionName.ToLowerInvariant() switch
        {
            "round" => $"roundNumber({args})",
            "min" => $"Math.min({args})",
            "max" => $"Math.max({args})",
            "abs" => $"Math.abs({args})",
            "if" => $"({Arguments[0].ToJavaScript()} ? {Arguments[1].ToJavaScript()} : {Arguments[2].ToJavaScript()})",
            "relatedlookup" => $"await bmwRelatedLookup({args})",
            "querylookup" => $"await bmwQueryLookup({args})",
            "lookupmultilevel" => $"await bmwQueryLookup({args})",
            _ => throw new InvalidOperationException($"Unknown function: {FunctionName}")
        };
    }

    private object? EvaluateRound(IReadOnlyDictionary<string, object?> context)
    {
        if (Arguments.Count < 1 || Arguments.Count > 2)
            throw new ArgumentException("Round expects 1 or 2 arguments");

        var value = ConvertToDecimal(Arguments[0].Evaluate(context));
        var decimals = Arguments.Count == 2
            ? Convert.ToInt32(Arguments[1].Evaluate(context))
            : 0;

        return Math.Round(value, decimals);
    }

    private object? EvaluateMin(IReadOnlyDictionary<string, object?> context)
    {
        if (Arguments.Count < 2)
            throw new ArgumentException("Min expects at least 2 arguments");

        var values = new List<decimal>();
        foreach (var arg in Arguments)
        {
            values.Add(ConvertToDecimal(arg.Evaluate(context)));
        }

        return values.Min();
    }

    private object? EvaluateMax(IReadOnlyDictionary<string, object?> context)
    {
        if (Arguments.Count < 2)
            throw new ArgumentException("Max expects at least 2 arguments");

        var values = new List<decimal>();
        foreach (var arg in Arguments)
        {
            values.Add(ConvertToDecimal(arg.Evaluate(context)));
        }

        return values.Max();
    }

    private object? EvaluateAbs(IReadOnlyDictionary<string, object?> context)
    {
        if (Arguments.Count != 1)
            throw new ArgumentException("Abs expects 1 argument");

        var value = ConvertToDecimal(Arguments[0].Evaluate(context));
        return Math.Abs(value);
    }

    private object? EvaluateIf(IReadOnlyDictionary<string, object?> context)
    {
        if (Arguments.Count != 3)
            throw new ArgumentException("If expects 3 arguments (condition, trueValue, falseValue)");

        var condition = Arguments[0].Evaluate(context);
        var isTrue = IsTruthy(condition);

        return isTrue
            ? Arguments[1].Evaluate(context)
            : Arguments[2].Evaluate(context);
    }

    private static bool IsTruthy(object? value)
    {
        if (value == null) return false;
        if (value is bool b) return b;
        if (value is string s) return !string.IsNullOrEmpty(s);
        var num = ConvertToDecimal(value);
        return num != 0;
    }

    private static decimal ConvertToDecimal(object? value)
    {
        if (value == null) return 0m;
        if (value is decimal d) return d;
        if (value is int i) return i;
        if (value is long l) return l;
        if (value is double dbl) return (decimal)dbl;
        if (value is float f) return (decimal)f;
        if (value is string s && decimal.TryParse(s, out var result)) return result;
        return 0m;
    }

    /// <summary>
    /// RelatedLookup(foreignKeyField, targetField)
    /// Follows a lookup relationship and returns a field from the related entity.
    /// </summary>
    private async ValueTask<object?> EvaluateRelatedLookupAsync(
        IReadOnlyDictionary<string, object?> context,
        ILookupResolver? resolver,
        CancellationToken cancellationToken)
    {
        if (resolver == null)
            throw new InvalidOperationException("RelatedLookup requires a lookup resolver.");
        if (Arguments.Count != 2)
            throw new ArgumentException("RelatedLookup expects 2 arguments: (foreignKeyField, targetField)");

        var fkField = GetStringArgument(Arguments[0], context, "foreignKeyField");
        var targetField = GetStringArgument(Arguments[1], context, "targetField");
        var entitySlug = context.TryGetValue("__entitySlug", out var slug) ? slug?.ToString() ?? "" : "";

        return await resolver.ResolveRelatedFieldAsync(entitySlug, fkField, targetField, context, cancellationToken);
    }

    /// <summary>
    /// QueryLookup(entitySlug, filterField1, filterValue1, ..., returnField)
    /// Queries an entity with equality filters and returns a field from the first match.
    /// Also used as the backing implementation for LookupMultiLevel.
    /// Filter values are evaluated asynchronously, enabling Parent.Field references.
    /// </summary>
    private async ValueTask<object?> EvaluateQueryLookupAsync(
        IReadOnlyDictionary<string, object?> context,
        ILookupResolver? resolver,
        CancellationToken cancellationToken)
    {
        if (resolver == null)
            throw new InvalidOperationException("QueryLookup requires a lookup resolver.");
        if (Arguments.Count < 4 || Arguments.Count % 2 != 0)
            throw new ArgumentException("QueryLookup expects: (entitySlug, filterField1, filterValue1, ..., returnField). Must have even number of args (minimum 4).");

        var entitySlug = GetStringArgument(Arguments[0], context, "entitySlug");
        var returnField = GetStringArgument(Arguments[Arguments.Count - 1], context, "returnField");

        var filters = new List<(string Field, object? Value)>();
        for (int idx = 1; idx < Arguments.Count - 1; idx += 2)
        {
            var filterField = GetStringArgument(Arguments[idx], context, $"filterField{(idx + 1) / 2}");
            var filterValue = await Arguments[idx + 1].EvaluateAsync(context, resolver, cancellationToken);
            filters.Add((filterField, filterValue));
        }

        return await resolver.QueryLookupAsync(entitySlug, filters, returnField, cancellationToken);
    }

    private static string GetStringArgument(ExpressionNode node, IReadOnlyDictionary<string, object?> context, string paramName)
    {
        var value = node.Evaluate(context);
        if (value is string str)
            return str;
        throw new ArgumentException($"Argument '{paramName}' must be a string literal, got: {value?.GetType().Name ?? "null"}");
    }
}

/// <summary>
/// Dot-access field traversal (e.g., CustomerId.DiscountLevel or CustomerId.RegionId.TaxRate).
/// Single-hop: left part is a FK field, right part is the target field on the related entity.
/// Multi-hop: each intermediate segment is a FK field on the previous entity.
/// Special case: <c>Parent.FieldName</c> reads the named field from the parent entity context
/// (populated via <see cref="CalculatedFieldService.EvaluateCalculatedFieldsAsync"/> parentContext).
/// </summary>
public sealed class DotAccessNode : ExpressionNode
{
    public string LookupField { get; }
    public IReadOnlyList<string> Path { get; }

    public DotAccessNode(string lookupField, IReadOnlyList<string> path)
    {
        LookupField = lookupField;
        Path = path;
    }

    public override object? Evaluate(IReadOnlyDictionary<string, object?> context)
    {
        // Parent.FieldName is resolvable synchronously from the context dictionary.
        if (string.Equals(LookupField, "Parent", StringComparison.OrdinalIgnoreCase))
        {
            if (Path.Count == 0) return null;
            var key = "Parent." + Path[Path.Count - 1];
            context.TryGetValue(key, out var parentValue);
            return parentValue;
        }

        throw new InvalidOperationException(
            $"Dot access '{LookupField}.{string.Join(".", Path)}' requires async evaluation via EvaluateAsync.");
    }

    public override async ValueTask<object?> EvaluateAsync(
        IReadOnlyDictionary<string, object?> context,
        ILookupResolver? resolver,
        CancellationToken cancellationToken = default)
    {
        // Parent.FieldName — read directly from the context (no resolver needed).
        if (string.Equals(LookupField, "Parent", StringComparison.OrdinalIgnoreCase))
        {
            if (Path.Count == 0) return null;
            var key = "Parent." + Path[Path.Count - 1];
            context.TryGetValue(key, out var parentValue);
            return parentValue;
        }

        if (resolver == null)
            throw new InvalidOperationException("Dot-access traversal requires a lookup resolver.");

        var entitySlug = context.TryGetValue("__entitySlug", out var slug) ? slug?.ToString() ?? "" : "";

        if (Path.Count == 1)
        {
            // Single-hop (existing behaviour).
            return await resolver.ResolveRelatedFieldAsync(entitySlug, LookupField, Path[0], context, cancellationToken);
        }

        // Multi-hop: build the full chain and delegate to ResolveChainAsync.
        var chain = new List<string>(Path.Count + 1) { LookupField };
        chain.AddRange(Path);
        return await resolver.ResolveChainAsync(entitySlug, chain, context, cancellationToken);
    }

    public override string ToJavaScript()
    {
        // Parent.Field cannot be expressed server-side in JS; emit a placeholder comment.
        if (string.Equals(LookupField, "Parent", StringComparison.OrdinalIgnoreCase))
            return $"/* Parent.{string.Join(".", Path)} — server-side only */null";

        // Multi-hop: pass full chain as a JSON array to bmwRelatedLookupChain.
        if (Path.Count > 1)
        {
            var chainParts = new List<string>(Path.Count + 1) { $"'{LookupField}'" };
            foreach (var seg in Path) chainParts.Add($"'{seg}'");
            return $"await bmwRelatedLookupChain([{string.Join(", ", chainParts)}])";
        }

        return $"await bmwRelatedLookup('{LookupField}', '{Path[0]}')";
    }
}
