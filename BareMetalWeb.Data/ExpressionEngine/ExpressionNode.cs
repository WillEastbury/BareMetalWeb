using System;
using System.Collections.Generic;

namespace BareMetalWeb.Data.ExpressionEngine;

/// <summary>
/// Abstract syntax tree node for expressions.
/// </summary>
public abstract class ExpressionNode
{
    public abstract object? Evaluate(IReadOnlyDictionary<string, object?> context);
    public abstract string ToJavaScript();
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
}
