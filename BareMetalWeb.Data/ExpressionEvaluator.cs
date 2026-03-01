using System.Collections;
using System.Runtime.CompilerServices;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Evaluates structured expression trees against entity state.
/// Uses EntityLayout compiled getters — no reflection in evaluation.
/// Pure, deterministic, side-effect free.
/// </summary>
public sealed class ExpressionEvaluator
{
    /// <summary>Delegate for cross-aggregate reads: (aggregateType, aggregateId, fieldName) → value.</summary>
    public delegate object? AggregateReader(string aggregateType, uint aggregateId, string fieldName);

    private readonly EntityLayout _layout;
    private readonly AggregateReader? _reader;

    public ExpressionEvaluator(EntityLayout layout, AggregateReader? reader = null)
    {
        _layout = layout;
        _reader = reader;
    }

    /// <summary>Evaluate an expression against an entity instance.</summary>
    public object? Evaluate(Expr expr, object entity, object? currentItem = null)
    {
        return expr switch
        {
            LiteralExpr lit => lit.Value,
            FieldRefExpr fref => ReadField(entity, fref.FieldName),
            ItemFieldRefExpr iref => currentItem != null ? ReadField(currentItem, iref.FieldName) : null,
            ParamRefExpr => throw new InvalidOperationException("ParamRefExpr must be resolved before evaluation."),
            GetExpr get => EvaluateGet(get, entity, currentItem),
            BinaryExpr bin => EvaluateBinary(bin, entity, currentItem),
            UnaryExpr un => EvaluateUnary(un, entity, currentItem),
            ConditionalExpr cond => IsTruthy(Evaluate(cond.Condition, entity, currentItem))
                ? Evaluate(cond.Then, entity, currentItem)
                : Evaluate(cond.Else, entity, currentItem),
            AggregateExpr agg => EvaluateAggregate(agg, entity),
            _ => throw new InvalidOperationException($"Unknown expression type: {expr.GetType().Name}"),
        };
    }

    /// <summary>Evaluate and coerce to bool.</summary>
    public bool EvaluateBool(Expr expr, object entity, object? currentItem = null)
        => IsTruthy(Evaluate(expr, entity, currentItem));

    private object? ReadField(object entity, string fieldName)
    {
        var field = _layout.FieldByName(fieldName);
        return field?.Getter(entity);
    }

    private object? EvaluateGet(GetExpr get, object entity, object? currentItem)
    {
        if (_reader == null)
            throw new InvalidOperationException("Cross-aggregate reads require an AggregateReader.");
        var idVal = Evaluate(get.AggregateIdExpr, entity, currentItem);
        if (idVal == null) return null;
        uint id = Convert.ToUInt32(idVal);
        return _reader(get.AggregateType, id, get.FieldName);
    }

    private object? EvaluateBinary(BinaryExpr bin, object entity, object? currentItem)
    {
        var left = Evaluate(bin.Left, entity, currentItem);
        var right = Evaluate(bin.Right, entity, currentItem);

        return bin.Op switch
        {
            // Logical (short-circuit not needed since both evaluated)
            ExprOp.And => IsTruthy(left) && IsTruthy(right),
            ExprOp.Or => IsTruthy(left) || IsTruthy(right),

            // Comparison
            ExprOp.Eq => Equals(left, right),
            ExprOp.Ne => !Equals(left, right),
            ExprOp.Lt => CompareValues(left, right) < 0,
            ExprOp.Gt => CompareValues(left, right) > 0,
            ExprOp.Le => CompareValues(left, right) <= 0,
            ExprOp.Ge => CompareValues(left, right) >= 0,

            // Arithmetic
            ExprOp.Add => ArithOp(left, right, (a, b) => a + b),
            ExprOp.Sub => ArithOp(left, right, (a, b) => a - b),
            ExprOp.Mul => ArithOp(left, right, (a, b) => a * b),
            ExprOp.Div => ArithOp(left, right, (a, b) => b != 0 ? a / b : 0),
            ExprOp.Mod => ArithOp(left, right, (a, b) => b != 0 ? a % b : 0),

            _ => throw new InvalidOperationException($"Unknown binary op: {bin.Op}"),
        };
    }

    private object? EvaluateUnary(UnaryExpr un, object entity, object? currentItem)
    {
        var operand = Evaluate(un.Operand, entity, currentItem);
        return un.Op switch
        {
            ExprOp.Not => !IsTruthy(operand),
            ExprOp.Neg => operand switch
            {
                int i => -i,
                long l => -l,
                double d => -d,
                decimal m => -m,
                float f => -f,
                _ => -(ToDouble(operand)),
            },
            _ => throw new InvalidOperationException($"Unknown unary op: {un.Op}"),
        };
    }

    private object? EvaluateAggregate(AggregateExpr agg, object entity)
    {
        var listVal = ReadField(entity, agg.ListFieldName);
        if (listVal is not IEnumerable enumerable) return null;

        double sum = 0;
        int count = 0;
        double min = double.MaxValue;
        double max = double.MinValue;
        bool any = false;
        bool all = true;

        foreach (var item in enumerable)
        {
            if (item == null) continue;
            var val = Evaluate(agg.Selector, entity, item);
            count++;

            switch (agg.Fn)
            {
                case ExprAggregateFn.Sum:
                    sum += ToDouble(val);
                    break;
                case ExprAggregateFn.Count:
                    break;
                case ExprAggregateFn.Min:
                    var d = ToDouble(val);
                    if (d < min) min = d;
                    break;
                case ExprAggregateFn.Max:
                    var d2 = ToDouble(val);
                    if (d2 > max) max = d2;
                    break;
                case ExprAggregateFn.Any:
                    if (IsTruthy(val)) any = true;
                    break;
                case ExprAggregateFn.All:
                    if (!IsTruthy(val)) all = false;
                    break;
            }
        }

        return agg.Fn switch
        {
            ExprAggregateFn.Sum => sum,
            ExprAggregateFn.Count => count,
            ExprAggregateFn.Min => count > 0 ? min : null,
            ExprAggregateFn.Max => count > 0 ? max : null,
            ExprAggregateFn.Any => any,
            ExprAggregateFn.All => all && count > 0,
            _ => null,
        };
    }

    // ── Helpers ──

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsTruthy(object? val) => val switch
    {
        null => false,
        bool b => b,
        int i => i != 0,
        uint u => u != 0,
        long l => l != 0,
        double d => d != 0,
        decimal m => m != 0,
        string s => s.Length > 0,
        _ => true,
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static double ToDouble(object? val) => val switch
    {
        null => 0,
        int i => i,
        uint u => u,
        long l => l,
        ulong ul => ul,
        float f => f,
        double d => d,
        decimal m => (double)m,
        short s => s,
        ushort us => us,
        byte b => b,
        _ => Convert.ToDouble(val),
    };

    private static int CompareValues(object? left, object? right)
    {
        if (left == null && right == null) return 0;
        if (left == null) return -1;
        if (right == null) return 1;
        if (left is IComparable cmp) return cmp.CompareTo(right);
        return ToDouble(left).CompareTo(ToDouble(right));
    }

    private static object? ArithOp(object? left, object? right, Func<double, double, double> op)
    {
        if (left == null || right == null) return null;
        // Preserve decimal precision when both are decimal
        if (left is decimal ld && right is decimal rd)
        {
            double dl = (double)ld, dr = (double)rd;
            return (decimal)op(dl, dr);
        }
        return op(ToDouble(left), ToDouble(right));
    }
}
