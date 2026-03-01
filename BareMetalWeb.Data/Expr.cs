namespace BareMetalWeb.Data;

/// <summary>Operators for expression evaluation. Stable IDs.</summary>
public enum ExprOp : byte
{
    // Comparison
    Eq = 1, Ne = 2, Lt = 3, Gt = 4, Le = 5, Ge = 6,
    // Arithmetic
    Add = 10, Sub = 11, Mul = 12, Div = 13, Mod = 14,
    // Logical
    And = 20, Or = 21, Not = 22,
    // Unary
    Neg = 30,
}

/// <summary>Aggregate functions usable in expressions (sum, count, min, max, any, all).</summary>
public enum ExprAggregateFn : byte
{
    Sum = 1, Count = 2, Min = 3, Max = 4, Any = 5, All = 6,
}

// ── Expression Tree ──
// Structured, deterministic, side-effect free. No textual scripting.

/// <summary>Base type for all expression tree nodes.</summary>
public abstract record Expr;

/// <summary>Constant value.</summary>
public sealed record LiteralExpr(object? Value) : Expr;

/// <summary>Field reference on the current aggregate.</summary>
public sealed record FieldRefExpr(string FieldName) : Expr;

/// <summary>Field reference within a ForSet item iteration.</summary>
public sealed record ItemFieldRefExpr(string FieldName) : Expr;

/// <summary>Cross-aggregate read: Get(AggregateType, AggregateId, FieldName).</summary>
public sealed record GetExpr(string AggregateType, Expr AggregateIdExpr, string FieldName) : Expr;

/// <summary>Binary operation: Left op Right.</summary>
public sealed record BinaryExpr(ExprOp Op, Expr Left, Expr Right) : Expr;

/// <summary>Unary operation: op Operand.</summary>
public sealed record UnaryExpr(ExprOp Op, Expr Operand) : Expr;

/// <summary>Ternary: if Condition then Then else Else.</summary>
public sealed record ConditionalExpr(Expr Condition, Expr Then, Expr Else) : Expr;

/// <summary>Aggregate over a list field: sum/count/min/max/any/all(listField, selector).</summary>
public sealed record AggregateExpr(ExprAggregateFn Fn, string ListFieldName, Expr Selector) : Expr;

/// <summary>Parameter reference — resolved during action expansion.</summary>
public sealed record ParamRefExpr(string ParamName) : Expr;

// ── Expression Builder (fluent API for constructing expressions) ──

public static class Ex
{
    public static LiteralExpr Lit(object? value) => new(value);
    public static FieldRefExpr Field(string name) => new(name);
    public static ItemFieldRefExpr Item(string name) => new(name);
    public static ParamRefExpr Param(string name) => new(name);
    public static GetExpr Get(string aggType, Expr idExpr, string field) => new(aggType, idExpr, field);

    public static BinaryExpr Eq(Expr l, Expr r) => new(ExprOp.Eq, l, r);
    public static BinaryExpr Ne(Expr l, Expr r) => new(ExprOp.Ne, l, r);
    public static BinaryExpr Lt(Expr l, Expr r) => new(ExprOp.Lt, l, r);
    public static BinaryExpr Gt(Expr l, Expr r) => new(ExprOp.Gt, l, r);
    public static BinaryExpr Le(Expr l, Expr r) => new(ExprOp.Le, l, r);
    public static BinaryExpr Ge(Expr l, Expr r) => new(ExprOp.Ge, l, r);
    public static BinaryExpr Add(Expr l, Expr r) => new(ExprOp.Add, l, r);
    public static BinaryExpr Sub(Expr l, Expr r) => new(ExprOp.Sub, l, r);
    public static BinaryExpr Mul(Expr l, Expr r) => new(ExprOp.Mul, l, r);
    public static BinaryExpr Div(Expr l, Expr r) => new(ExprOp.Div, l, r);
    public static BinaryExpr And(Expr l, Expr r) => new(ExprOp.And, l, r);
    public static BinaryExpr Or(Expr l, Expr r) => new(ExprOp.Or, l, r);
    public static UnaryExpr Not(Expr e) => new(ExprOp.Not, e);
    public static UnaryExpr Neg(Expr e) => new(ExprOp.Neg, e);
    public static ConditionalExpr If(Expr cond, Expr then, Expr @else) => new(cond, then, @else);

    public static AggregateExpr Sum(string listField, Expr selector) => new(ExprAggregateFn.Sum, listField, selector);
    public static AggregateExpr Count(string listField, Expr selector) => new(ExprAggregateFn.Count, listField, selector);
    public static AggregateExpr Min(string listField, Expr selector) => new(ExprAggregateFn.Min, listField, selector);
    public static AggregateExpr Max(string listField, Expr selector) => new(ExprAggregateFn.Max, listField, selector);
    public static AggregateExpr Any(string listField, Expr selector) => new(ExprAggregateFn.Any, listField, selector);
    public static AggregateExpr All(string listField, Expr selector) => new(ExprAggregateFn.All, listField, selector);
}
