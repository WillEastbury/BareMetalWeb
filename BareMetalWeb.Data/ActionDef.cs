namespace BareMetalWeb.Data;

/// <summary>Severity levels for AssertIf validation.</summary>
public enum Severity : byte { Error = 0, Warning = 1, Info = 2 }

/// <summary>Base type for all action commands.</summary>
public abstract record Command;

/// <summary>
/// Validation assertion. Evaluated during commit.
/// Error severity → abort entire envelope. Never mutates.
/// </summary>
public sealed record AssertIfCommand(
    Expr Condition,
    string Code,
    Severity Severity,
    string Message
) : Command;

/// <summary>
/// Conditional field mutation: if condition is true, set fieldId to valueExpr.
/// Produces a FieldDelta for the current aggregate.
/// </summary>
public sealed record SetIfCommand(
    Expr Condition,
    string FieldName,
    Expr ValueExpr
) : Command;

/// <summary>
/// Same as SetIf but marks derived field intent (computed/calculated).
/// </summary>
public sealed record CalculateAndSetIfCommand(
    Expr Condition,
    string FieldName,
    Expr ValueExpr
) : Command;

/// <summary>
/// Iterate a list field in snapshot mode. Single level only.
/// Expands deterministically. Operations see the snapshot state.
/// </summary>
public sealed record ForSetCommand(
    string ListFieldName,
    Expr ItemCondition,
    Command[] Operations
) : Command;

/// <summary>
/// Iterate a list field with progressive semantics.
/// Mutations update working copy immediately.
/// Order must be deterministic. Used for allocation scenarios (e.g., stock).
/// </summary>
public sealed record ForSetSequentialCommand(
    string ListFieldName,
    Expr ItemCondition,
    Command[] Operations
) : Command;

/// <summary>
/// Cross-aggregate invocation: if condition, invoke another action on a target aggregate.
/// Flat only — no nested invokes in v1.
/// Expands before commit phase.
/// </summary>
public sealed record InvokeIfCommand(
    Expr Condition,
    string TargetAggregateType,
    string ActionId,
    IReadOnlyDictionary<string, Expr> ParameterMap
) : Command;

/// <summary>
/// Immutable action definition. Published once, never modified.
/// Commands execute in declared order.
/// Expansion produces a TransactionEnvelope.
/// </summary>
public sealed record ActionDef(
    string ActionId,
    string AggregateType,
    int Version,
    Command[] Commands
);

/// <summary>
/// A single aggregate mutation within a transaction envelope.
/// </summary>
public sealed record AggregateMutation(
    string AggregateType,
    uint AggregateId,
    List<FieldDelta> Changes
);

/// <summary>
/// Result of action expansion. Declares the full set of touched aggregates.
/// No dynamic aggregate discovery during commit.
/// </summary>
public sealed class TransactionEnvelope
{
    public required string ActionId { get; init; }
    public required string TransactionId { get; init; }
    public required List<AggregateMutation> Mutations { get; init; }
    public required List<AssertIfCommand> Assertions { get; init; }
    /// <summary>All aggregate keys touched (for lock acquisition).</summary>
    public required List<string> TouchedAggregateKeys { get; init; }
}

/// <summary>Result of a transaction commit.</summary>
public sealed record TransactionResult(
    bool Success,
    string? ErrorCode,
    string? ErrorMessage,
    IReadOnlyList<TransactionWarning>? Warnings
);

/// <summary>Non-fatal assertion warning.</summary>
public sealed record TransactionWarning(string Code, string Message);
