namespace BareMetalWeb.Runtime;

/// <summary>Severity level for an <see cref="AssertIfCommand"/>.</summary>
public enum AssertSeverity : byte
{
    /// <summary>Validation error — aborts the entire envelope on failure.</summary>
    Error = 0,
    /// <summary>Non-fatal warning — recorded in the envelope but does not abort.</summary>
    Warning = 1,
    /// <summary>Informational diagnostic — always recorded, never aborts.</summary>
    Info = 2,
}

/// <summary>
/// Base type for all v1.1 action command primitives.
/// Commands are evaluated in declared order during action expansion and produce
/// field-level deltas or assertions in a <see cref="TransactionEnvelope"/>.
/// They are never directly replayed — only the resulting deltas are.
/// </summary>
public abstract record ActionCommand
{
    /// <summary>Declared execution order (ascending).</summary>
    public int Order { get; init; }
}

/// <summary>
/// Evaluates a condition at commit time and records an assertion result.
/// When <see cref="Severity"/> is <see cref="AssertSeverity.Error"/> and the condition
/// is <c>true</c> (i.e. the assertion fires), the entire envelope is aborted.
/// Never mutates aggregate state.
/// </summary>
public sealed record AssertIfCommand(
    int Order,
    string Condition,
    string Code,
    AssertSeverity Severity,
    string Message) : ActionCommand
{
    /// <inheritdoc />
    public new int Order { get; init; } = Order;
}

/// <summary>
/// If <see cref="Condition"/> evaluates to <c>true</c>, produces a field delta
/// that sets <see cref="FieldId"/> to the result of <see cref="ValueExpression"/>
/// on the current aggregate.
/// </summary>
public sealed record SetIfCommand(
    int Order,
    string Condition,
    string FieldId,
    string ValueExpression) : ActionCommand
{
    /// <inheritdoc />
    public new int Order { get; init; } = Order;
}

/// <summary>
/// Same semantics as <see cref="SetIfCommand"/> but marks the field delta as
/// derived-field intent (for tooling / audit purposes).
/// </summary>
public sealed record CalculateAndSetIfCommand(
    int Order,
    string Condition,
    string FieldId,
    string ValueExpression) : ActionCommand
{
    /// <inheritdoc />
    public new int Order { get; init; } = Order;
}

/// <summary>
/// Iterates all items in <see cref="ListFieldId"/> that satisfy <see cref="ItemCondition"/>
/// and applies <see cref="SubCommands"/> to each, using <em>snapshot</em> semantics
/// (mutations within the loop are not visible to subsequent iterations).
/// Single level only.
/// </summary>
public sealed record ForSetCommand(
    int Order,
    string ListFieldId,
    string ItemCondition,
    IReadOnlyList<ActionCommand> SubCommands) : ActionCommand
{
    /// <inheritdoc />
    public new int Order { get; init; } = Order;
}

/// <summary>
/// Like <see cref="ForSetCommand"/> but uses <em>progressive</em> semantics:
/// each mutation is applied to the working copy immediately and is visible to
/// subsequent iterations. Order must be deterministic. Used for allocation scenarios.
/// </summary>
public sealed record ForSetSequentialCommand(
    int Order,
    string ListFieldId,
    string ItemCondition,
    IReadOnlyList<ActionCommand> SubCommands) : ActionCommand
{
    /// <inheritdoc />
    public new int Order { get; init; } = Order;
}

/// <summary>
/// If <see cref="Condition"/> evaluates to <c>true</c>, expands the action identified
/// by <see cref="TargetActionId"/> on <see cref="TargetEntityType"/> and merges its
/// deltas into the enclosing <see cref="TransactionEnvelope"/>.
/// Flat only — nested InvokeIf chains are not permitted in v1.
/// </summary>
public sealed record InvokeIfCommand(
    int Order,
    string Condition,
    string TargetEntityType,
    string TargetActionId,
    IReadOnlyDictionary<string, string> ParameterMap) : ActionCommand
{
    /// <inheritdoc />
    public new int Order { get; init; } = Order;
}
