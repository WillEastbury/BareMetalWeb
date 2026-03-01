using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted definition of a single v1.1 command primitive belonging to an
/// <see cref="ActionDefinition"/>.  Commands are loaded at startup, compiled into
/// in-memory <see cref="ActionCommand"/> objects and attached to the owning
/// <see cref="RuntimeActionModel"/>.
///
/// Supported <see cref="CommandType"/> values:
/// <c>AssertIf</c>, <c>SetIf</c>, <c>CalculateAndSetIf</c>,
/// <c>ForSet</c>, <c>ForSetSequential</c>, <c>InvokeIf</c>.
/// </summary>
[DataEntity("Action Commands", ShowOnNav = false, NavGroup = "System", NavOrder = 1004)]
public class ActionCommandDefinition : RenderableDataObject
{
    /// <summary>FK to the owning <see cref="ActionDefinition"/>.</summary>
    [DataField(Label = "Action ID", Order = 1, Required = true)]
    [DataLookup(typeof(ActionDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string ActionId { get; set; } = string.Empty;

    /// <summary>
    /// Discriminates the command type.
    /// One of: AssertIf | SetIf | CalculateAndSetIf | ForSet | ForSetSequential | InvokeIf.
    /// </summary>
    [DataField(Label = "Command Type", Order = 2, Required = true)]
    public string CommandType { get; set; } = "SetIf";

    /// <summary>Execution order within the owning action (ascending).</summary>
    [DataField(Label = "Order", Order = 3)]
    public int Order { get; set; }

    /// <summary>
    /// Optional FK to a parent <see cref="ActionCommandDefinition"/> for sub-commands
    /// inside a <c>ForSet</c> or <c>ForSetSequential</c> command.
    /// Null for top-level commands.
    /// </summary>
    [DataField(Label = "Parent Command ID", Order = 4)]
    public string? ParentCommandId { get; set; }

    // ── Shared ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Boolean expression evaluated at expansion time.
    /// For <c>AssertIf</c>: fires the assertion when the expression is <c>true</c>.
    /// For <c>SetIf</c> / <c>CalculateAndSetIf</c>: applies the mutation only when <c>true</c>.
    /// For <c>ForSet</c> / <c>ForSetSequential</c>: item-level filter predicate.
    /// For <c>InvokeIf</c>: invokes the target action only when <c>true</c>.
    /// </summary>
    [DataField(Label = "Condition Expression", Order = 5)]
    public string? Condition { get; set; }

    // ── SetIf / CalculateAndSetIf ─────────────────────────────────────────────

    /// <summary>Target field identifier for <c>SetIf</c> / <c>CalculateAndSetIf</c>.</summary>
    [DataField(Label = "Field ID", Order = 6)]
    public string? FieldId { get; set; }

    /// <summary>
    /// Expression whose result is assigned to <see cref="FieldId"/>
    /// (for <c>SetIf</c> / <c>CalculateAndSetIf</c>).
    /// </summary>
    [DataField(Label = "Value Expression", Order = 7)]
    public string? ValueExpression { get; set; }

    // ── ForSet / ForSetSequential ─────────────────────────────────────────────

    /// <summary>
    /// Name of the list field to iterate over (for <c>ForSet</c> / <c>ForSetSequential</c>).
    /// </summary>
    [DataField(Label = "List Field ID", Order = 8)]
    public string? ListFieldId { get; set; }

    // ── AssertIf ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Assertion severity: <c>Error</c> | <c>Warning</c> | <c>Info</c>.
    /// Defaults to <c>Error</c>.
    /// </summary>
    [DataField(Label = "Severity", Order = 9)]
    public string? Severity { get; set; }

    /// <summary>Machine-readable assertion code (e.g. "NEG_BALANCE").</summary>
    [DataField(Label = "Error Code", Order = 10)]
    public string? ErrorCode { get; set; }

    /// <summary>Human-readable assertion message.</summary>
    [DataField(Label = "Message", Order = 11)]
    public string? Message { get; set; }

    // ── InvokeIf ──────────────────────────────────────────────────────────────

    /// <summary>Slug of the target entity type for <c>InvokeIf</c>.</summary>
    [DataField(Label = "Target Entity Type", Order = 12)]
    public string? TargetEntityType { get; set; }

    /// <summary>Name of the action to invoke on the target entity for <c>InvokeIf</c>.</summary>
    [DataField(Label = "Target Action ID", Order = 13)]
    public string? TargetActionId { get; set; }

    /// <summary>
    /// JSON object mapping target parameter names to expressions evaluated against
    /// the current aggregate context. Used by <c>InvokeIf</c>.
    /// Example: <c>{"TargetId": "CurrentOrderId", "Amount": "LineTotal"}</c>.
    /// </summary>
    [DataField(Label = "Parameter Map (JSON)", Order = 14)]
    public string? ParameterMap { get; set; }

    public override string ToString() => $"{CommandType}#{Order}";
}
