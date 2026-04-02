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
[DataEntity("Action Commands", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1004)]
public class ActionCommandDefinition : DataRecord
{
    public override string EntityTypeName => "ActionCommandDefinition";
    private const int Ord_ActionId = BaseFieldCount + 0;
    private const int Ord_CommandType = BaseFieldCount + 1;
    private const int Ord_Order = BaseFieldCount + 2;
    private const int Ord_ParentCommandId = BaseFieldCount + 3;
    private const int Ord_Condition = BaseFieldCount + 4;
    private const int Ord_FieldId = BaseFieldCount + 5;
    private const int Ord_ValueExpression = BaseFieldCount + 6;
    private const int Ord_ListFieldId = BaseFieldCount + 7;
    private const int Ord_Severity = BaseFieldCount + 8;
    private const int Ord_ErrorCode = BaseFieldCount + 9;
    private const int Ord_Message = BaseFieldCount + 10;
    private const int Ord_TargetEntityType = BaseFieldCount + 11;
    private const int Ord_TargetActionId = BaseFieldCount + 12;
    private const int Ord_ParameterMap = BaseFieldCount + 13;
    internal const int TotalFieldCount = BaseFieldCount + 14;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("ActionId", Ord_ActionId),
        new FieldSlot("CommandType", Ord_CommandType),
        new FieldSlot("Condition", Ord_Condition),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("ErrorCode", Ord_ErrorCode),
        new FieldSlot("FieldId", Ord_FieldId),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("ListFieldId", Ord_ListFieldId),
        new FieldSlot("Message", Ord_Message),
        new FieldSlot("Order", Ord_Order),
        new FieldSlot("ParameterMap", Ord_ParameterMap),
        new FieldSlot("ParentCommandId", Ord_ParentCommandId),
        new FieldSlot("Severity", Ord_Severity),
        new FieldSlot("TargetActionId", Ord_TargetActionId),
        new FieldSlot("TargetEntityType", Ord_TargetEntityType),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("ValueExpression", Ord_ValueExpression),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public ActionCommandDefinition() : base(TotalFieldCount) { }
    public ActionCommandDefinition(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>FK to the owning <see cref="ActionDefinition"/>.</summary>
    [DataField(Label = "Action ID", Order = 1, Required = true)]
    [DataLookup(typeof(ActionDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string ActionId
    {
        get => (string?)_values[Ord_ActionId] ?? string.Empty;
        set => _values[Ord_ActionId] = value;
    }

    /// <summary>
    /// Discriminates the command type.
    /// One of: AssertIf | SetIf | CalculateAndSetIf | ForSet | ForSetSequential | InvokeIf.
    /// </summary>
    [DataField(Label = "Command Type", Order = 2, Required = true)]
    public string CommandType
    {
        get => (string?)_values[Ord_CommandType] ?? "SetIf";
        set => _values[Ord_CommandType] = value;
    }

    /// <summary>Execution order within the owning action (ascending).</summary>
    [DataField(Label = "Order", Order = 3)]
    public int Order
    {
        get => (int)(_values[Ord_Order] ?? 0);
        set => _values[Ord_Order] = value;
    }

    /// <summary>
    /// Optional FK to a parent <see cref="ActionCommandDefinition"/> for sub-commands
    /// inside a <c>ForSet</c> or <c>ForSetSequential</c> command.
    /// Null for top-level commands.
    /// </summary>
    [DataField(Label = "Parent Command ID", Order = 4)]
    public string? ParentCommandId
    {
        get => (string?)_values[Ord_ParentCommandId];
        set => _values[Ord_ParentCommandId] = value;
    }

    // ── Shared ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Boolean expression evaluated at expansion time.
    /// For <c>AssertIf</c>: fires the assertion when the expression is <c>true</c>.
    /// For <c>SetIf</c> / <c>CalculateAndSetIf</c>: applies the mutation only when <c>true</c>.
    /// For <c>ForSet</c> / <c>ForSetSequential</c>: item-level filter predicate.
    /// For <c>InvokeIf</c>: invokes the target action only when <c>true</c>.
    /// </summary>
    [DataField(Label = "Condition Expression", Order = 5)]
    public string? Condition
    {
        get => (string?)_values[Ord_Condition];
        set => _values[Ord_Condition] = value;
    }

    // ── SetIf / CalculateAndSetIf ─────────────────────────────────────────────

    /// <summary>Target field identifier for <c>SetIf</c> / <c>CalculateAndSetIf</c>.</summary>
    [DataField(Label = "Field ID", Order = 6)]
    public string? FieldId
    {
        get => (string?)_values[Ord_FieldId];
        set => _values[Ord_FieldId] = value;
    }

    /// <summary>
    /// Expression whose result is assigned to <see cref="FieldId"/>
    /// (for <c>SetIf</c> / <c>CalculateAndSetIf</c>).
    /// </summary>
    [DataField(Label = "Value Expression", Order = 7)]
    public string? ValueExpression
    {
        get => (string?)_values[Ord_ValueExpression];
        set => _values[Ord_ValueExpression] = value;
    }

    // ── ForSet / ForSetSequential ─────────────────────────────────────────────

    /// <summary>
    /// Name of the list field to iterate over (for <c>ForSet</c> / <c>ForSetSequential</c>).
    /// </summary>
    [DataField(Label = "List Field ID", Order = 8)]
    public string? ListFieldId
    {
        get => (string?)_values[Ord_ListFieldId];
        set => _values[Ord_ListFieldId] = value;
    }

    // ── AssertIf ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Assertion severity: <c>Error</c> | <c>Warning</c> | <c>Info</c>.
    /// Defaults to <c>Error</c>.
    /// </summary>
    [DataField(Label = "Severity", Order = 9)]
    public string? Severity
    {
        get => (string?)_values[Ord_Severity];
        set => _values[Ord_Severity] = value;
    }

    /// <summary>Machine-readable assertion code (e.g. "NEG_BALANCE").</summary>
    [DataField(Label = "Error Code", Order = 10)]
    public string? ErrorCode
    {
        get => (string?)_values[Ord_ErrorCode];
        set => _values[Ord_ErrorCode] = value;
    }

    /// <summary>Human-readable assertion message.</summary>
    [DataField(Label = "Message", Order = 11)]
    public string? Message
    {
        get => (string?)_values[Ord_Message];
        set => _values[Ord_Message] = value;
    }

    // ── InvokeIf ──────────────────────────────────────────────────────────────

    /// <summary>Slug of the target entity type for <c>InvokeIf</c>.</summary>
    [DataField(Label = "Target Entity Type", Order = 12)]
    public string? TargetEntityType
    {
        get => (string?)_values[Ord_TargetEntityType];
        set => _values[Ord_TargetEntityType] = value;
    }

    /// <summary>Name of the action to invoke on the target entity for <c>InvokeIf</c>.</summary>
    [DataField(Label = "Target Action ID", Order = 13)]
    public string? TargetActionId
    {
        get => (string?)_values[Ord_TargetActionId];
        set => _values[Ord_TargetActionId] = value;
    }

    /// <summary>
    /// JSON object mapping target parameter names to expressions evaluated against
    /// the current aggregate context. Used by <c>InvokeIf</c>.
    /// Example: <c>{"TargetId": "CurrentOrderId", "Amount": "LineTotal"}</c>.
    /// </summary>
    [DataField(Label = "Parameter Map (JSON)", Order = 14)]
    public string? ParameterMap
    {
        get => (string?)_values[Ord_ParameterMap];
        set => _values[Ord_ParameterMap] = value;
    }

    public override string ToString() => $"{CommandType}#{Order}";
}
