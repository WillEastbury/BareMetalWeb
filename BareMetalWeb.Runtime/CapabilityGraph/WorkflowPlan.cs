namespace BareMetalWeb.Runtime.CapabilityGraph;

/// <summary>
/// The type of operation a workflow step performs.
/// Maps to <see cref="CapabilityType"/> but limited to executable operations.
/// </summary>
public enum StepType : byte
{
    Query,
    Create,
    Update,
    Delete,
    RunAction,
    RunWorkflow,
    Traverse
}

/// <summary>
/// A single step in a workflow plan, linked to a capability graph node.
/// </summary>
public readonly struct WorkflowStep
{
    public readonly int Order;
    public readonly StepType Type;
    public readonly string EntitySlug;
    public readonly string? Condition;
    public readonly string? ActionName;
    /// <summary>Output variable name that downstream steps can reference as input.</summary>
    public readonly string OutputVariable;
    /// <summary>Optional input variable from a prior step (-1 if none).</summary>
    public readonly string? InputVariable;
    /// <summary>ID of the corresponding node in the capability graph (-1 if unresolved).</summary>
    public readonly int CapabilityNodeId;

    public WorkflowStep(int order, StepType type, string entitySlug, string outputVariable,
        int capabilityNodeId, string? condition = null, string? actionName = null,
        string? inputVariable = null)
    {
        Order = order;
        Type = type;
        EntitySlug = entitySlug;
        Condition = condition;
        ActionName = actionName;
        OutputVariable = outputVariable;
        InputVariable = inputVariable;
        CapabilityNodeId = capabilityNodeId;
    }

    public override string ToString() =>
        ActionName != null
            ? $"[{Order}] {Type}({EntitySlug}.{ActionName}) → {OutputVariable}"
            : $"[{Order}] {Type}({EntitySlug}) → {OutputVariable}";
}

/// <summary>
/// An executable workflow plan generated from natural language intent via
/// capability graph traversal. Contains ordered steps with validated
/// input/output variable chaining.
/// </summary>
public sealed class WorkflowPlan
{
    public WorkflowStep[] Steps { get; }
    public bool IsValid { get; }
    public string[] ValidationErrors { get; }
    public string OriginalInput { get; }
    public DateTime CreatedUtc { get; }

    public WorkflowPlan(WorkflowStep[] steps, string originalInput, string[]? errors = null)
    {
        Steps = steps;
        OriginalInput = originalInput;
        CreatedUtc = DateTime.UtcNow;
        ValidationErrors = errors ?? [];
        IsValid = ValidationErrors.Length == 0 && Steps.Length > 0;
    }

    /// <summary>Summary statistics for diagnostics.</summary>
    public (int StepCount, int ErrorCount) Stats => (Steps.Length, ValidationErrors.Length);
}
