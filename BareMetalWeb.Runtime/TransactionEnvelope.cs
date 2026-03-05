namespace BareMetalWeb.Runtime;

/// <summary>
/// A single field-level value change within an <see cref="AggregateMutation"/>.
/// </summary>
public sealed class FieldValueChange
{
    public FieldValueChange(string fieldId, object? newValue, bool isDerived = false)
    {
        FieldId = fieldId;
        NewValue = newValue;
        IsDerived = isDerived;
    }

    /// <summary>Logical field identifier (name or stable ID).</summary>
    public string FieldId { get; }

    /// <summary>New value to apply. Null clears the field.</summary>
    public object? NewValue { get; }

    /// <summary>
    /// <c>true</c> when this change was produced by a
    /// <see cref="CalculateAndSetIfCommand"/> (derived-field intent marker).
    /// </summary>
    public bool IsDerived { get; }
}

/// <summary>
/// All field-level changes to apply to a single aggregate instance.
/// </summary>
public sealed class AggregateMutation
{
    public AggregateMutation(string aggregateType, string aggregateId, IReadOnlyList<FieldValueChange> changes)
    {
        AggregateType = aggregateType;
        AggregateId = aggregateId;
        Changes = changes;
    }

    /// <summary>Entity type slug (e.g. "invoices").</summary>
    public string AggregateType { get; }

    /// <summary>Instance identity string.</summary>
    public string AggregateId { get; }

    /// <summary>Ordered list of field-level changes.</summary>
    public IReadOnlyList<FieldValueChange> Changes { get; }
}

/// <summary>Result of evaluating a single <see cref="AssertIfCommand"/>.</summary>
public sealed class AssertionResult
{
    public AssertionResult(string code, AssertSeverity severity, string message, bool fired)
    {
        Code = code;
        Severity = severity;
        Message = message;
        Fired = fired;
    }

    /// <summary>Machine-readable assertion code (e.g. "NEG_BALANCE").</summary>
    public string Code { get; }

    /// <summary>Severity of the assertion.</summary>
    public AssertSeverity Severity { get; }

    /// <summary>Human-readable message.</summary>
    public string Message { get; }

    /// <summary>
    /// <c>true</c> when the assertion condition evaluated to <c>true</c> (i.e. the rule was violated).
    /// An <see cref="AssertSeverity.Error"/> with <c>Fired=true</c> aborts the envelope.
    /// </summary>
    public bool Fired { get; }
}

/// <summary>
/// The output of expanding an action against aggregate state.
/// Carries the full set of aggregate mutations and assertion results.
/// The envelope must declare all touched aggregates before commit;
/// no dynamic aggregate discovery occurs during the commit phase.
/// </summary>
public sealed class TransactionEnvelope
{
    public TransactionEnvelope(
        string transactionId,
        IReadOnlyList<AggregateMutation> aggregateMutations,
        IReadOnlyList<AssertionResult> assertions)
    {
        TransactionId = transactionId;
        AggregateMutations = aggregateMutations;
        Assertions = assertions;
    }

    /// <summary>Unique identifier for this transaction expansion.</summary>
    public string TransactionId { get; }

    /// <summary>All aggregate mutations to be committed atomically.</summary>
    public IReadOnlyList<AggregateMutation> AggregateMutations { get; }

    /// <summary>All assertion results evaluated during expansion.</summary>
    public IReadOnlyList<AssertionResult> Assertions { get; }

    /// <summary>
    /// Returns <c>true</c> when no <see cref="AssertSeverity.Error"/> assertion fired.
    /// A <c>false</c> result means the commit must be aborted.
    /// </summary>
    public bool IsValid
    {
        get
        {
            foreach (var a in Assertions)
                if (a.Fired && a.Severity == AssertSeverity.Error) return false;
            return true;
        }
    }

    /// <summary>
    /// Returns the first error assertion that fired, or <c>null</c> when the envelope is valid.
    /// </summary>
    public AssertionResult? FirstError
    {
        get
        {
            foreach (var a in Assertions)
                if (a.Fired && a.Severity == AssertSeverity.Error) return a;
            return null;
        }
    }
}
