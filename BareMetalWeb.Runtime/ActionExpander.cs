using BareMetalWeb.Data.ExpressionEngine;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Expands a <see cref="RuntimeActionModel"/> against an aggregate context into a
/// <see cref="TransactionEnvelope"/> containing field-level deltas and assertion results.
///
/// Design principles (§8 Security Model):
/// <list type="bullet">
///   <item>The server always re-expands actions — client-supplied deltas are never trusted.</item>
///   <item>Expressions are evaluated using the pure, side-effect-free <see cref="ExpressionParser"/>.</item>
///   <item>InvokeIf is flat: target actions are expanded inline; nested InvokeIf is rejected.</item>
/// </list>
/// </summary>
public static class ActionExpander
{
    private static readonly ExpressionParser _parser = new();

    /// <summary>
    /// Expands <paramref name="action"/> against <paramref name="context"/> and returns a
    /// <see cref="TransactionEnvelope"/> with all mutations and assertion results.
    /// </summary>
    /// <param name="action">The action to expand (from <see cref="RuntimeEntityRegistry"/>).</param>
    /// <param name="aggregateType">Slug of the primary aggregate type.</param>
    /// <param name="aggregateId">Identity of the primary aggregate instance.</param>
    /// <param name="context">Field values of the primary aggregate (field name → value).</param>
    /// <param name="depth">Internal recursion guard — callers must leave at default (0).</param>
    public static TransactionEnvelope Expand(
        RuntimeActionModel action,
        string aggregateType,
        string aggregateId,
        IReadOnlyDictionary<string, object?> context,
        int depth = 0)
    {
        if (depth > 0)
            throw new InvalidOperationException(
                $"Nested InvokeIf chains are not supported in v1 (action '{action.Name}').");

        var mutations = new Dictionary<string, AggregateMutationBuilder>(StringComparer.OrdinalIgnoreCase);
        var assertions = new List<AssertionResult>();

        var primaryKey = $"{aggregateType}:{aggregateId}";
        GetOrCreate(mutations, primaryKey, aggregateType, aggregateId);

        // Working copy for progressive ForSetSequential semantics
        var workingContext = new Dictionary<string, object?>(context, StringComparer.OrdinalIgnoreCase);

        ProcessCommands(action.Commands, workingContext, primaryKey, aggregateType, aggregateId,
            mutations, assertions, depth);

        return new TransactionEnvelope(
            transactionId: Guid.NewGuid().ToString("N"),
            aggregateMutations: mutations.Values.Select(b => b.Build()).ToList(),
            assertions: assertions);
    }

    // ── Command processing ─────────────────────────────────────────────────────

    private static void ProcessCommands(
        IReadOnlyList<ActionCommand> commands,
        Dictionary<string, object?> workingContext,
        string primaryKey,
        string aggregateType,
        string aggregateId,
        Dictionary<string, AggregateMutationBuilder> mutations,
        List<AssertionResult> assertions,
        int depth)
    {
        foreach (var command in commands.OrderBy(c => c.Order))
        {
            switch (command)
            {
                case AssertIfCommand assertIf:
                    ProcessAssertIf(assertIf, workingContext, assertions);
                    break;

                case SetIfCommand setIf:
                    ProcessSetIf(setIf, workingContext, primaryKey, aggregateType, aggregateId,
                        mutations, isDerived: false);
                    break;

                case CalculateAndSetIfCommand calcSet:
                    ProcessSetIf(
                        new SetIfCommand(calcSet.Order, calcSet.Condition, calcSet.FieldId, calcSet.ValueExpression),
                        workingContext, primaryKey, aggregateType, aggregateId, mutations, isDerived: true);
                    break;

                case ForSetCommand forSet:
                    ProcessForSet(forSet, workingContext, primaryKey, aggregateType, aggregateId,
                        mutations, assertions, depth, progressive: false);
                    break;

                case ForSetSequentialCommand forSetSeq:
                    ProcessForSet(
                        new ForSetCommand(forSetSeq.Order, forSetSeq.ListFieldId, forSetSeq.ItemCondition, forSetSeq.SubCommands),
                        workingContext, primaryKey, aggregateType, aggregateId,
                        mutations, assertions, depth, progressive: true);
                    break;

                case InvokeIfCommand invokeIf:
                    ProcessInvokeIf(invokeIf, workingContext, mutations, assertions, depth);
                    break;
            }
        }
    }

    private static void ProcessAssertIf(
        AssertIfCommand cmd,
        IReadOnlyDictionary<string, object?> context,
        List<AssertionResult> assertions)
    {
        var fired = EvaluateBool(cmd.Condition, context);
        assertions.Add(new AssertionResult(
            code: cmd.Code,
            severity: cmd.Severity,
            message: cmd.Message,
            fired: fired));
    }

    private static void ProcessSetIf(
        SetIfCommand cmd,
        Dictionary<string, object?> workingContext,
        string primaryKey,
        string aggregateType,
        string aggregateId,
        Dictionary<string, AggregateMutationBuilder> mutations,
        bool isDerived)
    {
        if (!EvaluateBool(cmd.Condition, workingContext))
            return;

        var newValue = EvaluateValue(cmd.ValueExpression, workingContext);
        GetOrCreate(mutations, primaryKey, aggregateType, aggregateId)
            .AddChange(cmd.FieldId, newValue, isDerived);

        // Keep working context current for subsequent commands
        workingContext[cmd.FieldId] = newValue;
    }

    private static void ProcessForSet(
        ForSetCommand cmd,
        Dictionary<string, object?> workingContext,
        string primaryKey,
        string aggregateType,
        string aggregateId,
        Dictionary<string, AggregateMutationBuilder> mutations,
        List<AssertionResult> assertions,
        int depth,
        bool progressive)
    {
        if (!workingContext.TryGetValue(cmd.ListFieldId, out var listObj)
            || listObj is not IEnumerable<IDictionary<string, object?>> items)
            return;

        // Snapshot: take a copy of the list so snapshot-mode doesn't see loop mutations
        var snapshot = items.ToList();

        foreach (var item in snapshot)
        {
            // Wrap to IReadOnlyDictionary for expression evaluation
            var readOnlyItem = item as IReadOnlyDictionary<string, object?>
                ?? new Dictionary<string, object?>(item, StringComparer.OrdinalIgnoreCase);

            if (!EvaluateBool(cmd.ItemCondition, readOnlyItem))
                continue;

            // For sub-commands, work on a per-item mutable context
            var itemContext = progressive
                ? (item is Dictionary<string, object?> dict
                    ? dict
                    : new Dictionary<string, object?>(item, StringComparer.OrdinalIgnoreCase))
                : new Dictionary<string, object?>(item, StringComparer.OrdinalIgnoreCase);

            ProcessCommands(cmd.SubCommands, itemContext,
                primaryKey, aggregateType, aggregateId, mutations, assertions, depth);
        }
    }

    private static void ProcessInvokeIf(
        InvokeIfCommand cmd,
        IReadOnlyDictionary<string, object?> context,
        Dictionary<string, AggregateMutationBuilder> mutations,
        List<AssertionResult> assertions,
        int depth)
    {
        if (!EvaluateBool(cmd.Condition, context))
            return;

        // Resolve target action from RuntimeEntityRegistry
        if (!RuntimeEntityRegistry.Current.TryGet(cmd.TargetEntityType, out var targetModel))
            return;

        var targetAction = targetModel.Actions
            .FirstOrDefault(a => string.Equals(a.Name, cmd.TargetActionId, StringComparison.OrdinalIgnoreCase));

        if (targetAction == null)
            return;

        // Build target context by evaluating parameter map expressions
        var targetContext = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (param, expr) in cmd.ParameterMap)
            targetContext[param] = EvaluateValue(expr, context);

        // Resolve AggregateId for the target — convention: "Id" param maps to target instance id
        cmd.ParameterMap.TryGetValue("Id", out var targetIdExpr);
        var targetAggregateId = targetIdExpr != null
            ? (EvaluateValue(targetIdExpr, context)?.ToString() ?? string.Empty)
            : string.Empty;

        // Flat expand (depth+1 guards against nesting)
        var childEnvelope = Expand(targetAction, cmd.TargetEntityType, targetAggregateId,
            targetContext, depth + 1);

        // Merge child mutations into parent
        foreach (var mutation in childEnvelope.AggregateMutations)
        {
            var key = $"{mutation.AggregateType}:{mutation.AggregateId}";
            var builder = GetOrCreate(mutations, key, mutation.AggregateType, mutation.AggregateId);
            foreach (var change in mutation.Changes)
                builder.AddChange(change.FieldId, change.NewValue, change.IsDerived);
        }

        assertions.AddRange(childEnvelope.Assertions);
    }

    // ── Expression helpers ─────────────────────────────────────────────────────

    private static bool EvaluateBool(string? expression, IReadOnlyDictionary<string, object?> context)
    {
        if (string.IsNullOrWhiteSpace(expression))
            return true; // empty condition = unconditional

        try
        {
            var ast = _parser.Parse(expression);
            var result = ast.Evaluate(context);
            return result switch
            {
                bool b => b,
                string s => bool.TryParse(s, out var bv) && bv,
                null => false,
                _ => Convert.ToBoolean(result)
            };
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Condition expression '{expression}' failed to evaluate: {ex.Message}", ex);
        }
    }

    private static object? EvaluateValue(string? expression, IReadOnlyDictionary<string, object?> context)
    {
        if (string.IsNullOrWhiteSpace(expression))
            return null;

        try
        {
            var ast = _parser.Parse(expression);
            return ast.Evaluate(context);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Value expression '{expression}' failed to evaluate: {ex.Message}", ex);
        }
    }

    // ── Builder helpers ────────────────────────────────────────────────────────

    private static AggregateMutationBuilder GetOrCreate(
        Dictionary<string, AggregateMutationBuilder> dict,
        string key,
        string aggregateType,
        string aggregateId)
    {
        if (!dict.TryGetValue(key, out var builder))
        {
            builder = new AggregateMutationBuilder(aggregateType, aggregateId);
            dict[key] = builder;
        }

        return builder;
    }

    // ── Internal builder ───────────────────────────────────────────────────────

    internal sealed class AggregateMutationBuilder
    {
        private readonly string _type;
        private readonly string _id;
        private readonly List<FieldValueChange> _changes = new();

        public AggregateMutationBuilder(string type, string id)
        {
            _type = type;
            _id = id;
        }

        public void AddChange(string fieldId, object? newValue, bool isDerived)
            => _changes.Add(new FieldValueChange(fieldId, newValue, isDerived));

        public AggregateMutation Build()
            => new(_type, _id, _changes.AsReadOnly());
    }
}
