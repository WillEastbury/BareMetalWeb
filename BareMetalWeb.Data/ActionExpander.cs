using System.Collections;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Expands an ActionDef + parameters into a TransactionEnvelope.
/// Deterministic: same inputs → same envelope.
/// Server re-expands independently — never trusts client-supplied deltas.
/// </summary>
public sealed class ActionExpander
{
    private readonly Func<string, ActionDef?> _actionResolver;
    private readonly ExpressionEvaluator.AggregateReader? _aggregateReader;

    public ActionExpander(
        Func<string, ActionDef?> actionResolver,
        ExpressionEvaluator.AggregateReader? aggregateReader = null)
    {
        _actionResolver = actionResolver;
        _aggregateReader = aggregateReader;
    }

    /// <summary>
    /// Expand an action against a root entity.
    /// </summary>
    public TransactionEnvelope Expand(
        ActionDef action,
        object rootEntity,
        EntityLayout layout,
        IReadOnlyDictionary<string, object?>? parameters = null)
    {
        var txId = Guid.NewGuid().ToString("N");
        var mutations = new List<AggregateMutation>();
        var assertions = new List<AssertIfCommand>();
        var touchedKeys = new List<string>();

        var rootKey = GetEntityKey(rootEntity);
        var rootAggKey = $"{action.AggregateType}:{rootKey}";
        touchedKeys.Add(rootAggKey);

        var rootChanges = new List<FieldDelta>();
        var eval = new ExpressionEvaluator(layout, _aggregateReader);

        foreach (var cmd in action.Commands)
        {
            ExpandCommand(cmd, rootEntity, layout, eval, rootChanges, assertions,
                mutations, touchedKeys, parameters);
        }

        if (rootChanges.Count > 0)
        {
            mutations.Insert(0, new AggregateMutation(
                action.AggregateType, rootKey, rootChanges));
        }

        return new TransactionEnvelope
        {
            ActionId = action.ActionId,
            TransactionId = txId,
            Mutations = mutations,
            Assertions = assertions,
            TouchedAggregateKeys = touchedKeys,
        };
    }

    private void ExpandCommand(
        Command cmd, object entity, EntityLayout layout, ExpressionEvaluator eval,
        List<FieldDelta> changes, List<AssertIfCommand> assertions,
        List<AggregateMutation> mutations, List<string> touchedKeys,
        IReadOnlyDictionary<string, object?>? parameters)
    {
        switch (cmd)
        {
            case AssertIfCommand assert:
                assertions.Add(assert);
                break;

            case SetIfCommand setIf:
                if (eval.EvaluateBool(ResolveParams(setIf.Condition, parameters), entity))
                {
                    var value = eval.Evaluate(ResolveParams(setIf.ValueExpr, parameters), entity);
                    var field = layout.FieldByName(setIf.FieldName);
                    if (field != null)
                    {
                        var encoded = DeltaMutationEngine.EncodeFieldValue(field, value);
                        changes.Add(new FieldDelta((ushort)field.Ordinal, encoded));
                    }
                }
                break;

            case CalculateAndSetIfCommand calcIf:
                if (eval.EvaluateBool(ResolveParams(calcIf.Condition, parameters), entity))
                {
                    var value = eval.Evaluate(ResolveParams(calcIf.ValueExpr, parameters), entity);
                    var field = layout.FieldByName(calcIf.FieldName);
                    if (field != null)
                    {
                        var encoded = DeltaMutationEngine.EncodeFieldValue(field, value);
                        changes.Add(new FieldDelta((ushort)field.Ordinal, encoded));
                    }
                }
                break;

            case ForSetCommand forSet:
                ExpandForSet(forSet, entity, layout, eval, changes, parameters, progressive: false);
                break;

            case ForSetSequentialCommand forSeq:
                ExpandForSet(
                    new ForSetCommand(forSeq.ListFieldName, forSeq.ItemCondition, forSeq.Operations),
                    entity, layout, eval, changes, parameters, progressive: true);
                break;

            case InvokeIfCommand invoke:
                if (eval.EvaluateBool(ResolveParams(invoke.Condition, parameters), entity))
                {
                    ExpandInvoke(invoke, entity, layout, eval, mutations, touchedKeys, parameters);
                }
                break;
        }
    }

    private void ExpandForSet(
        ForSetCommand forSet, object entity, EntityLayout layout, ExpressionEvaluator eval,
        List<FieldDelta> changes, IReadOnlyDictionary<string, object?>? parameters,
        bool progressive)
    {
        var listField = layout.FieldByName(forSet.ListFieldName);
        if (listField == null) return;
        var listVal = listField.Getter(entity);
        if (listVal is not IEnumerable enumerable) return;

        foreach (var item in enumerable)
        {
            if (item == null) continue;
            if (!eval.EvaluateBool(ResolveParams(forSet.ItemCondition, parameters), entity, item))
                continue;

            foreach (var op in forSet.Operations)
            {
                switch (op)
                {
                    case SetIfCommand setIf:
                        if (eval.EvaluateBool(ResolveParams(setIf.Condition, parameters), entity, item))
                        {
                            var value = eval.Evaluate(ResolveParams(setIf.ValueExpr, parameters), entity, item);
                            var field = layout.FieldByName(setIf.FieldName);
                            if (field != null)
                            {
                                var encoded = DeltaMutationEngine.EncodeFieldValue(field, value);
                                changes.Add(new FieldDelta((ushort)field.Ordinal, encoded));
                                if (progressive) field.Setter(entity, value);
                            }
                        }
                        break;
                    case CalculateAndSetIfCommand calcIf:
                        if (eval.EvaluateBool(ResolveParams(calcIf.Condition, parameters), entity, item))
                        {
                            var value = eval.Evaluate(ResolveParams(calcIf.ValueExpr, parameters), entity, item);
                            var field = layout.FieldByName(calcIf.FieldName);
                            if (field != null)
                            {
                                var encoded = DeltaMutationEngine.EncodeFieldValue(field, value);
                                changes.Add(new FieldDelta((ushort)field.Ordinal, encoded));
                                if (progressive) field.Setter(entity, value);
                            }
                        }
                        break;
                }
            }
        }
    }

    private void ExpandInvoke(
        InvokeIfCommand invoke, object entity, EntityLayout layout, ExpressionEvaluator eval,
        List<AggregateMutation> mutations, List<string> touchedKeys,
        IReadOnlyDictionary<string, object?>? parameters)
    {
        var targetAction = _actionResolver($"{invoke.TargetAggregateType}:{invoke.ActionId}");
        if (targetAction == null) return;

        // Resolve parameter map
        var resolvedParams = new Dictionary<string, object?>();
        foreach (var (key, expr) in invoke.ParameterMap)
            resolvedParams[key] = eval.Evaluate(ResolveParams(expr, parameters), entity);

        // Determine target aggregate ID from params (convention: "Id" param)
        if (!resolvedParams.TryGetValue("Id", out var idObj)) return;
        uint targetId = Convert.ToUInt32(idObj);

        var aggKey = $"{invoke.TargetAggregateType}:{targetId}";
        if (!touchedKeys.Contains(aggKey)) touchedKeys.Add(aggKey);

        // Load target entity and expand target action against it
        if (!DataScaffold.TryGetEntity(invoke.TargetAggregateType, out var targetMeta)) return;
        var targetLayout = EntityLayoutCompiler.GetOrCompile(targetMeta);

        var loadTask = DataScaffold.LoadAsync(targetMeta, targetId);
        var targetEntity = loadTask.IsCompleted
            ? loadTask.Result
            : loadTask.AsTask().GetAwaiter().GetResult();
        if (targetEntity == null) return;

        var targetEval = new ExpressionEvaluator(targetLayout, _aggregateReader);
        var targetChanges = new List<FieldDelta>();
        var assertions = new List<AssertIfCommand>(); // collected but not used here

        foreach (var cmd in targetAction.Commands)
        {
            if (cmd is InvokeIfCommand) continue; // flat only — no nested invokes in v1
            ExpandCommand(cmd, targetEntity, targetLayout, targetEval,
                targetChanges, assertions, mutations, touchedKeys, resolvedParams);
        }

        if (targetChanges.Count > 0)
            mutations.Add(new AggregateMutation(invoke.TargetAggregateType, targetId, targetChanges));
    }

    /// <summary>Resolve ParamRefExpr nodes by substituting with actual parameter values.</summary>
    private static Expr ResolveParams(Expr expr, IReadOnlyDictionary<string, object?>? parameters)
    {
        if (parameters == null || parameters.Count == 0) return expr;
        return expr switch
        {
            ParamRefExpr p => parameters.TryGetValue(p.ParamName, out var val)
                ? new LiteralExpr(val) : expr,
            BinaryExpr b => b with
            {
                Left = ResolveParams(b.Left, parameters),
                Right = ResolveParams(b.Right, parameters)
            },
            UnaryExpr u => u with { Operand = ResolveParams(u.Operand, parameters) },
            ConditionalExpr c => c with
            {
                Condition = ResolveParams(c.Condition, parameters),
                Then = ResolveParams(c.Then, parameters),
                Else = ResolveParams(c.Else, parameters)
            },
            _ => expr,
        };
    }

    private static uint GetEntityKey(object entity)
    {
        if (entity is IBaseDataObject obj) return obj.Key;
        return 0;
    }
}
