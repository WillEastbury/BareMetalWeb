using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Full transaction commit pipeline:
/// 1. Acquire locks (sorted, deadlock-free)
/// 2. Load canonical state for all aggregates
/// 3. Apply envelope mutations to working copies
/// 4. Run all AssertIf validations
/// 5. If valid: save all mutations atomically, release locks, return success
/// 6. If invalid: release locks, return rejected
/// </summary>
public sealed class TransactionCommitEngine
{
    private readonly AggregateLockManager _lockManager;

    public TransactionCommitEngine(AggregateLockManager lockManager)
    {
        _lockManager = lockManager;
    }

    /// <summary>
    /// Commit a transaction envelope.
    /// All validation occurs inside lock scope.
    /// </summary>
    public async ValueTask<TransactionResult> CommitAsync(
        TransactionEnvelope envelope,
        string userName,
        CancellationToken cancellationToken = default)
    {
        // 1. Acquire all locks in sorted order
        using var lockHandle = _lockManager.AcquireAll(
            envelope.TouchedAggregateKeys, envelope.TransactionId);

        try
        {
            // 2. Load canonical state for all touched aggregates
            var loadedEntities = new Dictionary<string, (DataEntityMetadata Meta, BaseDataObject Entity, EntityLayout Layout)>();

            foreach (var mutation in envelope.Mutations)
            {
                var key = $"{mutation.AggregateType}:{mutation.AggregateId}";
                if (loadedEntities.ContainsKey(key)) continue;

                if (!DataScaffold.TryGetEntity(mutation.AggregateType, out var meta))
                    return Fail("ENTITY_NOT_FOUND", $"Unknown entity type '{mutation.AggregateType}'.");

                var entity = await DataScaffold.LoadAsync(meta, mutation.AggregateId, cancellationToken) as BaseDataObject;
                if (entity == null)
                    return Fail("ENTITY_NOT_FOUND", $"Entity {mutation.AggregateType}:{mutation.AggregateId} not found.");

                var layout = EntityLayoutCompiler.GetOrCompile(meta);
                loadedEntities[key] = (meta, entity, layout);
            }

            // 3. Apply mutations to working copies
            foreach (var mutation in envelope.Mutations)
            {
                var key = $"{mutation.AggregateType}:{mutation.AggregateId}";
                var (_, entity, layout) = loadedEntities[key];

                foreach (var change in mutation.Changes)
                {
                    if (change.Ordinal >= layout.Fields.Length)
                        return Fail("INVALID_ORDINAL", $"Field ordinal {change.Ordinal} out of range for {mutation.AggregateType}.");

                    var field = layout.Fields[change.Ordinal];
                    if (field.Is(FieldFlags.ReadOnly)) continue;

                    if (change.IsNull)
                    {
                        if (!field.Is(FieldFlags.Nullable))
                            return Fail("VALIDATION_FAILED", $"Field '{field.Name}' on {mutation.AggregateType} is not nullable.");
                        field.Setter(entity, null);
                        continue;
                    }

                    var codec = CodecTable.Get(field.CodecId);
                    object? value = field.FixedSizeBytes > 0
                        ? codec.ReadFixed(change.Value.Span)
                        : codec.ReadVar(change.Value.Span);

                    if (field.Type == FieldType.EnumInt32 && value is int intVal)
                        value = Enum.ToObject(field.ClrType, intVal);

                    field.Setter(entity, value);
                }
            }

            // 4. Run all AssertIf validations
            var warnings = new List<TransactionWarning>();
            foreach (var assert in envelope.Assertions)
            {
                // Evaluate against the first (root) mutation's entity
                if (envelope.Mutations.Count == 0) continue;
                var rootMut = envelope.Mutations[0];
                var rootKey = $"{rootMut.AggregateType}:{rootMut.AggregateId}";
                if (!loadedEntities.TryGetValue(rootKey, out var root)) continue;

                var eval = new ExpressionEvaluator(root.Layout);
                bool conditionMet = eval.EvaluateBool(assert.Condition, root.Entity);

                if (!conditionMet)
                {
                    switch (assert.Severity)
                    {
                        case Severity.Error:
                            return Fail(assert.Code, assert.Message);
                        case Severity.Warning:
                            warnings.Add(new TransactionWarning(assert.Code, assert.Message));
                            break;
                        case Severity.Info:
                            warnings.Add(new TransactionWarning(assert.Code, assert.Message));
                            break;
                    }
                }
            }

            // 5. Save all mutations atomically
            foreach (var mutation in envelope.Mutations)
            {
                var key = $"{mutation.AggregateType}:{mutation.AggregateId}";
                var (meta, entity, _) = loadedEntities[key];
                entity.Touch(userName);
                await DataScaffold.SaveAsync(meta, entity, cancellationToken);
            }

            // 6. Success
            return new TransactionResult(
                Success: true,
                ErrorCode: null,
                ErrorMessage: null,
                Warnings: warnings.Count > 0 ? warnings : null);
        }
        catch (TimeoutException)
        {
            return Fail("LOCK_TIMEOUT", "Failed to acquire locks for transaction.");
        }
    }

    /// <summary>
    /// High-level: expand an action and commit in one call.
    /// Server re-expands independently (security model).
    /// </summary>
    public async ValueTask<TransactionResult> ExecuteActionAsync(
        ActionDef action,
        uint aggregateId,
        IReadOnlyDictionary<string, object?>? parameters,
        Func<string, ActionDef?> actionResolver,
        string userName,
        CancellationToken cancellationToken = default)
    {
        if (!DataScaffold.TryGetEntity(action.AggregateType, out var meta))
            return Fail("ENTITY_NOT_FOUND", $"Unknown entity type '{action.AggregateType}'.");

        var entity = await DataScaffold.LoadAsync(meta, aggregateId, cancellationToken) as BaseDataObject;
        if (entity == null)
            return Fail("ENTITY_NOT_FOUND", $"Entity {action.AggregateType}:{aggregateId} not found.");

        var layout = EntityLayoutCompiler.GetOrCompile(meta);

        // Server-side expansion (never trust client delta)
        var expander = new ActionExpander(actionResolver);
        var envelope = expander.Expand(action, entity, layout, parameters);

        return await CommitAsync(envelope, userName, cancellationToken);
    }

    private static TransactionResult Fail(string code, string message)
        => new(Success: false, ErrorCode: code, ErrorMessage: message, Warnings: null);
}
