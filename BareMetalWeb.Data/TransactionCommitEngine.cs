using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Full transaction commit pipeline:
/// 1. Acquire locks (sorted, deadlock-free)
/// 2. Load canonical state for all aggregates
/// 3. Run all AssertIf validations against canonical state
/// 4. Apply envelope mutations to working copies
/// 5. If valid: save all mutations atomically, release locks, return success
/// 6. If invalid: release locks, return rejected
/// </summary>
public sealed class TransactionCommitEngine
{
    private readonly AggregateLockManager _lockManager;
    private Func<string, ActionDef?>? _actionResolver;

    public TransactionCommitEngine(AggregateLockManager lockManager)
    {
        _lockManager = lockManager;
    }

    /// <summary>Set the action resolver (called once during initialization from Host layer).</summary>
    public void SetActionResolver(Func<string, ActionDef?> resolver) => _actionResolver = resolver;

    /// <summary>
    /// Commit a transaction envelope.
    /// All validation occurs inside lock scope.
    /// Domain event subscriptions fire after save, inside the same lock scope.
    /// </summary>
    public async ValueTask<TransactionResult> CommitAsync(
        TransactionEnvelope envelope,
        string userName,
        CancellationToken cancellationToken = default,
        bool allowEventDispatch = true)
    {
        var commitStart = EngineMetrics.StartTiming();

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

                var loaded = await DataScaffold.LoadAsync(meta, mutation.AggregateId, cancellationToken);
                if (loaded is null)
                    return Fail("ENTITY_NOT_FOUND", $"Entity {mutation.AggregateType}:{mutation.AggregateId} not found.");
                if (loaded is not BaseDataObject entity)
                    return Fail("TYPE_MISMATCH", $"Expected BaseDataObject for {mutation.AggregateType}:{mutation.AggregateId}, got {loaded.GetType().Name}.");

                var layout = EntityLayoutCompiler.GetOrCompile(meta);
                loadedEntities[key] = (meta, entity, layout);
            }

            // Snapshot before-state for domain event detection
            var beforeSnapshots = new Dictionary<string, BaseDataObject>();
            foreach (var (key, (meta, entity, _)) in loadedEntities)
            {
                beforeSnapshots[key] = CloneEntity(entity, meta);
            }

            // 3. Validate all AssertIf assertions against canonical (pre-mutation) state
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
                            EngineMetrics.RecordCommit(EngineMetrics.ElapsedUs(commitStart), false);
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

            // 4. Apply mutations to working copies (only reached if assertions passed)
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

            // 5. Save all mutations atomically
            foreach (var mutation in envelope.Mutations)
            {
                var key = $"{mutation.AggregateType}:{mutation.AggregateId}";
                var (meta, entity, _) = loadedEntities[key];
                entity.Touch(userName);
                await DataScaffold.SaveAsync(meta, entity, cancellationToken);
            }

            // 6. Dispatch domain event subscriptions (flat only — no nested events)
            if (allowEventDispatch && _actionResolver != null)
            {
                var entityStates = new Dictionary<string, (DataEntityMetadata, BaseDataObject, BaseDataObject, EntityLayout)>();
                foreach (var (key, (meta, entity, layout)) in loadedEntities)
                {
                    if (beforeSnapshots.TryGetValue(key, out var before))
                        entityStates[key] = (meta, before, entity, layout);
                }

                var eventResults = await DomainEventDispatcher.DispatchAsync(
                    envelope, entityStates, _actionResolver,
                    this, userName, cancellationToken);

                // Collect event warnings/errors
                foreach (var er in eventResults)
                {
                    if (!er.Success)
                        warnings.Add(new TransactionWarning(
                            er.ErrorCode ?? "EVENT_FAILED",
                            $"[Event:{er.SubscriptionName}] {er.ErrorMessage}"));
                }
            }

            // 7. Success
            EngineMetrics.RecordCommit(EngineMetrics.ElapsedUs(commitStart), true);
            return new TransactionResult(
                Success: true,
                ErrorCode: null,
                ErrorMessage: null,
                Warnings: warnings.Count > 0 ? warnings : null);
        }
        catch (TimeoutException)
        {
            EngineMetrics.RecordCommit(EngineMetrics.ElapsedUs(commitStart), false);
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

        var loaded = await DataScaffold.LoadAsync(meta, aggregateId, cancellationToken);
        if (loaded is null)
            return Fail("ENTITY_NOT_FOUND", $"Entity {action.AggregateType}:{aggregateId} not found.");
        if (loaded is not BaseDataObject entity)
            return Fail("TYPE_MISMATCH", $"Expected BaseDataObject for {action.AggregateType}:{aggregateId}, got {loaded.GetType().Name}.");

        var layout = EntityLayoutCompiler.GetOrCompile(meta);

        // Server-side expansion (never trust client delta)
        var expander = new ActionExpander(actionResolver);
        var envelope = expander.Expand(action, entity, layout, parameters);

        return await CommitAsync(envelope, userName, cancellationToken);
    }

    private static TransactionResult Fail(string code, string message)
        => new(Success: false, ErrorCode: code, ErrorMessage: message, Warnings: null);

    /// <summary>
    /// Shallow clone an entity to capture before-state for event comparison.
    /// Copies all field values via the layout getter/setter pairs.
    /// </summary>
    private static BaseDataObject CloneEntity(BaseDataObject source, DataEntityMetadata meta)
    {
        // AOT-safe: DataRecord clones via schema-aware constructor; compiled entities
        // fall back to RuntimeHelpers (no parameterless-ctor requirement).
        BaseDataObject clone;
        if (source is DataRecord dr && dr.Schema is { } schema)
        {
            clone = new DataRecord(schema);
        }
        else
        {
            clone = (BaseDataObject)System.Runtime.CompilerServices.RuntimeHelpers
                .GetUninitializedObject(source.GetType());
        }

        clone.Key = source.Key;

        var layout = EntityLayoutCompiler.GetOrCompile(meta);
        foreach (var field in layout.Fields)
        {
            try { field.Setter(clone, field.Getter(source)); }
            catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
            {
                System.Diagnostics.Debug.WriteLine($"CloneEntity: skipping field {field.Name}: {ex.GetType().Name}");
            }
        }
        return clone;
    }
}
