using BareMetalWeb.Core;
using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Default implementation of <see cref="ICommandService"/>.
/// Supports "create", "update", "delete", and named <see cref="ActionDefinition"/> operations.
/// Delegates to the entity's <see cref="DataEntityHandlers"/> registered with
/// <see cref="DataScaffold"/>.
/// </summary>
public sealed class CommandService : ICommandService
{
    /// <inheritdoc/>
    public async ValueTask<CommandResult> ExecuteAsync(
        CommandIntent intent,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (!DataScaffold.TryGetEntity(intent.EntitySlug, out var meta))
                return CommandResult.Fail($"Entity '{intent.EntitySlug}' not found.");

            var op = (intent.Operation ?? string.Empty).Trim().ToLowerInvariant();

            switch (op)
            {
                case "create":
                    return await CreateAsync(meta, intent, cancellationToken).ConfigureAwait(false);

                case "update":
                case "patch":
                    return await UpdateAsync(meta, intent, cancellationToken).ConfigureAwait(false);

                case "delete":
                    return await DeleteAsync(meta, intent, cancellationToken).ConfigureAwait(false);

                default:
                    // Named action — look it up in RuntimeEntityRegistry
                    return await ExecuteActionAsync(meta, intent, op, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            return CommandResult.Fail(ex.Message);
        }
    }

    // ── CRUD operations ────────────────────────────────────────────────────────

    private static async ValueTask<CommandResult> CreateAsync(
        DataEntityMetadata meta,
        CommandIntent intent,
        CancellationToken ct)
    {
        var obj = meta.Handlers.Create();
        var errors = DataScaffold.ApplyValuesFromForm(meta, obj, intent.Fields, forCreate: true);
        if (errors.Count > 0)
            return CommandResult.Fail(string.Join("; ", errors));

        await DataScaffold.ApplyAutoIdAsync(meta, obj, ct).ConfigureAwait(false);
        await meta.Handlers.SaveAsync(obj, ct).ConfigureAwait(false);

        return CommandResult.Ok(obj.Key.ToString(), QueryService.SerializeObject(obj, meta));
    }

    private static async ValueTask<CommandResult> UpdateAsync(
        DataEntityMetadata meta,
        CommandIntent intent,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(intent.EntityId))
            return CommandResult.Fail("EntityId is required for 'update'.");

        var obj = await meta.Handlers.LoadAsync(uint.Parse(intent.EntityId!), ct).ConfigureAwait(false);
        if (obj == null)
            return CommandResult.Fail($"Entity '{intent.EntitySlug}' with id '{intent.EntityId}' not found.");

        var errors = DataScaffold.ApplyValuesFromForm(meta, obj, intent.Fields, forCreate: false);
        if (errors.Count > 0)
            return CommandResult.Fail(string.Join("; ", errors));

        await meta.Handlers.SaveAsync(obj, ct).ConfigureAwait(false);
        return CommandResult.Ok(obj.Key.ToString(), QueryService.SerializeObject(obj, meta));
    }

    private static async ValueTask<CommandResult> DeleteAsync(
        DataEntityMetadata meta,
        CommandIntent intent,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(intent.EntityId))
            return CommandResult.Fail("EntityId is required for 'delete'.");

        await meta.Handlers.DeleteAsync(uint.Parse(intent.EntityId!), ct).ConfigureAwait(false);
        return CommandResult.Ok(intent.EntityId!);
    }

    // ── Named action ───────────────────────────────────────────────────────────

    private static async ValueTask<CommandResult> ExecuteActionAsync(
        DataEntityMetadata meta,
        CommandIntent intent,
        string actionName,
        CancellationToken ct)
    {
        // Resolve action from RuntimeEntityRegistry
        if (!RuntimeEntityRegistry.Current.TryGet(intent.EntitySlug, out var runtimeModel))
            return CommandResult.Fail($"No runtime entity found for slug '{intent.EntitySlug}'.");

        RuntimeActionModel? action = null;
        foreach (var a in runtimeModel.Actions)
        {
            if (string.Equals(a.Name, actionName, StringComparison.OrdinalIgnoreCase))
            {
                action = a;
                break;
            }
        }

        if (action == null)
            return CommandResult.Fail($"Action '{intent.Operation}' not found on entity '{intent.EntitySlug}'.");

        if (string.IsNullOrWhiteSpace(intent.EntityId))
            return CommandResult.Fail($"EntityId is required for action '{intent.Operation}'.");

        var obj = await meta.Handlers.LoadAsync(uint.Parse(intent.EntityId!), ct).ConfigureAwait(false);
        if (obj == null)
            return CommandResult.Fail($"Entity '{intent.EntitySlug}' with id '{intent.EntityId}' not found.");

        // ── v1.1 structured command pipeline ──────────────────────────────────
        if (action.Commands.Count > 0)
        {
            return await ExecuteStructuredActionAsync(meta, intent, action, obj, ct)
                .ConfigureAwait(false);
        }

        // ── Legacy: pipe-separated "SetField:Field=Value" operations ──────────
        foreach (var operation in action.Operations)
        {
            if (!operation.StartsWith("SetField:", StringComparison.OrdinalIgnoreCase))
                continue;

            var assignment = operation["SetField:".Length..];
            var eqIdx = assignment.IndexOf('=');
            if (eqIdx < 0) continue;

            var fieldName = assignment[..eqIdx].Trim();
            var value = assignment[(eqIdx + 1)..].Trim();

            var fieldPatch = new Dictionary<string, string?> { [fieldName] = value };
            DataScaffold.ApplyValuesFromForm(meta, obj, fieldPatch, forCreate: false);
        }

        await meta.Handlers.SaveAsync(obj, ct).ConfigureAwait(false);
        return CommandResult.Ok(obj.Key.ToString(), QueryService.SerializeObject(obj, meta));
    }

    // ── v1.1 structured action execution ──────────────────────────────────────

    private static async ValueTask<CommandResult> ExecuteStructuredActionAsync(
        DataEntityMetadata meta,
        CommandIntent intent,
        RuntimeActionModel action,
        DataRecord obj,
        CancellationToken ct)
    {
        // Build evaluation context from current field values
        var context = BuildContext(meta, obj);

        // §8 — server re-expands the action; never trusts client-supplied deltas
        TransactionEnvelope envelope;
        try
        {
            envelope = ActionExpander.Expand(action, intent.EntitySlug, intent.EntityId!, context);
        }
        catch (Exception ex)
        {
            return CommandResult.Fail($"Action expansion failed: {ex.Message}");
        }

        // §6.3 — validate assertions before acquiring locks
        if (!envelope.IsValid)
        {
            var err = envelope.FirstError!;
            return CommandResult.Fail($"[{err.Code}] {err.Message}");
        }

        // §6.2 — collect touched aggregates and acquire locks in sorted order
        var touchedIds = new List<string>(envelope.AggregateMutations.Count);
        foreach (var m in envelope.AggregateMutations)
            touchedIds.Add($"{m.AggregateType}:{m.AggregateId}");

        var transactionId = envelope.TransactionId;
        var lockTimeout = TimeSpan.FromSeconds(5);
        const int maxRetries = 3;

        for (int attempt = 0; attempt < maxRetries; attempt++)
        {
            if (AggregateLockManager.Instance.TryAcquireAll(touchedIds, transactionId, lockTimeout))
                break;

            if (attempt == maxRetries - 1)
                return CommandResult.Fail("Could not acquire aggregate locks — try again.");

            await Task.Delay(50 * (attempt + 1), ct).ConfigureAwait(false);
        }

        try
        {
            // Apply mutations for the primary aggregate to the loaded object
            AggregateMutation? primaryMutation = null;
            foreach (var m in envelope.AggregateMutations)
            {
                if (string.Equals(m.AggregateType, intent.EntitySlug, StringComparison.OrdinalIgnoreCase))
                {
                    primaryMutation = m;
                    break;
                }
            }

            if (primaryMutation != null)
            {
                foreach (var change in primaryMutation.Changes)
                {
                    // Convert typed value to string using invariant culture for correct parsing downstream
                    var strValue = change.NewValue switch
                    {
                        null => null,
                        bool b => b ? "true" : "false",
                        IFormattable f => f.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
                        _ => change.NewValue.ToString()
                    };
                    var patch = new Dictionary<string, string?> { [change.FieldId] = strValue };
                    DataScaffold.ApplyValuesFromForm(meta, obj, patch, forCreate: false);
                }
            }

            await meta.Handlers.SaveAsync(obj, ct).ConfigureAwait(false);
        }
        finally
        {
            AggregateLockManager.Instance.ReleaseAll(touchedIds, transactionId);
        }

        return CommandResult.Ok(obj.Key.ToString(), QueryService.SerializeObject(obj, meta));
    }

    /// <summary>Builds an expression evaluation context from an entity's current field values.</summary>
    private static IReadOnlyDictionary<string, object?> BuildContext(DataEntityMetadata meta, DataRecord obj)
    {
        var context = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        var serialized = QueryService.SerializeObject(obj, meta);
        if (serialized != null)
        {
            foreach (var (key, value) in serialized)
                context[key] = value;
        }

        return context;
    }
}

