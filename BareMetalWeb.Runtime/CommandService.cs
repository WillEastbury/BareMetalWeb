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

        return CommandResult.Ok(obj.Id, QueryService.SerializeObject(obj, meta));
    }

    private static async ValueTask<CommandResult> UpdateAsync(
        DataEntityMetadata meta,
        CommandIntent intent,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(intent.EntityId))
            return CommandResult.Fail("EntityId is required for 'update'.");

        var obj = await meta.Handlers.LoadAsync(intent.EntityId!, ct).ConfigureAwait(false);
        if (obj == null)
            return CommandResult.Fail($"Entity '{intent.EntitySlug}' with id '{intent.EntityId}' not found.");

        var errors = DataScaffold.ApplyValuesFromForm(meta, obj, intent.Fields, forCreate: false);
        if (errors.Count > 0)
            return CommandResult.Fail(string.Join("; ", errors));

        await meta.Handlers.SaveAsync(obj, ct).ConfigureAwait(false);
        return CommandResult.Ok(obj.Id, QueryService.SerializeObject(obj, meta));
    }

    private static async ValueTask<CommandResult> DeleteAsync(
        DataEntityMetadata meta,
        CommandIntent intent,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(intent.EntityId))
            return CommandResult.Fail("EntityId is required for 'delete'.");

        await meta.Handlers.DeleteAsync(intent.EntityId!, ct).ConfigureAwait(false);
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

        var action = runtimeModel.Actions
            .FirstOrDefault(a => string.Equals(a.Name, actionName, StringComparison.OrdinalIgnoreCase));

        if (action == null)
            return CommandResult.Fail($"Action '{intent.Operation}' not found on entity '{intent.EntitySlug}'.");

        if (string.IsNullOrWhiteSpace(intent.EntityId))
            return CommandResult.Fail($"EntityId is required for action '{intent.Operation}'.");

        var obj = await meta.Handlers.LoadAsync(intent.EntityId!, ct).ConfigureAwait(false);
        if (obj == null)
            return CommandResult.Fail($"Entity '{intent.EntitySlug}' with id '{intent.EntityId}' not found.");

        // Execute SetField operations declaratively
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
        return CommandResult.Ok(obj.Id, QueryService.SerializeObject(obj, meta));
    }
}
