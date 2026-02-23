namespace BareMetalWeb.Runtime;

/// <summary>
/// Represents an intent to create, update, delete or invoke a named action
/// on an entity instance. Consumed by <see cref="ICommandService"/>.
/// </summary>
public sealed class CommandIntent
{
    /// <summary>Slug of the target entity (e.g. "tickets").</summary>
    public string EntitySlug { get; set; } = string.Empty;

    /// <summary>
    /// ID of the target instance.
    /// Required for "update", "delete", and action operations.
    /// Omit (or set to null) for "create".
    /// </summary>
    public string? EntityId { get; set; }

    /// <summary>
    /// Operation to execute: "create", "update", "delete", or the name of
    /// an <see cref="ActionDefinition"/> (e.g. "Resolve").
    /// </summary>
    public string Operation { get; set; } = string.Empty;

    /// <summary>Field name → string value pairs to apply to the instance.</summary>
    public Dictionary<string, string?> Fields { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Result of executing a <see cref="CommandIntent"/>.</summary>
public sealed class CommandResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }

    /// <summary>ID of the affected instance (populated on success).</summary>
    public string? EntityId { get; set; }

    /// <summary>
    /// Current field values of the affected instance after the operation
    /// (populated on success for create/update).
    /// </summary>
    public Dictionary<string, object?>? Data { get; set; }

    public static CommandResult Ok(string id, Dictionary<string, object?>? data = null)
        => new() { Success = true, EntityId = id, Data = data };

    public static CommandResult Fail(string error)
        => new() { Success = false, Error = error };
}
