namespace BareMetalWeb.Runtime;

/// <summary>
/// Compiles a persisted <see cref="EntityDefinition"/> and its associated
/// <see cref="FieldDefinition"/>, <see cref="IndexDefinition"/> and
/// <see cref="ActionDefinition"/> records into an immutable <see cref="RuntimeEntityModel"/>.
/// </summary>
public interface IRuntimeEntityCompiler
{
    /// <summary>
    /// Validates and compiles the supplied schema records into an immutable
    /// <see cref="RuntimeEntityModel"/>. Returns <c>null</c> if the definition
    /// is invalid (e.g. missing name).
    /// </summary>
    /// <param name="entity">The entity schema definition.</param>
    /// <param name="fields">All field definitions belonging to this entity.</param>
    /// <param name="indexes">All index definitions belonging to this entity.</param>
    /// <param name="actions">All action definitions belonging to this entity.</param>
    /// <param name="actionCommands">All v1.1 command definitions belonging to actions of this entity.</param>
    /// <param name="warnings">Populated with non-fatal validation messages.</param>
    RuntimeEntityModel? Compile(
        EntityDefinition entity,
        IReadOnlyList<FieldDefinition> fields,
        IReadOnlyList<IndexDefinition> indexes,
        IReadOnlyList<ActionDefinition> actions,
        IReadOnlyList<ActionCommandDefinition> actionCommands,
        out IReadOnlyList<string> warnings);
}
