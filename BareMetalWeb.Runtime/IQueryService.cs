using BareMetalWeb.Core;
using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Unified query facade that works across all registered entities —
/// both compiled (UserClasses) and runtime-defined (EntityDefinition-based).
/// </summary>
public interface IQueryService
{
    /// <summary>
    /// Returns all instances of the given entity that match <paramref name="query"/>,
    /// serialized as field-name → value dictionaries.
    /// Returns an empty sequence if the entity slug is not registered.
    /// </summary>
    ValueTask<IEnumerable<Dictionary<string, object?>>> QueryAsync(
        string entitySlug,
        QueryDefinition? query = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns a single entity instance by ID, or <c>null</c> if not found.
    /// </summary>
    ValueTask<Dictionary<string, object?>?> GetByIdAsync(
        string entitySlug,
        string id,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the total count of instances matching <paramref name="query"/>.
    /// </summary>
    ValueTask<int> CountAsync(
        string entitySlug,
        QueryDefinition? query = null,
        CancellationToken cancellationToken = default);
}
