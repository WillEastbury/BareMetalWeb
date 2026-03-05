using BareMetalWeb.Core;
using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Default implementation of <see cref="IQueryService"/>.
/// Delegates to the entity's <see cref="DataEntityHandlers"/> registered with
/// <see cref="DataScaffold"/>, serializing results to field-name → value dictionaries.
/// Works for both compiled and runtime-defined (EntityDefinition-based) entities.
/// </summary>
public sealed class QueryService : IQueryService
{
    /// <inheritdoc/>
    public async ValueTask<IEnumerable<Dictionary<string, object?>>> QueryAsync(
        string entitySlug,
        QueryDefinition? query = null,
        CancellationToken cancellationToken = default)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta))
            return Array.Empty<Dictionary<string, object?>>();

        var items = await meta.Handlers.QueryAsync(query, cancellationToken).ConfigureAwait(false);
        var result = new List<Dictionary<string, object?>>();
        foreach (var obj in items)
            result.Add(SerializeObject(obj, meta));
        return result;
    }

    /// <inheritdoc/>
    public async ValueTask<Dictionary<string, object?>?> GetByIdAsync(
        string entitySlug,
        string id,
        CancellationToken cancellationToken = default)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta))
            return null;

        var obj = await meta.Handlers.LoadAsync(uint.Parse(id), cancellationToken).ConfigureAwait(false);
        return obj == null ? null : SerializeObject(obj, meta);
    }

    /// <inheritdoc/>
    public async ValueTask<int> CountAsync(
        string entitySlug,
        QueryDefinition? query = null,
        CancellationToken cancellationToken = default)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta))
            return 0;

        return await meta.Handlers.CountAsync(query, cancellationToken).ConfigureAwait(false);
    }

    // ── Serialization ──────────────────────────────────────────────────────────

    /// <summary>
    /// Serializes a <see cref="BaseDataObject"/> to a field-name → value dictionary
    /// using the entity's field metadata. Works for both compiled and dynamic objects.
    /// </summary>
    internal static Dictionary<string, object?> SerializeObject(
        BaseDataObject obj,
        DataEntityMetadata meta)
    {
        var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["id"] = obj.Key,
            ["createdOnUtc"] = obj.CreatedOnUtc,
            ["updatedOnUtc"] = obj.UpdatedOnUtc,
            ["createdBy"] = obj.CreatedBy,
            ["updatedBy"] = obj.UpdatedBy
        };

        foreach (var field in meta.Fields)
        {
            try
            {
                dict[field.Name] = field.Property.GetValue(obj);
            }
            catch
            {
                // Field access failed (e.g. type mismatch during deserialization);
                // emit null so the response remains well-formed.
                dict[field.Name] = null;
            }
        }

        return dict;
    }
}
