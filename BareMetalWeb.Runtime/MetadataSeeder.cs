using BareMetalWeb.Core;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Seeds <see cref="EntityDefinition"/>, <see cref="FieldDefinition"/>, and
/// <see cref="IndexDefinition"/> records into a data store by extracting them from
/// every C# entity type that is currently registered with <see cref="DataScaffold"/>.
///
/// This is the entry-point for the "metadata-first" workflow: after seeding, all
/// entity schemas are visible and editable in the admin UI without any code changes.
/// </summary>
public static class MetadataSeeder
{
    /// <summary>
    /// Seeds metadata for every registered C# entity type that does not already have a
    /// corresponding <see cref="EntityDefinition"/> in <paramref name="store"/>.
    /// </summary>
    /// <param name="store">The data store to seed into.</param>
    /// <param name="overwrite">
    /// When <c>true</c>, existing <see cref="EntityDefinition"/> records (and their
    /// associated <see cref="FieldDefinition"/>s / <see cref="IndexDefinition"/>s) are
    /// deleted and replaced with freshly extracted values. Use with care — any admin-UI
    /// edits made to the existing records will be lost.
    /// When <c>false</c> (default), entities that already have a definition in the store
    /// are skipped.
    /// </param>
    /// <param name="logger">Optional delegate called with informational / warning messages.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The display names of every entity that was seeded in this call.</returns>
    public static async Task<IReadOnlyList<string>> SeedFromRegisteredEntitiesAsync(
        IDataObjectStore store,
        bool overwrite = false,
        Action<string>? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);

        var seeded = new List<string>();

        // Load existing EntityDefinitions so we can skip already-seeded entities.
        var existingDefs = new List<EntityDefinition>(await store.QueryAsync<EntityDefinition>(null, cancellationToken)
            .ConfigureAwait(false));

        // Index by the slug that will be used (either explicit Slug, or derived from Name).
        var existingBySlug = new Dictionary<string, EntityDefinition>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in existingDefs)
        {
            var s = !string.IsNullOrWhiteSpace(e.Slug)
                ? e.Slug!
                : DataScaffold.ToSlug(e.Name);
            existingBySlug[s] = e;
        }

        foreach (var meta in DataScaffold.Entities)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Skip DataRecord instances — they are runtime-defined, not code-first.
            if (meta.Type == typeof(DataRecord)) continue;

            // Only seed types that are explicitly annotated with [DataEntity].
            // All entities in DataScaffold are registered because they have this attribute,
            // but DataRecord instances are runtime-defined and also present.
            if (meta.Type == typeof(DataRecord)) continue;

            var slug = meta.Slug;

            if (!overwrite && existingBySlug.ContainsKey(slug))
            {
                logger?.Invoke($"Skipping '{meta.Name}' — EntityDefinition already exists in store.");
                continue;
            }

            var (entityDef, fields, indexes) = MetadataExtractor.ExtractFromType(meta.Type);

            if (overwrite && existingBySlug.TryGetValue(slug, out var existing))
            {
                // Preserve the identity so the record is updated in-place.
                entityDef.Key = existing.Key;
                entityDef.EntityId = existing.EntityId;
                entityDef.Version = existing.Version + 1;

                // Remove old field and index records before writing fresh ones.
                await DeleteChildRecordsAsync(store, existing.EntityId, cancellationToken)
                    .ConfigureAwait(false);
            }

            await store.SaveAsync(entityDef, cancellationToken).ConfigureAwait(false);

            foreach (var field in fields)
                await store.SaveAsync(field, cancellationToken).ConfigureAwait(false);

            foreach (var index in indexes)
                await store.SaveAsync(index, cancellationToken).ConfigureAwait(false);

            seeded.Add(meta.Name);
            logger?.Invoke(
                $"Seeded '{meta.Name}': {fields.Count} field(s), {indexes.Count} index(es).");
        }

        return seeded;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Deletes all <see cref="FieldDefinition"/> and <see cref="IndexDefinition"/>
    /// records that belong to the entity identified by <paramref name="entityDefId"/>.
    /// Uses a filtered query to avoid a full table scan on large stores.
    /// </summary>
    private static async Task DeleteChildRecordsAsync(
        IDataObjectStore store,
        string entityDefId,
        CancellationToken ct)
    {
        // Filter by EntityId to avoid loading all records into memory.
        var entityIdQuery = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "EntityId", Operator = QueryOperator.Equals, Value = entityDefId } }
        };

        var fields = new List<FieldDefinition>(await store.QueryAsync<FieldDefinition>(entityIdQuery, ct).ConfigureAwait(false));

        foreach (var f in fields)
            await store.DeleteAsync<FieldDefinition>(f.Key, ct).ConfigureAwait(false);

        var idxs = new List<IndexDefinition>(await store.QueryAsync<IndexDefinition>(entityIdQuery, ct).ConfigureAwait(false));

        foreach (var idx in idxs)
            await store.DeleteAsync<IndexDefinition>(idx.Key, ct).ConfigureAwait(false);
    }
}
