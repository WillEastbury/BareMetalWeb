using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data.ExpressionEngine;

/// <summary>
/// Server-side implementation of <see cref="ILookupResolver"/> that uses
/// <see cref="DataScaffold"/> to resolve relationships across entities.
/// </summary>
public sealed class ServerLookupResolver : ILookupResolver
{
    public static readonly ServerLookupResolver Instance = new();

    public async ValueTask<object?> ResolveRelatedFieldAsync(
        string currentEntitySlug,
        string foreignKeyField,
        string targetField,
        IReadOnlyDictionary<string, object?> context,
        CancellationToken cancellationToken = default)
    {
        // Get the FK value from the current context
        if (!context.TryGetValue(foreignKeyField, out var fkValue) || fkValue == null)
            return null;

        var fkString = fkValue.ToString();
        if (string.IsNullOrEmpty(fkString) || !uint.TryParse(fkString, out var fkKey))
            return null;

        // Find the lookup target entity from the FK field's metadata
        DataEntityMetadata? targetMeta = null;

        if (!string.IsNullOrEmpty(currentEntitySlug) && DataScaffold.TryGetEntity(currentEntitySlug, out var currentMeta))
        {
            DataFieldMetadata? fkFieldMeta = null;
            foreach (var f in currentMeta!.Fields)
            {
                if (string.Equals(f.Name, foreignKeyField, StringComparison.OrdinalIgnoreCase))
                {
                    fkFieldMeta = f;
                    break;
                }
            }

            if (fkFieldMeta?.Lookup != null)
            {
                targetMeta = DataScaffold.GetEntityByType(fkFieldMeta.Lookup.TargetType);
            }
        }

        if (targetMeta == null)
            return null;

        // Load the related entity
        var relatedEntity = await targetMeta.Handlers.LoadAsync(fkKey, cancellationToken);
        if (relatedEntity == null)
            return null;

        return ExtractFieldValue(relatedEntity, targetField);
    }

    public async ValueTask<object?> QueryLookupAsync(
        string entitySlug,
        IReadOnlyList<(string Field, object? Value)> filters,
        string returnField,
        CancellationToken cancellationToken = default)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta))
            return null;

        // Query all entities and filter in memory
        // (DataScaffold query infrastructure filters on standard fields)
        var query = (QueryDefinition?)null;
        var allItems = await meta!.Handlers.QueryAsync(query, cancellationToken);

        foreach (var item in allItems)
        {
            bool matches = true;
            foreach (var (filterField, filterValue) in filters)
            {
                var itemValue = ExtractFieldValue(item, filterField);
                if (!ValuesEqual(itemValue, filterValue))
                {
                    matches = false;
                    break;
                }
            }

            if (matches)
                return ExtractFieldValue(item, returnField);
        }

        return null;
    }

    public async ValueTask<object?> ResolveChainAsync(
        string startEntitySlug,
        IReadOnlyList<string> chain,
        IReadOnlyDictionary<string, object?> context,
        CancellationToken cancellationToken = default)
    {
        if (chain.Count < 2)
            return null;

        // Step 1: resolve the first FK from the starting entity context
        var firstFkField = chain[0];
        if (!context.TryGetValue(firstFkField, out var firstFkValue) || firstFkValue == null)
            return null;

        var firstFkString = firstFkValue.ToString();
        if (string.IsNullOrEmpty(firstFkString) || !uint.TryParse(firstFkString, out var firstFkKey))
            return null;

        DataEntityMetadata? currentMeta = null;
        if (!string.IsNullOrEmpty(startEntitySlug) && DataScaffold.TryGetEntity(startEntitySlug, out var startMeta))
        {
            DataFieldMetadata? firstFkFieldMeta = null;
            foreach (var f in startMeta!.Fields)
            {
                if (string.Equals(f.Name, firstFkField, StringComparison.OrdinalIgnoreCase))
                {
                    firstFkFieldMeta = f;
                    break;
                }
            }
            if (firstFkFieldMeta?.Lookup != null)
                currentMeta = DataScaffold.GetEntityByType(firstFkFieldMeta.Lookup.TargetType);
        }

        if (currentMeta == null)
            return null;

        var currentEntity = await currentMeta.Handlers.LoadAsync(firstFkKey, cancellationToken);
        if (currentEntity == null)
            return null;

        // Steps 2..n-1: traverse intermediate FK fields using entity metadata
        for (int i = 1; i < chain.Count - 1; i++)
        {
            var nextFkField = chain[i];
            var nextFkValue = ExtractFieldValue(currentEntity, nextFkField);
            if (nextFkValue == null)
                return null;

            var nextFkString = nextFkValue.ToString();
            if (string.IsNullOrEmpty(nextFkString) || !uint.TryParse(nextFkString, out var nextFkKey))
                return null;

            DataEntityMetadata? nextMeta = null;
            var entityMeta = DataScaffold.GetEntityByType(currentEntity.GetType());
            var fieldMeta = entityMeta?.FindField(nextFkField);
            if (fieldMeta?.Lookup != null)
                nextMeta = DataScaffold.GetEntityByType(fieldMeta.Lookup.TargetType);

            if (nextMeta == null)
                return null;

            currentEntity = await nextMeta.Handlers.LoadAsync(nextFkKey, cancellationToken);
            if (currentEntity == null)
                return null;
        }

        return ExtractFieldValue(currentEntity, chain[chain.Count - 1]);
    }

    private static readonly ConcurrentDictionary<(Type, string), Func<object, object?>?> _accessorCache = new();

    private static object? ExtractFieldValue(object entity, string fieldName)
    {
        if (entity is DataRecord rec && rec.Schema != null)
            return rec.GetField(rec.Schema, fieldName);

        // Use entity metadata for compiled accessor delegates
        var meta = DataScaffold.GetEntityByType(entity.GetType());
        if (meta != null)
        {
            var field = meta.FindField(fieldName);
            if (field != null)
                return field.GetValueFn(entity);
        }

        // Fallback with cached compiled accessor for base/unregistered properties
        var getter = _accessorCache.GetOrAdd((entity.GetType(), fieldName), static key =>
        {
            var prop = key.Item1.GetProperty(key.Item2,
                System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.IgnoreCase);
            return prop != null ? PropertyAccessorFactory.BuildGetter(prop) : null;
        });
        return getter?.Invoke(entity);
    }

    private static bool ValuesEqual(object? a, object? b)
    {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;

        var aStr = a.ToString();
        var bStr = b.ToString();
        return string.Equals(aStr, bStr, StringComparison.OrdinalIgnoreCase);
    }
}
