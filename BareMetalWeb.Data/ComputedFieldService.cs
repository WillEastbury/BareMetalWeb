using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Service for computing field values from related entities.
/// </summary>
public static class ComputedFieldService
{
    private static readonly ConcurrentDictionary<string, ComputedValueCacheEntry> _cache = new();

    private sealed record ComputedValueCacheEntry(object? Value, DateTime ExpiresUtc);

    /// <summary>
    /// Applies computed values to an entity instance based on the specified trigger.
    /// Used for snapshot strategy during create/update operations.
    /// </summary>
    public static async ValueTask ApplyComputedValuesAsync(
        DataEntityMetadata metadata,
        BaseDataObject instance,
        ComputedTrigger trigger,
        CancellationToken cancellationToken = default)
    {
        foreach (var field in metadata.Fields.Where(f => f.Computed != null))
        {
            var config = field.Computed!;

            // Skip if this field doesn't match the trigger
            if (config.Strategy == ComputedStrategy.Snapshot)
            {
                bool shouldCompute = trigger switch
                {
                    ComputedTrigger.OnCreate => config.Trigger == ComputedTrigger.OnCreate || config.Trigger == ComputedTrigger.OnCreateAndUpdate,
                    ComputedTrigger.OnUpdate => config.Trigger == ComputedTrigger.OnUpdate || config.Trigger == ComputedTrigger.OnCreateAndUpdate,
                    _ => false
                };

                if (!shouldCompute)
                    continue;

                var value = await ComputeValueAsync(metadata, instance, field, config, cancellationToken);
                field.Property.SetValue(instance, value);
            }
        }
    }

    /// <summary>
    /// Gets the computed value for a field, using caching if appropriate.
    /// Used for CachedLive and AlwaysLive strategies during read operations.
    /// </summary>
    public static async ValueTask<object?> GetComputedValueAsync(
        DataEntityMetadata metadata,
        BaseDataObject instance,
        DataFieldMetadata field,
        CancellationToken cancellationToken = default)
    {
        var config = field.Computed;
        if (config == null)
            return field.Property.GetValue(instance);

        if (config.Strategy == ComputedStrategy.Snapshot)
        {
            // Snapshot values are stored in the property
            return field.Property.GetValue(instance);
        }

        if (config.Strategy == ComputedStrategy.CachedLive)
        {
            var cacheKey = $"{metadata.Type.FullName}.{instance.Id}.{field.Name}";
            if (_cache.TryGetValue(cacheKey, out var cached) && cached.ExpiresUtc > DateTime.UtcNow)
            {
                return cached.Value;
            }

            var value = await ComputeValueAsync(metadata, instance, field, config, cancellationToken);
            _cache[cacheKey] = new ComputedValueCacheEntry(value, DateTime.UtcNow.Add(config.CacheDuration));
            return value;
        }

        // AlwaysLive
        return await ComputeValueAsync(metadata, instance, field, config, cancellationToken);
    }

    /// <summary>
    /// Clears the cached values for a specific entity instance.
    /// </summary>
    public static void ClearCache(DataEntityMetadata metadata, string instanceId)
    {
        var prefix = $"{metadata.Type.FullName}.{instanceId}.";
        var keysToRemove = _cache.Keys.Where(k => k.StartsWith(prefix)).ToList();
        foreach (var key in keysToRemove)
        {
            _cache.TryRemove(key, out _);
        }
    }

    /// <summary>
    /// Clears all cached computed values.
    /// </summary>
    public static void ClearAllCache()
    {
        _cache.Clear();
    }

    private static async ValueTask<object?> ComputeValueAsync(
        DataEntityMetadata metadata,
        BaseDataObject instance,
        DataFieldMetadata field,
        ComputedFieldConfig config,
        CancellationToken cancellationToken)
    {
        // Handle aggregations on child collections
        if (!string.IsNullOrEmpty(config.ChildCollectionProperty))
        {
            return await ComputeAggregationAsync(metadata, instance, field, config, cancellationToken);
        }

        // Handle single-entity lookups
        if (config.SourceEntity != null && !string.IsNullOrEmpty(config.ForeignKeyField))
        {
            return await ComputeLookupAsync(metadata, instance, field, config, cancellationToken);
        }

        return null;
    }

    private static async ValueTask<object?> ComputeLookupAsync(
        DataEntityMetadata metadata,
        BaseDataObject instance,
        DataFieldMetadata field,
        ComputedFieldConfig config,
        CancellationToken cancellationToken)
    {
        // Get the foreign key value
        var fkProperty = metadata.Type.GetProperty(config.ForeignKeyField!);
        if (fkProperty == null)
            return null;

        var foreignKeyValue = fkProperty.GetValue(instance)?.ToString();
        if (string.IsNullOrEmpty(foreignKeyValue))
            return null;

        // Load the related entity
        var sourceMetadata = DataScaffold.GetEntityByType(config.SourceEntity!);
        if (sourceMetadata == null)
            return null;

        var relatedEntity = await sourceMetadata.Handlers.LoadAsync(foreignKeyValue, cancellationToken);
        if (relatedEntity == null)
            return null;

        // Get the source field value
        var sourceProperty = config.SourceEntity!.GetProperty(config.SourceField!);
        if (sourceProperty == null)
            return null;

        return sourceProperty.GetValue(relatedEntity);
    }

    private static async ValueTask<object?> ComputeAggregationAsync(
        DataEntityMetadata metadata,
        BaseDataObject instance,
        DataFieldMetadata field,
        ComputedFieldConfig config,
        CancellationToken cancellationToken)
    {
        // Get the child collection property
        var collectionProperty = metadata.Type.GetProperty(config.ChildCollectionProperty!);
        if (collectionProperty == null)
            return null;

        var collection = collectionProperty.GetValue(instance) as IEnumerable;
        if (collection == null)
        {
            // Try to query for child entities if the collection isn't loaded
            // This would require knowing the child entity type and foreign key relationship
            // For now, return default value
            return GetDefaultValueForAggregate(config.Aggregate, field.Property.PropertyType);
        }

        var items = collection.Cast<object>().ToList();

        if (string.IsNullOrEmpty(config.SourceField))
        {
            // Count aggregation doesn't need a source field
            if (config.Aggregate == AggregateFunction.Count)
                return items.Count;
            
            return GetDefaultValueForAggregate(config.Aggregate, field.Property.PropertyType);
        }

        // Get values from the source field
        var values = new List<object?>();
        foreach (var item in items)
        {
            var itemType = item.GetType();
            var sourceProperty = itemType.GetProperty(config.SourceField);
            if (sourceProperty != null)
            {
                values.Add(sourceProperty.GetValue(item));
            }
        }

        return ApplyAggregateFunction(config.Aggregate, values, field.Property.PropertyType);
    }

    private static object? ApplyAggregateFunction(AggregateFunction aggregate, List<object?> values, Type targetType)
    {
        if (values.Count == 0)
            return GetDefaultValueForAggregate(aggregate, targetType);

        switch (aggregate)
        {
            case AggregateFunction.Count:
                return values.Count;

            case AggregateFunction.Sum:
                return SumValues(values, targetType);

            case AggregateFunction.Average:
                return AverageValues(values, targetType);

            case AggregateFunction.Min:
                return MinValue(values, targetType);

            case AggregateFunction.Max:
                return MaxValue(values, targetType);

            case AggregateFunction.None:
            default:
                return values.FirstOrDefault();
        }
    }

    private static object? SumValues(List<object?> values, Type targetType)
    {
        var numericValues = values.Where(v => v != null).ToList();
        if (numericValues.Count == 0)
            return GetDefaultValueForAggregate(AggregateFunction.Sum, targetType);

        if (targetType == typeof(decimal) || targetType == typeof(decimal?))
            return numericValues.Sum(v => Convert.ToDecimal(v));
        if (targetType == typeof(double) || targetType == typeof(double?))
            return numericValues.Sum(v => Convert.ToDouble(v));
        if (targetType == typeof(float) || targetType == typeof(float?))
            return (float)numericValues.Sum(v => Convert.ToDouble(v));
        if (targetType == typeof(long) || targetType == typeof(long?))
            return numericValues.Sum(v => Convert.ToInt64(v));
        if (targetType == typeof(int) || targetType == typeof(int?))
            return numericValues.Sum(v => Convert.ToInt32(v));

        return numericValues.Sum(v => Convert.ToDecimal(v));
    }

    private static object? AverageValues(List<object?> values, Type targetType)
    {
        var numericValues = values.Where(v => v != null).ToList();
        if (numericValues.Count == 0)
            return GetDefaultValueForAggregate(AggregateFunction.Average, targetType);

        if (targetType == typeof(decimal) || targetType == typeof(decimal?))
            return numericValues.Average(v => Convert.ToDecimal(v));
        if (targetType == typeof(double) || targetType == typeof(double?))
            return numericValues.Average(v => Convert.ToDouble(v));
        if (targetType == typeof(float) || targetType == typeof(float?))
            return (float)numericValues.Average(v => Convert.ToDouble(v));

        return numericValues.Average(v => Convert.ToDecimal(v));
    }

    private static object? MinValue(List<object?> values, Type targetType)
    {
        var numericValues = values.Where(v => v != null).ToList();
        if (numericValues.Count == 0)
            return GetDefaultValueForAggregate(AggregateFunction.Min, targetType);

        if (targetType == typeof(decimal) || targetType == typeof(decimal?))
            return numericValues.Min(v => Convert.ToDecimal(v));
        if (targetType == typeof(double) || targetType == typeof(double?))
            return numericValues.Min(v => Convert.ToDouble(v));
        if (targetType == typeof(float) || targetType == typeof(float?))
            return numericValues.Min(v => Convert.ToSingle(v));
        if (targetType == typeof(long) || targetType == typeof(long?))
            return numericValues.Min(v => Convert.ToInt64(v));
        if (targetType == typeof(int) || targetType == typeof(int?))
            return numericValues.Min(v => Convert.ToInt32(v));

        return numericValues.Min();
    }

    private static object? MaxValue(List<object?> values, Type targetType)
    {
        var numericValues = values.Where(v => v != null).ToList();
        if (numericValues.Count == 0)
            return GetDefaultValueForAggregate(AggregateFunction.Max, targetType);

        if (targetType == typeof(decimal) || targetType == typeof(decimal?))
            return numericValues.Max(v => Convert.ToDecimal(v));
        if (targetType == typeof(double) || targetType == typeof(double?))
            return numericValues.Max(v => Convert.ToDouble(v));
        if (targetType == typeof(float) || targetType == typeof(float?))
            return numericValues.Max(v => Convert.ToSingle(v));
        if (targetType == typeof(long) || targetType == typeof(long?))
            return numericValues.Max(v => Convert.ToInt64(v));
        if (targetType == typeof(int) || targetType == typeof(int?))
            return numericValues.Max(v => Convert.ToInt32(v));

        return numericValues.Max();
    }

    private static object? GetDefaultValueForAggregate(AggregateFunction aggregate, Type targetType)
    {
        if (aggregate == AggregateFunction.Count)
            return 0;

        // For nullable types, return null
        if (Nullable.GetUnderlyingType(targetType) != null)
            return null;

        // For non-nullable numeric types, return 0
        if (targetType == typeof(decimal))
            return 0m;
        if (targetType == typeof(double))
            return 0.0;
        if (targetType == typeof(float))
            return 0f;
        if (targetType == typeof(long))
            return 0L;
        if (targetType == typeof(int))
            return 0;

        return null;
    }
}
