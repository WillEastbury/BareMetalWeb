using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
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
    private static readonly ConcurrentDictionary<(Type, string), Func<object, object?>?> _getterCache = new();
    private static DateTime _lastCacheScavenge = DateTime.UtcNow;
    private const int MaxCacheEntries = 10_000;

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
        foreach (var field in metadata.Fields)
        {
            if (field.Computed == null)
                continue;

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
                field.SetValueFn(instance, value);
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
            return field.GetValueFn(instance);

        if (config.Strategy == ComputedStrategy.Snapshot)
        {
            // Snapshot values are stored in the property
            return field.GetValueFn(instance);
        }

        if (config.Strategy == ComputedStrategy.CachedLive)
        {
            ScavengeExpiredEntries();
            var cacheKey = $"{metadata.Type.FullName}.{instance.Key}.{field.Name}";
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
        // Stream removal — avoid materializing all keys into a list.
        foreach (var key in _cache.Keys)
        {
            if (key.StartsWith(prefix))
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

    /// <summary>Evict expired entries and enforce max size. Runs at most once per 30 seconds.</summary>
    private static void ScavengeExpiredEntries()
    {
        var now = DateTime.UtcNow;
        if ((now - _lastCacheScavenge).TotalSeconds < 30) return;
        _lastCacheScavenge = now;

        foreach (var kvp in _cache)
        {
            if (kvp.Value.ExpiresUtc < now)
                _cache.TryRemove(kvp.Key, out _);
        }

        // Hard cap: if still over limit, remove oldest entries
        if (_cache.Count > MaxCacheEntries)
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

    private static Func<object, object?>? GetCachedGetter(Type type, string name)
    {
        return _getterCache.GetOrAdd((type, name), static key =>
        {
            // Prefer entity metadata compiled getter over raw reflection
            var meta = DataScaffold.GetEntityByType(key.Item1);
            var field = meta?.FindField(key.Item2);
            if (field != null)
                return field.GetValueFn;

            var prop = key.Item1.GetProperty(key.Item2);
            return prop != null ? PropertyAccessorFactory.BuildGetter(prop) : null;
        });
    }

    private static async ValueTask<object?> ComputeLookupAsync(
        DataEntityMetadata metadata,
        BaseDataObject instance,
        DataFieldMetadata field,
        ComputedFieldConfig config,
        CancellationToken cancellationToken)
    {
        // Get the foreign key value
        var fkGetter = GetCachedGetter(metadata.Type, config.ForeignKeyField!);
        if (fkGetter == null)
            return null;

        var foreignKeyValue = fkGetter(instance)?.ToString();
        if (string.IsNullOrEmpty(foreignKeyValue) || !uint.TryParse(foreignKeyValue, out var foreignKey))
            return null;

        // Load the related entity
        var sourceMetadata = DataScaffold.GetEntityByType(config.SourceEntity!);
        if (sourceMetadata == null)
            return null;

        var relatedEntity = await sourceMetadata.Handlers.LoadAsync(foreignKey, cancellationToken);
        if (relatedEntity == null)
            return null;

        // Get the source field value
        var sourceGetter = GetCachedGetter(config.SourceEntity!, config.SourceField!);
        if (sourceGetter == null)
            return null;

        return sourceGetter(relatedEntity);
    }

    private static async ValueTask<object?> ComputeAggregationAsync(
        DataEntityMetadata metadata,
        BaseDataObject instance,
        DataFieldMetadata field,
        ComputedFieldConfig config,
        CancellationToken cancellationToken)
    {
        // Get the child collection property
        var collectionGetter = GetCachedGetter(metadata.Type, config.ChildCollectionProperty!);
        if (collectionGetter == null)
            return null;

        var collection = collectionGetter(instance) as IEnumerable;
        if (collection == null)
        {
            // Try to query for child entities if the collection isn't loaded
            // This would require knowing the child entity type and foreign key relationship
            // For now, return default value
            return GetDefaultValueForAggregate(config.Aggregate, field.ClrType);
        }

        var items = new List<object>();
        foreach (var item in collection)
        {
            items.Add(item);
        }

        if (string.IsNullOrEmpty(config.SourceField))
        {
            // Count aggregation doesn't need a source field
            if (config.Aggregate == AggregateFunction.Count)
                return items.Count;
            
            return GetDefaultValueForAggregate(config.Aggregate, field.ClrType);
        }

        // Get values from the source field (cache lookup per item type)
        var values = new List<object?>();
        Func<object, object?>? cachedSourceGetter = null;
        Type? cachedItemType = null;
        foreach (var item in items)
        {
            var itemType = item.GetType();
            if (itemType != cachedItemType)
            {
                cachedItemType = itemType;
                cachedSourceGetter = GetCachedGetter(itemType, config.SourceField);
            }
            if (cachedSourceGetter != null)
            {
                values.Add(cachedSourceGetter(item));
            }
        }

        return ApplyAggregateFunction(config.Aggregate, values, field.ClrType);
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
                return values.Count > 0 ? values[0] : null;
        }
    }

    private static List<object> FilterNonNull(List<object?> values)
    {
        var result = new List<object>(values.Count);
        foreach (var v in values)
        {
            if (v != null)
                result.Add(v);
        }
        return result;
    }

    private static object? SumValues(List<object?> values, Type targetType)
    {
        var numericValues = FilterNonNull(values);
        if (numericValues.Count == 0)
            return GetDefaultValueForAggregate(AggregateFunction.Sum, targetType);

        if (targetType == typeof(decimal) || targetType == typeof(decimal?))
        {
            decimal sum = 0m;
            foreach (var v in numericValues)
                sum += Convert.ToDecimal(v);
            return sum;
        }
        if (targetType == typeof(double) || targetType == typeof(double?))
        {
            double sum = 0.0;
            foreach (var v in numericValues)
                sum += Convert.ToDouble(v);
            return sum;
        }
        if (targetType == typeof(float) || targetType == typeof(float?))
        {
            double sum = 0.0;
            foreach (var v in numericValues)
                sum += Convert.ToDouble(v);
            return (float)sum;
        }
        if (targetType == typeof(long) || targetType == typeof(long?))
        {
            long sum = 0L;
            foreach (var v in numericValues)
                sum += Convert.ToInt64(v);
            return sum;
        }
        if (targetType == typeof(int) || targetType == typeof(int?))
        {
            int sum = 0;
            foreach (var v in numericValues)
                sum += Convert.ToInt32(v);
            return sum;
        }

        {
            decimal sum = 0m;
            foreach (var v in numericValues)
                sum += Convert.ToDecimal(v);
            return sum;
        }
    }

    private static object? AverageValues(List<object?> values, Type targetType)
    {
        var numericValues = FilterNonNull(values);
        if (numericValues.Count == 0)
            return GetDefaultValueForAggregate(AggregateFunction.Average, targetType);

        if (targetType == typeof(decimal) || targetType == typeof(decimal?))
        {
            decimal sum = 0m;
            foreach (var v in numericValues)
                sum += Convert.ToDecimal(v);
            return sum / numericValues.Count;
        }
        if (targetType == typeof(double) || targetType == typeof(double?))
        {
            double sum = 0.0;
            foreach (var v in numericValues)
                sum += Convert.ToDouble(v);
            return sum / numericValues.Count;
        }
        if (targetType == typeof(float) || targetType == typeof(float?))
        {
            double sum = 0.0;
            foreach (var v in numericValues)
                sum += Convert.ToDouble(v);
            return (float)(sum / numericValues.Count);
        }

        {
            decimal sum = 0m;
            foreach (var v in numericValues)
                sum += Convert.ToDecimal(v);
            return sum / numericValues.Count;
        }
    }

    private static object? MinValue(List<object?> values, Type targetType)
    {
        var numericValues = FilterNonNull(values);
        if (numericValues.Count == 0)
            return GetDefaultValueForAggregate(AggregateFunction.Min, targetType);

        if (targetType == typeof(decimal) || targetType == typeof(decimal?))
        {
            decimal min = Convert.ToDecimal(numericValues[0]);
            for (int i = 1; i < numericValues.Count; i++)
            {
                decimal val = Convert.ToDecimal(numericValues[i]);
                if (val < min) min = val;
            }
            return min;
        }
        if (targetType == typeof(double) || targetType == typeof(double?))
        {
            double min = Convert.ToDouble(numericValues[0]);
            for (int i = 1; i < numericValues.Count; i++)
            {
                double val = Convert.ToDouble(numericValues[i]);
                if (val < min) min = val;
            }
            return min;
        }
        if (targetType == typeof(float) || targetType == typeof(float?))
        {
            float min = Convert.ToSingle(numericValues[0]);
            for (int i = 1; i < numericValues.Count; i++)
            {
                float val = Convert.ToSingle(numericValues[i]);
                if (val < min) min = val;
            }
            return min;
        }
        if (targetType == typeof(long) || targetType == typeof(long?))
        {
            long min = Convert.ToInt64(numericValues[0]);
            for (int i = 1; i < numericValues.Count; i++)
            {
                long val = Convert.ToInt64(numericValues[i]);
                if (val < min) min = val;
            }
            return min;
        }
        if (targetType == typeof(int) || targetType == typeof(int?))
        {
            int min = Convert.ToInt32(numericValues[0]);
            for (int i = 1; i < numericValues.Count; i++)
            {
                int val = Convert.ToInt32(numericValues[i]);
                if (val < min) min = val;
            }
            return min;
        }

        {
            var comparer = Comparer<object>.Default;
            object min = numericValues[0];
            for (int i = 1; i < numericValues.Count; i++)
            {
                if (comparer.Compare(numericValues[i], min) < 0)
                    min = numericValues[i];
            }
            return min;
        }
    }

    private static object? MaxValue(List<object?> values, Type targetType)
    {
        var numericValues = FilterNonNull(values);
        if (numericValues.Count == 0)
            return GetDefaultValueForAggregate(AggregateFunction.Max, targetType);

        if (targetType == typeof(decimal) || targetType == typeof(decimal?))
        {
            decimal max = Convert.ToDecimal(numericValues[0]);
            for (int i = 1; i < numericValues.Count; i++)
            {
                decimal val = Convert.ToDecimal(numericValues[i]);
                if (val > max) max = val;
            }
            return max;
        }
        if (targetType == typeof(double) || targetType == typeof(double?))
        {
            double max = Convert.ToDouble(numericValues[0]);
            for (int i = 1; i < numericValues.Count; i++)
            {
                double val = Convert.ToDouble(numericValues[i]);
                if (val > max) max = val;
            }
            return max;
        }
        if (targetType == typeof(float) || targetType == typeof(float?))
        {
            float max = Convert.ToSingle(numericValues[0]);
            for (int i = 1; i < numericValues.Count; i++)
            {
                float val = Convert.ToSingle(numericValues[i]);
                if (val > max) max = val;
            }
            return max;
        }
        if (targetType == typeof(long) || targetType == typeof(long?))
        {
            long max = Convert.ToInt64(numericValues[0]);
            for (int i = 1; i < numericValues.Count; i++)
            {
                long val = Convert.ToInt64(numericValues[i]);
                if (val > max) max = val;
            }
            return max;
        }
        if (targetType == typeof(int) || targetType == typeof(int?))
        {
            int max = Convert.ToInt32(numericValues[0]);
            for (int i = 1; i < numericValues.Count; i++)
            {
                int val = Convert.ToInt32(numericValues[i]);
                if (val > max) max = val;
            }
            return max;
        }

        {
            var comparer = Comparer<object>.Default;
            object max = numericValues[0];
            for (int i = 1; i < numericValues.Count; i++)
            {
                if (comparer.Compare(numericValues[i], max) > 0)
                    max = numericValues[i];
            }
            return max;
        }
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
