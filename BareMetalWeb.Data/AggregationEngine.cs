using System.Runtime.CompilerServices;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Streaming single-pass aggregation engine. Uses compiled getters from EntityLayout
/// or DataFieldMetadata — no reflection in the accumulation loop.
/// </summary>
public static class AggregationEngine
{
    /// <summary>
    /// Compute an aggregate over a query result set using a compiled getter.
    /// Single-pass streaming — does not materialise the full result list for sum/avg/stddev.
    /// </summary>
    public static async ValueTask<AggregateResult> ComputeAsync(
        DataEntityMetadata meta,
        QueryDefinition? query,
        string fieldName,
        AggregateFunction function,
        CancellationToken cancellationToken = default)
    {
        if (function == AggregateFunction.None)
            return new AggregateResult(function, fieldName, null, 0);

        // Count fast path — no need to load entities
        if (function == AggregateFunction.Count)
        {
            var count = await meta.Handlers.CountAsync(query, cancellationToken);
            return new AggregateResult(function, fieldName, count, count);
        }

        // Resolve getter — prefer compiled from DataFieldMetadata, fallback to EntityLayout
        Func<object, object?>? getter = null;
        DataFieldMetadata? field = null;
        foreach (var f in meta.Fields)
        {
            if (string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase))
            {
                field = f;
                break;
            }
        }
        if (field != null)
        {
            getter = field.GetValueFn; // compiled delegate, no reflection
        }
        else
        {
            // Try EntityLayout
            var layout = EntityLayoutCompiler.GetOrCompile(meta);
            var fr = layout.FieldByName(fieldName);
            if (fr != null) getter = fr.Getter;
        }

        if (getter == null)
            return new AggregateResult(function, fieldName, null, 0);

        // Stream entities and accumulate
        var entities = await meta.Handlers.QueryAsync(query, cancellationToken);
        var acc = new StreamingAccumulator(function);

        foreach (var entity in entities)
        {
            var val = getter(entity);
            if (val == null) continue;
            acc.Add(ToDouble(val));
        }

        return new AggregateResult(function, fieldName, acc.Result(), acc.Count);
    }

    /// <summary>
    /// Compute multiple aggregates in a single pass over the data.
    /// </summary>
    public static async ValueTask<AggregateResult[]> ComputeMultiAsync(
        DataEntityMetadata meta,
        QueryDefinition? query,
        (string FieldName, AggregateFunction Function)[] aggregates,
        CancellationToken cancellationToken = default)
    {
        if (aggregates.Length == 0)
            return Array.Empty<AggregateResult>();

        // Fast path: all are Count
        bool allCount = true;
        foreach (var a in aggregates)
        {
            if (a.Function != AggregateFunction.Count)
            {
                allCount = false;
                break;
            }
        }
        if (allCount)
        {
            var count = await meta.Handlers.CountAsync(query, cancellationToken);
            var countResults = new AggregateResult[aggregates.Length];
            for (int i = 0; i < aggregates.Length; i++)
                countResults[i] = new AggregateResult(aggregates[i].Function, aggregates[i].FieldName, count, count);
            return countResults;
        }

        // Resolve getters
        var layout = EntityLayoutCompiler.GetOrCompile(meta);
        var fieldsByName = new Dictionary<string, DataFieldMetadata>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in meta.Fields)
            fieldsByName[f.Name] = f;
        var accumulators = new (Func<object, object?>? Getter, StreamingAccumulator Acc, string FieldName, AggregateFunction Fn)[aggregates.Length];

        for (int i = 0; i < aggregates.Length; i++)
        {
            Func<object, object?>? getter = null;
            if (fieldsByName.TryGetValue(aggregates[i].FieldName, out var fm))
                getter = fm.GetValueFn;
            else
            {
                var fr = layout.FieldByName(aggregates[i].FieldName);
                if (fr != null) getter = fr.Getter;
            }
            accumulators[i] = (getter, new StreamingAccumulator(aggregates[i].Function), aggregates[i].FieldName, aggregates[i].Function);
        }

        // Single pass
        var entities = await meta.Handlers.QueryAsync(query, cancellationToken);
        foreach (var entity in entities)
        {
            for (int i = 0; i < accumulators.Length; i++)
            {
                ref var a = ref accumulators[i];
                if (a.Fn == AggregateFunction.Count)
                {
                    a.Acc.Add(0); // just increment count
                    continue;
                }
                if (a.Getter == null) continue;
                var val = a.Getter(entity);
                if (val == null) continue;
                a.Acc.Add(ToDouble(val));
            }
        }

        var results = new AggregateResult[aggregates.Length];
        for (int i = 0; i < aggregates.Length; i++)
            results[i] = new AggregateResult(accumulators[i].Fn, accumulators[i].FieldName, accumulators[i].Acc.Result(), accumulators[i].Acc.Count);
        return results;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static double ToDouble(object val) => val switch
    {
        int i => i,
        uint u => u,
        long l => l,
        ulong ul => ul,
        float f => f,
        double d => d,
        decimal m => (double)m,
        short s => s,
        ushort us => us,
        byte b => b,
        sbyte sb => sb,
        _ => Convert.ToDouble(val),
    };

    /// <summary>
    /// Single-pass streaming accumulator supporting all aggregate functions.
    /// Uses Welford's online algorithm for StdDev (numerically stable).
    /// </summary>
    private struct StreamingAccumulator
    {
        private readonly AggregateFunction _fn;
        private double _sum;
        private double _min;
        private double _max;
        private double _m2;     // Welford: sum of squared diffs
        private double _mean;   // Welford: running mean
        public int Count;

        public StreamingAccumulator(AggregateFunction fn)
        {
            _fn = fn;
            _sum = 0;
            _min = double.MaxValue;
            _max = double.MinValue;
            _m2 = 0;
            _mean = 0;
            Count = 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void Add(double value)
        {
            Count++;
            switch (_fn)
            {
                case AggregateFunction.Count:
                    break;
                case AggregateFunction.Sum:
                    _sum += value;
                    break;
                case AggregateFunction.Min:
                    if (value < _min) _min = value;
                    break;
                case AggregateFunction.Max:
                    if (value > _max) _max = value;
                    break;
                case AggregateFunction.Average:
                    _sum += value;
                    break;
                case AggregateFunction.StdDev:
                    // Welford's online algorithm
                    double delta = value - _mean;
                    _mean += delta / Count;
                    double delta2 = value - _mean;
                    _m2 += delta * delta2;
                    break;
            }
        }

        public object? Result() => _fn switch
        {
            AggregateFunction.Count => Count,
            AggregateFunction.Sum => _sum,
            AggregateFunction.Min => Count > 0 ? _min : null,
            AggregateFunction.Max => Count > 0 ? _max : null,
            AggregateFunction.Average => Count > 0 ? _sum / Count : null,
            AggregateFunction.StdDev => Count > 1 ? Math.Sqrt(_m2 / Count) : (Count == 1 ? 0.0 : null),
            _ => null,
        };
    }
}

/// <summary>Result of a single aggregation.</summary>
public sealed record AggregateResult(
    AggregateFunction Function,
    string FieldName,
    object? Value,
    int Count);
