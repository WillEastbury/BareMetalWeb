using System;
using System.Collections;
using System.Collections.Generic;
using BareMetalWeb.Core;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Data;

public sealed class DataQueryEvaluator : IDataQueryEvaluator
{
    private readonly Action<string>? _debugHook;

    public DataQueryEvaluator(Action<string>? debugHook = null)
    {
        _debugHook = debugHook;
    }

    public bool Matches(object obj, QueryDefinition? query)
    {
        if (query == null)
            return true;

        return EvaluateGroup(obj, query.Clauses, query.Groups, query.Logic);
    }

    private bool EvaluateGroup(object obj, IReadOnlyList<QueryClause> clauses, IReadOnlyList<QueryGroup> groups, QueryGroupLogic logic)
    {
        if (logic == QueryGroupLogic.And)
        {
            foreach (var clause in clauses)
            {
                if (!EvaluateClause(obj, clause))
                    return false;
            }

            foreach (var group in groups)
            {
                if (!EvaluateGroup(obj, group.Clauses, group.Groups, group.Logic))
                    return false;
            }

            return true;
        }

        foreach (var clause in clauses)
        {
            if (EvaluateClause(obj, clause))
                return true;
        }

        foreach (var group in groups)
        {
            if (EvaluateGroup(obj, group.Clauses, group.Groups, group.Logic))
                return true;
        }

        return false;
    }

    private bool EvaluateClause(object obj, QueryClause clause)
    {
        if (string.IsNullOrWhiteSpace(clause.Field))
            return false;

        if (!TryGetMemberValue(obj, clause.Field, out var memberValue, out var memberType))
        {
            if (_debugHook != null)
                _debugHook($"Query field not found: {clause.Field}");
            return false;
        }

        return EvaluateClause(memberValue, memberType, clause);
    }

    /// <summary>
    /// Filters a pre-loaded batch of rows against <paramref name="query"/>, honouring
    /// <paramref name="skip"/> and <paramref name="top"/> for pagination.
    ///
    /// <para>When the batch is large enough and the query shape qualifies (flat AND
    /// clauses, no nested groups), this delegates to <see cref="ColumnQueryExecutor"/>
    /// for vectorised SIMD column scanning. Otherwise the scalar per-row path is used.</para>
    /// </summary>
    public IReadOnlyList<T> FilterBatch<T>(
        IReadOnlyList<T> candidates,
        QueryDefinition? query,
        int skip = 0,
        int top  = int.MaxValue)
        where T : DataRecord
    {
        if (query == null || (query.Clauses.Count == 0 && query.Groups.Count == 0))
        {
            // No filter — return a sliced copy using GetRange when available.
            int start = Math.Min(skip, candidates.Count);
            int end   = Math.Min(start + top, candidates.Count);
            if (candidates is List<T> asList)
                return asList.GetRange(start, end - start);
            var slice = new List<T>(end - start);
            for (int i = start; i < end; i++) slice.Add(candidates[i]);
            return slice;
        }

        if (ColumnQueryExecutor.IsEligible(candidates, query))
            return ColumnQueryExecutor.Filter(candidates[0].EntityTypeName, candidates, query, skip, top);

        // Scalar fallback.
        var result  = new List<T>(Math.Min(top, candidates.Count));
        int matched = 0;
        foreach (var item in candidates)
        {
            if (!Matches(item, query)) continue;
            if (matched++ < skip) continue;
            result.Add(item);
            if (result.Count >= top) break;
        }
        return result;
    }

    public IEnumerable<T> ApplySorts<T>(IEnumerable<T> source, QueryDefinition? query)
    {
        if (query == null || query.Sorts.Count == 0)
            return source;

        // Collect the active sort specifications
        var activeSorts = new List<(string Field, SortDirection Direction)>();
        foreach (var sort in query.Sorts)
        {
            if (!string.IsNullOrWhiteSpace(sort.Field))
                activeSorts.Add((sort.Field, sort.Direction));
        }

        if (activeSorts.Count == 0)
            return source;

        var list = new List<T>(source is ICollection<T> col ? col.Count : 16);
        foreach (var item in source)
            list.Add(item);

        var comparer = new ObjectComparer();
        list.Sort((a, b) =>
        {
            foreach (var (field, direction) in activeSorts)
            {
                var va = GetMemberValue(a!, field);
                var vb = GetMemberValue(b!, field);
                int cmp = comparer.Compare(va, vb);
                if (cmp != 0)
                    return direction == SortDirection.Desc ? -cmp : cmp;
            }
            return 0;
        });

        return list;
    }

    private static bool EvaluateClause(object? memberValue, Type memberType, QueryClause clause)
    {
        var targetValue = ConvertToType(clause.Value, memberType);

        switch (clause.Operator)
        {
            case QueryOperator.Equals:
                return AreEqual(memberValue, targetValue, memberType);
            case QueryOperator.NotEquals:
                return !AreEqual(memberValue, targetValue, memberType);
            case QueryOperator.Contains:
                return Contains(memberValue, targetValue, memberType);
            case QueryOperator.StartsWith:
                return StartsWith(memberValue, targetValue);
            case QueryOperator.EndsWith:
                return EndsWith(memberValue, targetValue);
            case QueryOperator.In:
                return InList(memberValue, clause.Value, memberType);
            case QueryOperator.NotIn:
                return !InList(memberValue, clause.Value, memberType);
            case QueryOperator.GreaterThan:
                return Compare(memberValue, targetValue) > 0;
            case QueryOperator.LessThan:
                return Compare(memberValue, targetValue) < 0;
            case QueryOperator.GreaterThanOrEqual:
                return Compare(memberValue, targetValue) >= 0;
            case QueryOperator.LessThanOrEqual:
                return Compare(memberValue, targetValue) <= 0;
            default:
                return false;
        }
    }

    private static bool AreEqual(object? left, object? right, Type memberType)
    {
        if (left == null && right == null)
            return true;
        if (left == null || right == null)
            return false;

        if (memberType == typeof(string))
            return string.Equals(left.ToString(), right.ToString(), StringComparison.OrdinalIgnoreCase);

        return left.Equals(right);
    }

    private static bool Contains(object? memberValue, object? targetValue, Type memberType)
    {
        if (memberValue == null || targetValue == null)
            return false;

        if (memberValue is string s)
            return s.Contains(targetValue.ToString() ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        if (memberValue is IEnumerable enumerable)
        {
            var elementType = GetEnumerableElementType(memberType);
            // When memberType is object (no schema), infer element type from the collection value
            if (elementType == typeof(object))
            {
                elementType = memberValue switch
                {
                    IList<string> => typeof(string),
                    IList<int> => typeof(int),
                    IList<decimal> => typeof(decimal),
                    IList<double> => typeof(double),
                    IList<long> => typeof(long),
                    _ => typeof(object)
                };
            }
            var listValues = BuildInValues(targetValue, elementType);
            if (listValues.Count == 0)
                return false;

            foreach (var item in enumerable)
            {
                foreach (var candidate in listValues)
                {
                    if (AreEqual(item, candidate, elementType))
                        return true;
                }
            }
        }

        return false;
    }

    private static bool StartsWith(object? memberValue, object? targetValue)
    {
        if (memberValue is string s && targetValue != null)
            return s.StartsWith(targetValue.ToString() ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        return false;
    }

    private static bool EndsWith(object? memberValue, object? targetValue)
    {
        if (memberValue is string s && targetValue != null)
            return s.EndsWith(targetValue.ToString() ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        return false;
    }

    private static bool InList(object? memberValue, object? rawValue, Type memberType)
    {
        if (rawValue == null)
            return false;

        var values = BuildInValues(rawValue, memberType);
        if (values.Count == 0)
            return false;

        foreach (var value in values)
        {
            if (AreEqual(memberValue, value, memberType))
                return true;
        }

        return false;
    }

    private static List<object?> BuildInValues(object rawValue, Type memberType)
    {
        if (rawValue is string s)
        {
            var trimmed = s.Trim();
            if (trimmed.Length >= 2 && trimmed[0] == '[' && trimmed[^1] == ']')
            {
                var inner = trimmed[1..^1];
                if (string.IsNullOrWhiteSpace(inner))
                    return new List<object?>();

                var list = new List<object?>();
                var remaining = inner.AsSpan();
                while (remaining.Length > 0)
                {
                    int idx = remaining.IndexOf(',');
                    ReadOnlySpan<char> segment;
                    if (idx < 0) { segment = remaining; remaining = default; }
                    else { segment = remaining[..idx]; remaining = remaining[(idx + 1)..]; }
                    var part = segment.Trim();
                    if (part.IsEmpty) continue;
                    var normalized = TrimListToken(part.ToString());
                    list.Add(ConvertToType(normalized, memberType));
                }
                return list;
            }

            if (s.IndexOf(',') >= 0)
            {
                var list = new List<object?>();
                var remaining = s.AsSpan();
                while (remaining.Length > 0)
                {
                    int idx = remaining.IndexOf(',');
                    ReadOnlySpan<char> segment;
                    if (idx < 0) { segment = remaining; remaining = default; }
                    else { segment = remaining[..idx]; remaining = remaining[(idx + 1)..]; }
                    var part = segment.Trim();
                    if (part.IsEmpty) continue;
                    var normalized = TrimListToken(part.ToString());
                    list.Add(ConvertToType(normalized, memberType));
                }
                return list;
            }

            return new List<object?> { ConvertToType(s, memberType) };
        }

        if (rawValue is IEnumerable enumerable)
        {
            var list = new List<object?>();
            foreach (var item in enumerable)
            {
                if (item == null)
                {
                    list.Add(null);
                    continue;
                }

                list.Add(ConvertToType(item, memberType));
            }
            return list;
        }

        return new List<object?> { ConvertToType(rawValue, memberType) };
    }

    private static Type GetEnumerableElementType(Type memberType)
    {
        if (memberType.IsArray)
            return memberType.GetElementType() ?? typeof(object);

        if (memberType.IsGenericType)
        {
            var args = memberType.GetGenericArguments();
            if (args.Length == 1)
                return args[0];
        }

        return typeof(object);
    }

    private static string TrimListToken(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length >= 2)
        {
            var first = trimmed[0];
            var last = trimmed[^1];
            if ((first == '"' && last == '"') || (first == '\'' && last == '\''))
                return trimmed[1..^1];
        }

        return trimmed;
    }

    private static int Compare(object? left, object? right)
    {
        if (left == null && right == null)
            return 0;
        if (left == null)
            return -1;
        if (right == null)
            return 1;

        if (left is string ls && right is string rs)
            return string.Compare(ls, rs, StringComparison.OrdinalIgnoreCase);

        if (left is IComparable comparable)
        {
            try
            {
                return comparable.CompareTo(right);
            }
            catch
            {
                // Fall back to string comparison when types are incompatible.
            }
        }

        return string.Compare(left.ToString(), right.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryGetMemberValue(object obj, string field, out object? value, out Type memberType)
    {
        if (obj is DataRecord dataObject)
        {
            var meta = DataScaffold.GetEntityByName(dataObject.EntityTypeName);
            if (meta != null)
            {
                var fieldMeta = meta.FindField(field);
                if (fieldMeta != null)
                {
                    value = fieldMeta.GetValueFn(dataObject);
                    memberType = fieldMeta.ClrType;
                    return true;
                }
            }

            // Fall back to ordinal lookup via entity's field map (covers non-[DataField] properties)
            var fieldMap = dataObject.GetFieldMap();
            int lo = 0, hi = fieldMap.Length - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >>> 1;
                int cmp = string.Compare(fieldMap[mid].Name, field, StringComparison.OrdinalIgnoreCase);
                if (cmp == 0)
                {
                    value = dataObject.GetFieldValue(fieldMap[mid].Ordinal);
                    // Use schema CLR type when available; only fall back to typeof(object) for untyped slots
                    var schema = dataObject.Schema;
                    if (schema != null && fieldMap[mid].Ordinal >= DataRecord.BaseFieldCount)
                    {
                        int schemaIdx = fieldMap[mid].Ordinal - DataRecord.BaseFieldCount;
                        memberType = schemaIdx < schema.ClrTypes.Length ? schema.ClrTypes[schemaIdx] : typeof(object);
                    }
                    else if (fieldMap[mid].Ordinal < DataRecord.BaseFieldCount)
                    {
                        // Well-known base field types — avoids GetType()
                        memberType = fieldMap[mid].Ordinal switch
                        {
                            DataRecord.Ord_Key => typeof(uint),
                            DataRecord.Ord_Identifier => typeof(string),
                            DataRecord.Ord_CreatedOnUtc or DataRecord.Ord_UpdatedOnUtc => typeof(DateTime),
                            DataRecord.Ord_CreatedBy or DataRecord.Ord_UpdatedBy or DataRecord.Ord_ETag => typeof(string),
                            DataRecord.Ord_Version => typeof(int),
                            _ => typeof(object)
                        };
                    }
                    else
                    {
                        // Non-base field without schema — infer type from value via pattern match
                        memberType = value switch
                        {
                            int => typeof(int),
                            uint => typeof(uint),
                            long => typeof(long),
                            decimal => typeof(decimal),
                            double => typeof(double),
                            float => typeof(float),
                            bool => typeof(bool),
                            DateTime => typeof(DateTime),
                            string => typeof(string),
                            _ => typeof(object)
                        };
                    }
                    return true;
                }
                if (cmp < 0) lo = mid + 1;
                else hi = mid - 1;
            }
        }

        value = null;
        memberType = typeof(object);
        return false;
    }

    private static object? GetMemberValue(object obj, string field)
    {
        TryGetMemberValue(obj, field, out var value, out _);
        return value;
    }

    private static object? ConvertToType(object? value, Type targetType)
    {
        if (value == null)
            return null;

        var effectiveType = Nullable.GetUnderlyingType(targetType) ?? targetType;
        if (effectiveType.IsInstanceOfType(value))
            return value;

        if (value is string s)
        {
            if (effectiveType == typeof(DateTime) && DateTime.TryParse(s, out var dt))
                return dt;
            if (effectiveType == typeof(DateOnly) && DateOnly.TryParse(s, out var d))
                return d;
            if (effectiveType == typeof(TimeOnly) && TimeOnly.TryParse(s, out var t))
                return t;
            if (effectiveType.IsEnum && DataScaffold.GetEnumLookup(effectiveType).TryGetValue(s, out var enumValue))
                return enumValue;
        }

        try
        {
            if (effectiveType.IsEnum && value is IConvertible ic)
                return EnumHelper.FromInt32(effectiveType, ic.ToInt32(null));

            // Specific type conversions — AOT-safe, no Convert.ChangeType overhead.
            if (effectiveType == typeof(int))      return Convert.ToInt32(value);
            if (effectiveType == typeof(long))     return Convert.ToInt64(value);
            if (effectiveType == typeof(double))   return Convert.ToDouble(value);
            if (effectiveType == typeof(float))    return Convert.ToSingle(value);
            if (effectiveType == typeof(decimal))  return Convert.ToDecimal(value);
            if (effectiveType == typeof(bool))     return Convert.ToBoolean(value);
            if (effectiveType == typeof(string))   return value.ToString();
            if (effectiveType == typeof(uint))     return Convert.ToUInt32(value);
            if (effectiveType == typeof(short))    return Convert.ToInt16(value);
            if (effectiveType == typeof(ushort))   return Convert.ToUInt16(value);
            if (effectiveType == typeof(byte))     return Convert.ToByte(value);
            if (effectiveType == typeof(sbyte))    return Convert.ToSByte(value);
            if (effectiveType == typeof(ulong))    return Convert.ToUInt64(value);
            if (effectiveType == typeof(DateTime)) return Convert.ToDateTime(value);
            return value;
        }
        catch
        {
            return value;
        }
    }

    private sealed class ObjectComparer : IComparer<object?>
    {
        public int Compare(object? x, object? y) => DataQueryEvaluator.Compare(x, y);
    }
}
