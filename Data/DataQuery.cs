using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Data;

public enum QueryOperator
{
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    In,
    NotIn,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual
}

public sealed class QueryClause
{
    public string Field { get; set; } = string.Empty;
    public QueryOperator Operator { get; set; } = QueryOperator.Equals;
    public object? Value { get; set; }
}

public enum SortDirection
{
    Asc,
    Desc
}

public enum QueryGroupLogic
{
    And,
    Or
}

public sealed class SortClause
{
    public string Field { get; set; } = string.Empty;
    public SortDirection Direction { get; set; } = SortDirection.Asc;
}

public sealed class QueryDefinition
{
    public List<QueryClause> Clauses { get; set; } = new();
    public List<QueryGroup> Groups { get; set; } = new();
    public QueryGroupLogic Logic { get; set; } = QueryGroupLogic.And;
    public List<SortClause> Sorts { get; set; } = new();
    public int? Skip { get; set; }
    public int? Top { get; set; }
}

public sealed class QueryGroup
{
    public List<QueryClause> Clauses { get; set; } = new();
    public List<QueryGroup> Groups { get; set; } = new();
    public QueryGroupLogic Logic { get; set; } = QueryGroupLogic.And;
}

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

    public IEnumerable<T> ApplySorts<T>(IEnumerable<T> source, QueryDefinition? query)
    {
        if (query == null || query.Sorts.Count == 0)
            return source;

        IOrderedEnumerable<T>? ordered = null;
        var comparer = new ObjectComparer();

        foreach (var sort in query.Sorts)
        {
            if (string.IsNullOrWhiteSpace(sort.Field))
                continue;

            if (ordered == null)
            {
                ordered = sort.Direction == SortDirection.Desc
                    ? source.OrderByDescending(item => GetMemberValue(item!, sort.Field), comparer)
                    : source.OrderBy(item => GetMemberValue(item!, sort.Field), comparer);
            }
            else
            {
                ordered = sort.Direction == SortDirection.Desc
                    ? ordered.ThenByDescending(item => GetMemberValue(item!, sort.Field), comparer)
                    : ordered.ThenBy(item => GetMemberValue(item!, sort.Field), comparer);
            }
        }

        return ordered ?? source;
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

                var parts = inner.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                var list = new List<object?>(parts.Length);
                foreach (var part in parts)
                {
                    var normalized = TrimListToken(part);
                    list.Add(ConvertToType(normalized, memberType));
                }
                return list;
            }

            if (s.IndexOf(',') >= 0)
            {
                var parts = s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                var list = new List<object?>(parts.Length);
                foreach (var part in parts)
                {
                    var normalized = TrimListToken(part);
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
        if (obj is BaseDataObject dataObject)
        {
            var meta = DataScaffold.GetEntityByType(dataObject.GetType());
            if (meta != null)
            {
                var fieldMeta = meta.Fields.FirstOrDefault(f => string.Equals(f.Name, field, StringComparison.OrdinalIgnoreCase));
                if (fieldMeta != null)
                {
                    value = fieldMeta.Property.GetValue(dataObject);
                    memberType = fieldMeta.Property.PropertyType;
                    return true;
                }
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
        if (effectiveType.IsAssignableFrom(value.GetType()))
            return value;

        if (value is string s)
        {
            if (effectiveType == typeof(DateTime) && DateTime.TryParse(s, out var dt))
                return dt;
            if (effectiveType == typeof(DateOnly) && DateOnly.TryParse(s, out var d))
                return d;
            if (effectiveType == typeof(TimeOnly) && TimeOnly.TryParse(s, out var t))
                return t;
            if (effectiveType.IsEnum && Enum.TryParse(effectiveType, s, ignoreCase: true, out var enumValue))
                return enumValue;
        }

        try
        {
            if (effectiveType.IsEnum)
                return Enum.ToObject(effectiveType, Convert.ChangeType(value, Enum.GetUnderlyingType(effectiveType))!);

            return Convert.ChangeType(value, effectiveType);
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
