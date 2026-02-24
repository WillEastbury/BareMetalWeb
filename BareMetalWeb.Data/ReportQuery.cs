using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Fluent builder for cross-entity report queries.
/// Use <see cref="ReportExecutor"/> to execute the built query.
/// </summary>
public sealed class ReportQuery
{
    private string _rootEntity = string.Empty;
    private readonly List<ReportJoin> _joins = new();
    private readonly List<ReportColumn> _columns = new();
    private readonly List<ReportFilter> _filters = new();
    private string? _sortField;
    private bool _sortDescending;
    private int? _limit;

    /// <summary>Specifies the root entity by its slug (e.g. "orders").</summary>
    public ReportQuery From(string entitySlug)
    {
        _rootEntity = entitySlug;
        return this;
    }

    /// <summary>Specifies the root entity by its CLR type.</summary>
    public ReportQuery From<T>() where T : BaseDataObject
    {
        _rootEntity = DataScaffold.GetEntityByType(typeof(T))?.Slug ?? typeof(T).Name.ToSlug();
        return this;
    }

    /// <summary>Adds an INNER JOIN between two entity fields.</summary>
    public ReportQuery Join(string fromEntity, string fromField, string toEntity, string toField)
        => AddJoin(fromEntity, fromField, toEntity, toField, JoinType.Inner);

    /// <summary>Adds a LEFT JOIN — all left rows preserved, nulls for unmatched right.</summary>
    public ReportQuery LeftJoin(string fromEntity, string fromField, string toEntity, string toField)
        => AddJoin(fromEntity, fromField, toEntity, toField, JoinType.Left);

    /// <summary>Adds a RIGHT JOIN — all right rows preserved, nulls for unmatched left.</summary>
    public ReportQuery RightJoin(string fromEntity, string fromField, string toEntity, string toField)
        => AddJoin(fromEntity, fromField, toEntity, toField, JoinType.Right);

    /// <summary>Adds a FULL OUTER JOIN — all rows from both sides preserved.</summary>
    public ReportQuery FullOuterJoin(string fromEntity, string fromField, string toEntity, string toField)
        => AddJoin(fromEntity, fromField, toEntity, toField, JoinType.FullOuter);

    private ReportQuery AddJoin(string fromEntity, string fromField, string toEntity, string toField, JoinType type)
    {
        _joins.Add(new ReportJoin
        {
            FromEntity = fromEntity,
            FromField = fromField,
            ToEntity = toEntity,
            ToField = toField,
            Type = type
        });
        return this;
    }

    /// <summary>Adds an INNER JOIN using CLR type accessors.</summary>
    public ReportQuery Join<TFrom, TTo>(
        System.Linq.Expressions.Expression<Func<TFrom, object?>> fromField,
        System.Linq.Expressions.Expression<Func<TTo, object?>> toField)
        where TFrom : BaseDataObject
        where TTo : BaseDataObject
    {
        var fromFieldName = GetMemberName(fromField);
        var toFieldName = GetMemberName(toField);
        _joins.Add(new ReportJoin
        {
            FromEntity = DataScaffold.GetEntityByType(typeof(TFrom))?.Slug ?? typeof(TFrom).Name.ToSlug(),
            FromField = fromFieldName,
            ToEntity = DataScaffold.GetEntityByType(typeof(TTo))?.Slug ?? typeof(TTo).Name.ToSlug(),
            ToField = toFieldName,
            Type = JoinType.Inner
        });
        return this;
    }

    /// <summary>Selects output columns using "Entity.Field" notation, optionally with a label.</summary>
    public ReportQuery Select(params string[] entityDotField)
    {
        foreach (var col in entityDotField)
        {
            var parts = col.Split('.');
            if (parts.Length == 2)
            {
                _columns.Add(new ReportColumn
                {
                    Entity = parts[0],
                    Field = parts[1],
                    Label = col
                });
            }
        }
        return this;
    }

    /// <summary>Adds a single output column with a display label.</summary>
    public ReportQuery SelectColumn(string entity, string field, string label, string format = "", AggregateFunction aggregate = AggregateFunction.None)
    {
        _columns.Add(new ReportColumn
        {
            Entity = entity,
            Field = field,
            Label = label,
            Format = format,
            Aggregate = aggregate
        });
        return this;
    }

    /// <summary>Adds a filter predicate ("Entity.Field", operator, value).</summary>
    public ReportQuery Where(string entityDotField, string op, string value)
    {
        var parts = entityDotField.Split('.');
        _filters.Add(parts.Length == 2
            ? new ReportFilter { Entity = parts[0], Field = parts[1], Operator = op, Value = value }
            : new ReportFilter { Entity = _rootEntity, Field = entityDotField, Operator = op, Value = value });
        return this;
    }

    /// <summary>Specifies the sort column ("Entity.Field") and direction.</summary>
    public ReportQuery OrderBy(string entityDotField, bool descending = false)
    {
        _sortField = entityDotField;
        _sortDescending = descending;
        return this;
    }

    /// <summary>Caps the maximum number of result rows returned.</summary>
    public ReportQuery Limit(int maxRows)
    {
        _limit = maxRows;
        return this;
    }

    // Internal accessors used by ReportExecutor
    internal string RootEntity => _rootEntity;
    internal IReadOnlyList<ReportJoin> Joins => _joins;
    internal IReadOnlyList<ReportColumn> Columns => _columns;
    internal IReadOnlyList<ReportFilter> Filters => _filters;
    internal string? SortField => _sortField;
    internal bool SortDescending => _sortDescending;
    internal int? QueryLimit => _limit;

    private static string GetMemberName<T>(System.Linq.Expressions.Expression<Func<T, object?>> expr)
    {
        if (expr.Body is System.Linq.Expressions.MemberExpression memberExpr)
            return memberExpr.Member.Name;
        if (expr.Body is System.Linq.Expressions.UnaryExpression unary &&
            unary.Operand is System.Linq.Expressions.MemberExpression memberExpr2)
            return memberExpr2.Member.Name;
        throw new ArgumentException("Expression must be a simple member access (e.g. x => x.PropertyName).");
    }
}

internal static class StringSlugExtensions
{
    internal static string ToSlug(this string name)
    {
        // Mirrors DataScaffold slug generation: lowercase + hyphenate on camel-case boundaries
        if (string.IsNullOrEmpty(name))
            return name;

        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c) && i > 0)
                sb.Append('-');
            sb.Append(char.ToLowerInvariant(c));
        }
        return sb.ToString();
    }
}
