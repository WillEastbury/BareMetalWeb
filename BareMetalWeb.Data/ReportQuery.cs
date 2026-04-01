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

    /// <summary>Selects output columns using "Entity.Field" notation, optionally with a label.</summary>
    public ReportQuery Select(params string[] entityDotField)
    {
        foreach (var col in entityDotField)
        {
            int dotIdx = col.IndexOf('.');
            if (dotIdx > 0 && dotIdx < col.Length - 1)
            {
                _columns.Add(new ReportColumn
                {
                    Entity = col[..dotIdx],
                    Field = col[(dotIdx + 1)..],
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
        int dotIdx = entityDotField.IndexOf('.');
        _filters.Add(dotIdx > 0 && dotIdx < entityDotField.Length - 1
            ? new ReportFilter { Entity = entityDotField[..dotIdx], Field = entityDotField[(dotIdx + 1)..], Operator = op, Value = value }
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
}
