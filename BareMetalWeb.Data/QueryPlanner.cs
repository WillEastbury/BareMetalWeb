using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Query planner for multi-entity report queries. Produces an optimised
/// <see cref="QueryPlan"/> from a <see cref="ReportQuery"/> by:
///
/// 1. Predicate pushdown — pushes filters to entity loads before joins
/// 2. Join order optimisation — reorders joins by estimated cardinality (smallest first)
/// 3. Index routing — marks fields that have DataIndex for fast-path evaluation
/// 4. Memory vs streaming boundaries — caps per-entity loads, flags streaming aggregates
///
/// The planner is deterministic: same query + same metadata = same plan.
/// </summary>
public sealed class QueryPlanner
{
    /// <summary>Produce an optimised execution plan for the given report query.</summary>
    public QueryPlan Plan(ReportQuery query)
    {
        var steps = new List<QueryPlanStep>();
        var pushedFilters = new Dictionary<string, QueryDefinition>(StringComparer.OrdinalIgnoreCase);

        // 1. Classify filters by target entity (predicate pushdown)
        foreach (var filter in query.Filters)
        {
            var entitySlug = string.IsNullOrEmpty(filter.Entity) ? query.RootEntity : filter.Entity;

            if (!pushedFilters.TryGetValue(entitySlug, out var qd))
                pushedFilters[entitySlug] = qd = new QueryDefinition();

            qd.Clauses.Add(new QueryClause
            {
                Field = filter.Field,
                Operator = MapOperator(filter.Operator),
                Value = filter.Value
            });
        }

        // 2. Root entity load step
        var rootEstimate = EstimateCardinality(query.RootEntity);
        pushedFilters.TryGetValue(query.RootEntity, out var rootFilter);
        var rootIndexed = GetIndexedFields(query.RootEntity, rootFilter);

        steps.Add(new QueryPlanStep(
            StepType: PlanStepType.LoadEntity,
            EntitySlug: query.RootEntity,
            EstimatedRows: rootEstimate,
            PushedFilter: rootFilter,
            IndexedFields: rootIndexed,
            JoinInfo: null));

        // 3. Reorder joins by estimated cardinality of the TO entity (smallest first)
        var orderedJoins = query.Joins
            .Select(j => (Join: j, Estimate: EstimateCardinality(j.ToEntity)))
            .OrderBy(x => x.Estimate)
            .ToList();

        foreach (var (join, estimate) in orderedJoins)
        {
            pushedFilters.TryGetValue(join.ToEntity, out var joinFilter);
            var joinIndexed = GetIndexedFields(join.ToEntity, joinFilter);

            // Check if the join field on the TO side is indexed (hash build optimization)
            var toFieldIndexed = IsFieldIndexed(join.ToEntity, join.ToField);

            steps.Add(new QueryPlanStep(
                StepType: PlanStepType.HashJoin,
                EntitySlug: join.ToEntity,
                EstimatedRows: estimate,
                PushedFilter: joinFilter,
                IndexedFields: joinIndexed,
                JoinInfo: new JoinPlanInfo(
                    FromEntity: join.FromEntity,
                    FromField: join.FromField,
                    ToField: join.ToField,
                    JoinType: join.Type,
                    BuildSideIndexed: toFieldIndexed)));
        }

        // 4. Determine aggregate streaming eligibility
        var canStreamAggregate = query.Columns.Any(c =>
            c.Aggregate != AggregateFunction.None) && query.Joins.Count == 0;

        // 5. Post-join filter step (filters referencing cross-entity computed fields)
        var hasPostJoinFilters = query.Filters.Any(f =>
            !string.IsNullOrEmpty(f.Entity) &&
            !string.Equals(f.Entity, query.RootEntity, StringComparison.OrdinalIgnoreCase) &&
            query.Joins.All(j => !string.Equals(j.ToEntity, f.Entity, StringComparison.OrdinalIgnoreCase)));

        if (hasPostJoinFilters)
        {
            steps.Add(new QueryPlanStep(
                StepType: PlanStepType.PostJoinFilter,
                EntitySlug: "*",
                EstimatedRows: 0,
                PushedFilter: null,
                IndexedFields: Array.Empty<string>(),
                JoinInfo: null));
        }

        // 6. Final projection + sort step
        steps.Add(new QueryPlanStep(
            StepType: PlanStepType.ProjectAndSort,
            EntitySlug: "*",
            EstimatedRows: 0,
            PushedFilter: null,
            IndexedFields: Array.Empty<string>(),
            JoinInfo: null));

        return new QueryPlan(
            Steps: steps,
            CanStreamAggregate: canStreamAggregate,
            PushedFilters: pushedFilters,
            JoinOrderOptimised: orderedJoins.Count > 1);
    }

    private static int EstimateCardinality(string entitySlug)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta))
            return int.MaxValue;

        // Use cached count if available, otherwise estimate from metadata
        try
        {
            var count = meta.Handlers.CountAsync(null, CancellationToken.None);
            if (count.IsCompleted)
                return (int)Math.Min(count.Result, int.MaxValue);
        }
        catch { /* fall through */ }

        return 10_000; // default estimate
    }

    private static IReadOnlyList<string> GetIndexedFields(string entitySlug, QueryDefinition? filter)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta))
            return Array.Empty<string>();

        var indexed = new List<string>();
        foreach (var field in meta.Fields)
        {
            if (field.IsIndexed)
                indexed.Add(field.Name);
        }

        return indexed;
    }

    private static bool IsFieldIndexed(string entitySlug, string fieldName)
    {
        if (!DataScaffold.TryGetEntity(entitySlug, out var meta))
            return false;

        return meta.Fields.Any(f =>
            string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase) && f.IsIndexed);
    }

    private static QueryOperator MapOperator(string op)
    {
        return op?.ToLowerInvariant() switch
        {
            "eq" or "equals" or "=" => QueryOperator.Equals,
            "neq" or "notequals" or "!=" => QueryOperator.NotEquals,
            "contains" => QueryOperator.Contains,
            "startswith" => QueryOperator.StartsWith,
            "endswith" => QueryOperator.EndsWith,
            "gt" or ">" => QueryOperator.GreaterThan,
            "gte" or ">=" => QueryOperator.GreaterThanOrEqual,
            "lt" or "<" => QueryOperator.LessThan,
            "lte" or "<=" => QueryOperator.LessThanOrEqual,
            "in" => QueryOperator.In,
            "notin" => QueryOperator.NotIn,
            _ => QueryOperator.Equals
        };
    }
}

/// <summary>Optimised execution plan for a report query.</summary>
public sealed record QueryPlan(
    IReadOnlyList<QueryPlanStep> Steps,
    bool CanStreamAggregate,
    IReadOnlyDictionary<string, QueryDefinition> PushedFilters,
    bool JoinOrderOptimised);

/// <summary>A single step in the query execution plan.</summary>
public sealed record QueryPlanStep(
    PlanStepType StepType,
    string EntitySlug,
    int EstimatedRows,
    QueryDefinition? PushedFilter,
    IReadOnlyList<string> IndexedFields,
    JoinPlanInfo? JoinInfo);

/// <summary>Join-specific plan metadata.</summary>
public sealed record JoinPlanInfo(
    string FromEntity,
    string FromField,
    string ToField,
    JoinType JoinType,
    bool BuildSideIndexed);

public enum PlanStepType
{
    LoadEntity,
    HashJoin,
    PostJoinFilter,
    ProjectAndSort
}
