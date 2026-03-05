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
        var missingIndexes = new List<MissingIndexRecommendation>();

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

        // Detect missing indexes on root entity filter fields
        if (rootFilter != null)
        {
            foreach (var clause in rootFilter.Clauses)
            {
                if (!IsFieldIndexed(query.RootEntity, clause.Field))
                    missingIndexes.Add(new MissingIndexRecommendation(
                        EntitySlug: query.RootEntity,
                        FieldName: clause.Field,
                        Reason: $"Filter on '{clause.Field}' performs a full table scan; an index would speed up predicate pushdown."));
            }
        }

        steps.Add(new QueryPlanStep(
            StepType: PlanStepType.LoadEntity,
            EntitySlug: query.RootEntity,
            EstimatedRows: rootEstimate,
            PushedFilter: rootFilter,
            IndexedFields: rootIndexed,
            JoinInfo: null));

        // 3. Reorder joins by estimated cardinality of the TO entity (smallest first)
        var orderedJoins = new List<(ReportJoin Join, int Estimate)>();
        foreach (var j in query.Joins)
            orderedJoins.Add((j, EstimateCardinality(j.ToEntity)));
        orderedJoins.Sort((a, b) => a.Estimate.CompareTo(b.Estimate));

        foreach (var (join, estimate) in orderedJoins)
        {
            pushedFilters.TryGetValue(join.ToEntity, out var joinFilter);
            var joinIndexed = GetIndexedFields(join.ToEntity, joinFilter);

            // Check if the join field on the TO side is indexed (hash build optimization)
            var toFieldIndexed = IsFieldIndexed(join.ToEntity, join.ToField);

            if (!toFieldIndexed)
                missingIndexes.Add(new MissingIndexRecommendation(
                    EntitySlug: join.ToEntity,
                    FieldName: join.ToField,
                    Reason: $"Hash-join build side on '{join.ToEntity}.{join.ToField}' is unindexed; an index would eliminate linear probing during join."));

            if (joinFilter != null)
            {
                foreach (var clause in joinFilter.Clauses)
                {
                    if (!IsFieldIndexed(join.ToEntity, clause.Field))
                        missingIndexes.Add(new MissingIndexRecommendation(
                            EntitySlug: join.ToEntity,
                            FieldName: clause.Field,
                            Reason: $"Filter on '{clause.Field}' in joined entity '{join.ToEntity}' performs a full scan; an index would speed up predicate pushdown."));
                }
            }

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
        bool canStreamAggregate = false;
        if (query.Joins.Count == 0)
        {
            foreach (var c in query.Columns)
            {
                if (c.Aggregate != AggregateFunction.None)
                {
                    canStreamAggregate = true;
                    break;
                }
            }
        }

        // 5. Post-join filter step (filters referencing cross-entity computed fields)
        bool hasPostJoinFilters = false;
        foreach (var f in query.Filters)
        {
            if (string.IsNullOrEmpty(f.Entity) ||
                string.Equals(f.Entity, query.RootEntity, StringComparison.OrdinalIgnoreCase))
                continue;

            bool referencesJoin = false;
            foreach (var j in query.Joins)
            {
                if (string.Equals(j.ToEntity, f.Entity, StringComparison.OrdinalIgnoreCase))
                {
                    referencesJoin = true;
                    break;
                }
            }
            if (!referencesJoin)
            {
                hasPostJoinFilters = true;
                break;
            }
        }

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

        // 6. Final projection + sort step — detect missing index on sort field
        if (!string.IsNullOrEmpty(query.SortField))
        {
            var sortSpan = query.SortField.AsSpan();
            int dotIdx = sortSpan.IndexOf('.');
            var sortEntity = dotIdx > 0 ? sortSpan[..dotIdx].ToString() : query.RootEntity;
            var sortField  = dotIdx > 0 ? sortSpan[(dotIdx + 1)..].ToString() : query.SortField;
            if (!IsFieldIndexed(sortEntity, sortField))
                missingIndexes.Add(new MissingIndexRecommendation(
                    EntitySlug: sortEntity,
                    FieldName: sortField,
                    Reason: $"Sort on '{sortEntity}.{sortField}' requires an in-memory sort pass; an index would allow ordered retrieval without sorting."));
        }

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
            JoinOrderOptimised: orderedJoins.Count > 1,
            MissingIndexRecommendations: missingIndexes);
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

        foreach (var f in meta.Fields)
        {
            if (string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase) && f.IsIndexed)
                return true;
        }
        return false;
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
    bool JoinOrderOptimised,
    IReadOnlyList<MissingIndexRecommendation> MissingIndexRecommendations);

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

/// <summary>Recommendation to add a missing index that would improve query performance.</summary>
public sealed record MissingIndexRecommendation(
    string EntitySlug,
    string FieldName,
    string Reason);
