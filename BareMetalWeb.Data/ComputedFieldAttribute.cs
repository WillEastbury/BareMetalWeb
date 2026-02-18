using System;

namespace BareMetalWeb.Data;

/// <summary>
/// Specifies that a property is computed from related entities or aggregations.
/// </summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class ComputedFieldAttribute : Attribute
{
    /// <summary>
    /// The entity type to query for the source value (e.g., typeof(Product)).
    /// Required for single-entity lookups. Not required for aggregations on child collections.
    /// </summary>
    public Type? SourceEntity { get; set; }

    /// <summary>
    /// The field name on the source entity to read (e.g., "Price").
    /// Required for single-entity lookups and aggregations.
    /// </summary>
    public string? SourceField { get; set; }

    /// <summary>
    /// The field on the current entity that holds the foreign key to the source entity (e.g., "ProductId").
    /// Required for single-entity lookups.
    /// </summary>
    public string? ForeignKeyField { get; set; }

    /// <summary>
    /// The navigation property that holds the child collection for aggregation (e.g., "OrderLines").
    /// Required for aggregations on child collections.
    /// </summary>
    public string? ChildCollectionProperty { get; set; }

    /// <summary>
    /// The computation strategy (Snapshot, CachedLive, AlwaysLive).
    /// </summary>
    public ComputedStrategy Strategy { get; set; } = ComputedStrategy.Snapshot;

    /// <summary>
    /// When to compute the value for Snapshot strategy (OnCreate, OnUpdate, or both).
    /// </summary>
    public ComputedTrigger Trigger { get; set; } = ComputedTrigger.OnCreate;

    /// <summary>
    /// Aggregate function to apply (None, Sum, Count, Min, Max, Average).
    /// </summary>
    public AggregateFunction Aggregate { get; set; } = AggregateFunction.None;

    /// <summary>
    /// Cache duration in seconds for CachedLive strategy. Default is 60 seconds.
    /// </summary>
    public int CacheSeconds { get; set; } = 60;
}

/// <summary>
/// Defines the strategy for computing field values.
/// </summary>
public enum ComputedStrategy
{
    /// <summary>
    /// Copy the value from the related entity at a specific point in time (create/update).
    /// The value is stored locally and does not change if the source changes.
    /// Good for: order line prices, invoice totals, audit trail values.
    /// </summary>
    Snapshot = 0,

    /// <summary>
    /// Compute the value on access and cache it for a configurable duration.
    /// The cache is refreshed when expired. Balances performance with freshness.
    /// Good for: frequently accessed derived values that don't need real-time accuracy.
    /// </summary>
    CachedLive = 1,

    /// <summary>
    /// Always compute the value on access by querying the related entity.
    /// The value always reflects the current state with no caching.
    /// Good for: current stock levels, dynamic pricing, real-time status.
    /// </summary>
    AlwaysLive = 2
}

/// <summary>
/// Defines when to compute snapshot values.
/// </summary>
public enum ComputedTrigger
{
    /// <summary>
    /// Compute the value only when the entity is created.
    /// </summary>
    OnCreate = 1,

    /// <summary>
    /// Compute the value only when the entity is updated.
    /// </summary>
    OnUpdate = 2,

    /// <summary>
    /// Compute the value both on create and update.
    /// </summary>
    OnCreateAndUpdate = 3,

    /// <summary>
    /// Used internally for live strategies - compute on each access.
    /// </summary>
    OnAccess = 4
}

/// <summary>
/// Defines aggregate functions for computed fields.
/// </summary>
public enum AggregateFunction
{
    /// <summary>
    /// No aggregation - direct field value lookup.
    /// </summary>
    None = 0,

    /// <summary>
    /// Sum of numeric values.
    /// </summary>
    Sum = 1,

    /// <summary>
    /// Count of items.
    /// </summary>
    Count = 2,

    /// <summary>
    /// Minimum value.
    /// </summary>
    Min = 3,

    /// <summary>
    /// Maximum value.
    /// </summary>
    Max = 4,

    /// <summary>
    /// Average of numeric values.
    /// </summary>
    Average = 5
}
