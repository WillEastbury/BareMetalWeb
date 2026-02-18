using System;

namespace BareMetalWeb.Data;

/// <summary>
/// Configuration for a computed field, derived from the [ComputedField] attribute.
/// </summary>
public sealed record ComputedFieldConfig(
    Type? SourceEntity,
    string? SourceField,
    string? ForeignKeyField,
    string? ChildCollectionProperty,
    ComputedStrategy Strategy,
    ComputedTrigger Trigger,
    AggregateFunction Aggregate,
    TimeSpan CacheDuration
);
