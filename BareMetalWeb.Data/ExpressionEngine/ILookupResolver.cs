using System.Threading;
using System.Threading.Tasks;

namespace BareMetalWeb.Data.ExpressionEngine;

/// <summary>
/// Resolves field values from related entities during expression evaluation.
/// Enables relationship traversal (e.g., Customer.DiscountLevel) and
/// multi-entity query lookups in calculated field expressions.
/// </summary>
public interface ILookupResolver
{
    /// <summary>
    /// Resolves a field value from a related entity by following a lookup (foreign key) field.
    /// For example, given an Order with CustomerId="c1", resolving ("CustomerId", "DiscountLevel")
    /// loads Customer "c1" and returns its DiscountLevel.
    /// </summary>
    /// <param name="currentEntitySlug">Slug of the entity being evaluated.</param>
    /// <param name="foreignKeyField">The FK field name on the current entity (e.g. "CustomerId").</param>
    /// <param name="targetField">The field to read from the related entity (e.g. "DiscountLevel").</param>
    /// <param name="context">Current field values of the entity being evaluated.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    ValueTask<object?> ResolveRelatedFieldAsync(
        string currentEntitySlug,
        string foreignKeyField,
        string targetField,
        IReadOnlyDictionary<string, object?> context,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Queries an entity with filter conditions and returns a field value from the first match.
    /// For example: QueryLookup("pricingdata", "CustomerID", "c1", "DiscountPercentage")
    /// queries PricingData where CustomerID == "c1" and returns DiscountPercentage.
    /// </summary>
    /// <param name="entitySlug">Slug of the entity to query.</param>
    /// <param name="filters">Field/value pairs used as equality filters.</param>
    /// <param name="returnField">The field to return from the first matching record.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    ValueTask<object?> QueryLookupAsync(
        string entitySlug,
        IReadOnlyList<(string Field, object? Value)> filters,
        string returnField,
        CancellationToken cancellationToken = default);
}
