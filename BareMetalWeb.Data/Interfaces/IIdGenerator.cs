using System;

namespace BareMetalWeb.Data.Interfaces;

/// <summary>
/// Provides ID generation for entity instances.
/// </summary>
public interface IIdGenerator
{
    /// <summary>
    /// Generates a new ID value for the specified entity type and strategy.
    /// </summary>
    /// <param name="entityType">The type of entity requiring an ID.</param>
    /// <param name="strategy">The ID generation strategy to use.</param>
    /// <returns>A newly generated ID value as a string.</returns>
    string GenerateId(Type entityType, IdGenerationStrategy strategy);
}
