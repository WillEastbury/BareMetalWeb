using System;

namespace BareMetalWeb.Data.Interfaces;

/// <summary>
/// Provides ID generation for entity instances.
/// </summary>
public interface IIdGenerator
{
    /// <summary>
    /// Generates a new sequential uint key for the specified entity type.
    /// </summary>
    uint GenerateKey(Type entityType);
}
