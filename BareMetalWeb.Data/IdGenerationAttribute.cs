using System;

namespace BareMetalWeb.Data;

/// <summary>
/// Specifies that a property should be auto-generated with the specified strategy.
/// </summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class IdGenerationAttribute : Attribute
{
    public IdGenerationStrategy Strategy { get; set; }

    public IdGenerationAttribute(IdGenerationStrategy strategy)
    {
        Strategy = strategy;
    }
}

/// <summary>
/// Defines the strategy for auto-generating ID values.
/// </summary>
public enum IdGenerationStrategy
{
    /// <summary>
    /// No auto-generation (default behavior).
    /// </summary>
    None = 0,

    /// <summary>
    /// Auto-generate using a sequential uint32 per entity type.
    /// </summary>
    Sequential = 1
}
