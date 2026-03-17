using System;

namespace BareMetalWeb.Data;

/// <summary>
/// Lightweight descriptor for virtual/gallery-defined entity fields.
/// Replaces <c>DynamicPropertyInfo : PropertyInfo</c> to eliminate
/// System.Reflection from the metadata layer entirely.
/// </summary>
internal readonly struct DynamicFieldDescriptor
{
    public readonly string Name;
    public readonly Type FieldType;
    public readonly int Ordinal;

    public DynamicFieldDescriptor(string name, Type fieldType, int ordinal)
    {
        Name = name;
        FieldType = fieldType;
        Ordinal = ordinal;
    }
}
