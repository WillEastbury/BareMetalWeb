using System;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>A name→ordinal slot in an entity's field lookup table. Sorted by Name for linear scan.</summary>
public readonly struct FieldSlot
{
    public readonly string Name;
    public readonly int Ordinal;
    public FieldSlot(string name, int ordinal) { Name = name; Ordinal = ordinal; }
}
