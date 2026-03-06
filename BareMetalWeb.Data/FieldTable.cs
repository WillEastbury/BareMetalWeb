using System;
using BareMetalWeb.Rendering.Models;
using static BareMetalWeb.Data.MetadataWireSerializer;

namespace BareMetalWeb.Data;

/// <summary>
/// Dense struct-of-arrays table for field metadata, indexed by contiguous FieldId (0..Count-1).
/// Fields are grouped by entity: entity E's fields span FieldTable[EntityTable.FieldStart[E] .. +FieldCount[E]).
/// Immutable after construction — safe for concurrent reads without locking.
/// </summary>
public sealed class FieldTable
{
    public readonly int Count;
    public readonly string[] Names;
    public readonly WireFieldType[] WireTypes;
    public readonly FormFieldType[] FormTypes;
    public readonly FieldFlags[] Flags;
    public readonly int[] Orders;        // display order
    public readonly int[] EntityIds;     // owning EntityId
    public readonly int[] ColumnSpans;   // Bootstrap grid width (1-12)

    public FieldTable(
        string[] names,
        WireFieldType[] wireTypes,
        FormFieldType[] formTypes,
        FieldFlags[] flags,
        int[] orders,
        int[] entityIds,
        int[] columnSpans)
    {
        Count = names.Length;
        Names = names;
        WireTypes = wireTypes;
        FormTypes = formTypes;
        Flags = flags;
        Orders = orders;
        EntityIds = entityIds;
        ColumnSpans = columnSpans;
    }
}
