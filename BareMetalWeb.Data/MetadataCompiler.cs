using System;
using System.Collections.Generic;
using BareMetalWeb.Core;
using BareMetalWeb.Rendering.Models;
using static BareMetalWeb.Data.MetadataWireSerializer;

namespace BareMetalWeb.Data;

/// <summary>
/// Compiles DataEntityMetadata/DataFieldMetadata into dense, ordinal-indexed
/// runtime tables optimised for cache-friendly array reads on hot paths.
/// Runs at startup after WAL replay and on metadata/gallery changes.
/// </summary>
public static class MetadataCompiler
{
    /// <summary>
    /// Compiles a set of entity metadata into an immutable <see cref="RuntimeSnapshot"/>.
    /// Assigns contiguous EntityIds (sorted by slug) and contiguous FieldIds.
    /// </summary>
    public static RuntimeSnapshot Compile(IReadOnlyList<DataEntityMetadata> entities)
    {
        int entityCount = entities.Count;

        // Sort entities by slug for deterministic ID assignment
        var sorted = new DataEntityMetadata[entityCount];
        for (int i = 0; i < entityCount; i++) sorted[i] = entities[i];
        Array.Sort(sorted, (a, b) => string.Compare(a.Slug, b.Slug, StringComparison.OrdinalIgnoreCase));

        // --- Pass 1: count total fields ---
        int totalFields = 0;
        for (int i = 0; i < entityCount; i++)
            totalFields += sorted[i].Fields.Count;

        // --- Allocate entity arrays ---
        var eNames        = new string[entityCount];
        var eSlugs        = new string[entityCount];
        var eFieldStart   = new int[entityCount];
        var eFieldCount   = new int[entityCount];
        var eShowOnNav    = new bool[entityCount];
        var eNavOrder     = new int[entityCount];
        var eIdStrategies = new AutoIdStrategy[entityCount];
        var eHandlers     = new DataEntityHandlers[entityCount];

        // --- Allocate field arrays ---
        var fNames       = new string[totalFields];
        var fWireTypes   = new WireFieldType[totalFields];
        var fFormTypes   = new FormFieldType[totalFields];
        var fFlags       = new FieldFlags[totalFields];
        var fOrders      = new int[totalFields];
        var fEntityIds   = new int[totalFields];
        var fColumnSpans = new int[totalFields];

        // --- Slug lookup arrays (sorted for binary search) ---
        var sortedSlugs     = new string[entityCount];
        var sortedEntityIds = new int[entityCount];

        // --- Pass 2: populate ---
        int fieldOffset = 0;
        for (int entityId = 0; entityId < entityCount; entityId++)
        {
            var meta = sorted[entityId];

            eNames[entityId]        = meta.Name;
            eSlugs[entityId]        = meta.Slug;
            eFieldStart[entityId]   = fieldOffset;
            eFieldCount[entityId]   = meta.Fields.Count;
            eShowOnNav[entityId]    = meta.ShowOnNav;
            eNavOrder[entityId]     = meta.NavOrder;
            eIdStrategies[entityId] = meta.IdGeneration;
            eHandlers[entityId]     = meta.Handlers;

            sortedSlugs[entityId]     = meta.Slug;
            sortedEntityIds[entityId] = entityId;

            var fields = meta.Fields;
            for (int fi = 0; fi < fields.Count; fi++)
            {
                int globalFieldId = fieldOffset + fi;
                var field = fields[fi];

                fNames[globalFieldId]       = field.Name;
                fWireTypes[globalFieldId]   = ResolveFormFieldToWireType(field.FieldType);
                fFormTypes[globalFieldId]   = field.FieldType;
                fFlags[globalFieldId]       = PackFlags(field);
                fOrders[globalFieldId]      = field.Order;
                fEntityIds[globalFieldId]   = entityId;
                fColumnSpans[globalFieldId] = field.ColumnSpan;
            }

            fieldOffset += fields.Count;
        }

        var entityTable = new EntityTable(
            eNames, eSlugs, eFieldStart, eFieldCount,
            eShowOnNav, eNavOrder, eIdStrategies, eHandlers,
            sortedSlugs, sortedEntityIds);

        var fieldTable = new FieldTable(
            fNames, fWireTypes, fFormTypes, fFlags,
            fOrders, fEntityIds, fColumnSpans);

        var routeTable = new RouteTable(entityCount);

        return new RuntimeSnapshot(entityTable, fieldTable, routeTable);
    }

    /// <summary>
    /// Compiles and atomically swaps the current <see cref="RuntimeSnapshot"/>.
    /// </summary>
    public static RuntimeSnapshot CompileAndSwap(IReadOnlyList<DataEntityMetadata> entities)
    {
        var snapshot = Compile(entities);
        RuntimeSnapshot.Swap(snapshot);
        return snapshot;
    }

    private static FieldFlags PackFlags(DataFieldMetadata field)
    {
        var flags = FieldFlags.None;
        if (field.Required)                         flags |= FieldFlags.Required;
        if (field.ReadOnly)                         flags |= FieldFlags.ReadOnly;
        if (field.Lookup != null)                   flags |= FieldFlags.Lookup;
        if (field.Computed != null)                  flags |= FieldFlags.Computed;
        return flags;
    }

    private static WireFieldType ResolveFormFieldToWireType(FormFieldType formType) => formType switch
    {
        FormFieldType.YesNo        => WireFieldType.Bool,
        FormFieldType.Integer      => WireFieldType.Int32,
        FormFieldType.Decimal      => WireFieldType.Decimal,
        FormFieldType.Money        => WireFieldType.Decimal,
        FormFieldType.DateTime     => WireFieldType.DateTime,
        FormFieldType.DateOnly     => WireFieldType.DateOnly,
        FormFieldType.TimeOnly     => WireFieldType.TimeOnly,
        FormFieldType.Enum         => WireFieldType.Enum,
        FormFieldType.LookupList   => WireFieldType.String,
        FormFieldType.GeoCoordinate => WireFieldType.Float64,
        _                          => WireFieldType.String,
    };
}
