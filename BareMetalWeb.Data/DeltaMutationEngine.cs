using System.Buffers;
using System.Buffers.Binary;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Server-side delta mutation engine. Applies field-level deltas to entities
/// with optimistic concurrency, using EntityLayout for ordinal-based field access.
/// No reflection at apply time — all type resolution is precompiled in EntityLayout.
/// </summary>
public static class DeltaMutationEngine
{
    /// <summary>
    /// Apply a mutation delta to an existing entity.
    /// 1. Load entity by RowId
    /// 2. Verify ExpectedVersion (optimistic concurrency)
    /// 3. Verify SchemaHash
    /// 4. Apply field changes via compiled setters + codec deserialization
    /// 5. Touch (increment version)
    /// 6. Save
    /// 7. Return updated entity
    /// </summary>
    public static async ValueTask<(BaseDataObject? Entity, MutationResult Result)> ApplyDeltaAsync(
        DataEntityMetadata meta,
        EntityLayout layout,
        MutationDelta delta,
        string userName,
        CancellationToken cancellationToken = default)
    {
        // Schema hash check
        if (delta.SchemaHash != 0 && delta.SchemaHash != layout.SchemaHash)
            return (null, MutationResult.SchemaHashMismatch);

        // Load existing entity
        var loaded = await DataScaffold.LoadAsync(meta, delta.RowId, cancellationToken);
        if (loaded is null)
            return (null, MutationResult.EntityNotFound);
        if (loaded is not BaseDataObject entity)
            return (null, MutationResult.TypeMismatch);

        // Optimistic concurrency check
        if (delta.ExpectedVersion != 0 && entity.Version != delta.ExpectedVersion)
            return (entity, MutationResult.VersionConflict);

        // Apply field changes
        foreach (ref readonly var change in delta.Changes.AsSpan())
        {
            if (change.Ordinal >= layout.Fields.Length)
                return (entity, MutationResult.InvalidOrdinal);

            var field = layout.Fields[change.Ordinal];

            // Skip read-only fields
            if (field.Is(FieldFlags.ReadOnly))
                continue;

            // Null handling
            if (change.IsNull)
            {
                if (!field.Is(FieldFlags.Nullable))
                    return (entity, MutationResult.ValidationFailed);
                field.Setter(entity, null);
                continue;
            }

            // Decode value using codec and set via compiled setter
            var codec = CodecTable.Get(field.CodecId);
            object? value;
            if (field.FixedSizeBytes > 0)
                value = codec.ReadFixed(change.Value.Span);
            else
                value = codec.ReadVar(change.Value.Span);

            // For enums, convert int32 back to the actual enum type
            if (field.Type == FieldType.EnumInt32 && value is int intVal)
                value = Enum.ToObject(field.ClrType, intVal);

            field.Setter(entity, value);
        }

        // Touch updates Version, UpdatedOnUtc, ETag, UpdatedBy
        entity.Touch(userName);

        // Persist
        await DataScaffold.SaveAsync(meta, entity, cancellationToken);

        return (entity, MutationResult.Success);
    }

    /// <summary>
    /// Encode a single field value using its codec. Used by clients to build FieldDelta values.
    /// </summary>
    public static ReadOnlyMemory<byte> EncodeFieldValue(FieldRuntime field, object? value)
    {
        if (value is null) return ReadOnlyMemory<byte>.Empty;

        var codec = CodecTable.Get(field.CodecId);
        if (field.FixedSizeBytes > 0)
        {
            var buf = new byte[field.FixedSizeBytes];
            codec.WriteFixed(value, buf);
            return buf;
        }
        else
        {
            var writer = new ArrayBufferWriter<byte>(64);
            codec.WriteVar(value, writer);
            return writer.WrittenMemory;
        }
    }

    /// <summary>
    /// Build a MutationDelta by comparing two entity instances (old vs new).
    /// Uses EntityLayout for ordinal-based field comparison.
    /// </summary>
    public static MutationDelta BuildDeltaFromEntities(
        EntityLayout layout,
        BaseDataObject oldEntity,
        BaseDataObject newEntity)
    {
        var changes = new List<FieldDelta>();

        foreach (var field in layout.Fields)
        {
            // Skip system fields that are managed by Touch()
            if (field.Name is "Version" or "UpdatedOnUtc" or "UpdatedBy" or "ETag")
                continue;

            var oldVal = field.Getter(oldEntity);
            var newVal = field.Getter(newEntity);

            if (!Equals(oldVal, newVal))
            {
                var encoded = EncodeFieldValue(field, newVal);
                changes.Add(new FieldDelta((ushort)field.Ordinal, encoded));
            }
        }

        return new MutationDelta
        {
            RowId = oldEntity.Key,
            ExpectedVersion = oldEntity.Version,
            SchemaHash = layout.SchemaHash,
            Changes = changes.ToArray(),
        };
    }
}
