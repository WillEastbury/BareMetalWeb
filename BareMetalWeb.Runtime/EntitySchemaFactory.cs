using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Bridges <see cref="RuntimeEntityModel"/> to <see cref="EntitySchema"/>.
/// Lives in the Runtime project because it depends on both Data and Runtime types.
/// </summary>
public static class EntitySchemaFactory
{
    /// <summary>
    /// Builds an <see cref="EntitySchema"/> from a compiled <see cref="RuntimeEntityModel"/>.
    /// Field ordinals, names, types and flags are preserved exactly.
    /// </summary>
    public static EntitySchema FromModel(RuntimeEntityModel model)
    {
        // RuntimeEntityModel fields are already sorted by ordinal.
        // Ordinals are 1-based from RuntimeEntityCompiler, but we use 0-based
        // array indexing in EntitySchema — map ordinal i to array index i.
        var fields = model.Fields;
        var builder = new EntitySchema.Builder(model.Name, model.Slug);

        foreach (var f in fields)
        {
            var clrType = RuntimeEntityCompiler.MapClrType(f.FieldType, f.IsNullable, f.EnumValues);
            var fieldType = MapFieldType(f.FieldType, clrType);
            var flags = FieldFlags.None;

            if (f.IsNullable) flags |= FieldFlags.Nullable;
            if (f.Required) flags |= FieldFlags.Required;
            if (f.ReadOnly) flags |= FieldFlags.ReadOnly;
            if (f.FieldType == FormFieldType.LookupList) flags |= FieldFlags.Lookup;

            builder.AddField(
                name: f.Name,
                type: fieldType,
                clrType: clrType,
                nullable: f.IsNullable,
                required: f.Required,
                indexed: false, // indexes handled separately via IndexDefinition
                maxLength: f.MaxLength ?? 0,
                extraFlags: flags);
        }

        return builder.Build();
    }

    /// <summary>
    /// Maps a <see cref="FormFieldType"/> + CLR type to the compact <see cref="FieldType"/>
    /// used in the data layer for binary layout and codec selection.
    /// </summary>
    internal static FieldType MapFieldType(FormFieldType formType, Type clrType)
    {
        var effective = Nullable.GetUnderlyingType(clrType) ?? clrType;

        if (effective == typeof(bool)) return FieldType.Bool;
        if (effective == typeof(int)) return FieldType.Int32;
        if (effective == typeof(uint)) return FieldType.UInt32;
        if (effective == typeof(long)) return FieldType.Int64;
        if (effective == typeof(decimal)) return FieldType.Decimal;
        if (effective == typeof(DateTime)) return FieldType.DateTime;
        if (effective == typeof(DateOnly)) return FieldType.DateOnly;
        if (effective == typeof(TimeOnly)) return FieldType.TimeOnly;
        if (effective == typeof(double)) return FieldType.Float64;
        if (effective == typeof(float)) return FieldType.Float32;
        if (effective == typeof(Guid)) return FieldType.Guid;
        if (effective == typeof(byte)) return FieldType.Byte;
        if (effective == typeof(short)) return FieldType.Int16;
        if (effective.IsEnum) return FieldType.EnumInt32;

        return formType switch
        {
            FormFieldType.String or FormFieldType.TextArea or FormFieldType.Email
                or FormFieldType.Password or FormFieldType.Country or FormFieldType.Tags
                or FormFieldType.Link or FormFieldType.Hidden or FormFieldType.CustomHtml
                or FormFieldType.ReadOnly => FieldType.StringUtf8,
            FormFieldType.Image or FormFieldType.File => FieldType.Bytes,
            _ => FieldType.StringUtf8,
        };
    }
}
