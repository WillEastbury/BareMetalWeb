using System.ComponentModel;
using BareMetalWeb.Core;
using BareMetalWeb.Data;

namespace BareMetalWeb.AI;

/// <summary>
/// AI tools for designing entities via natural language.
/// Each method is annotated with <see cref="DescriptionAttribute"/> for
/// automatic registration with the Copilot SDK or Microsoft.Extensions.AI.
/// </summary>
public static class EntityDesignerTools
{
    [Description("List all registered entity types with name, slug, and field count.")]
    public static IReadOnlyList<EntitySummary> ListEntities()
    {
        return DataScaffold.Entities
            .Select(e => new EntitySummary(e.Name, e.Slug, e.Fields.Count))
            .ToArray();
    }

    [Description("List available field types (Bool, Int32, Decimal, DateTime, StringUtf8, etc.) for entity field definitions.")]
    public static string[] ListFieldTypes()
    {
        return Enum.GetNames<FieldType>();
    }

    [Description("Get the full field list for a registered entity by its slug name.")]
    public static EntitySchemaInfo? GetEntitySchema(string slug)
    {
        if (!DataScaffold.TryGetEntity(slug, out var meta)) return null;

        var fields = meta.Fields.Select(f => new FieldSchemaInfo(
            f.Name, f.Label, f.FieldType.ToString(),
            f.Required, f.ReadOnly, f.Validation?.MaxLength ?? 0
        )).ToArray();

        return new EntitySchemaInfo(meta.Name, meta.Slug, fields);
    }

    [Description("Create a new entity schema with the given name and fields. Each field needs: name, type (from ListFieldTypes), and optional label/maxLength/required flags.")]
    public static EntitySchemaInfo CreateEntitySchema(
        string entityName,
        FieldDefinitionInput[] fields)
    {
        var slug = entityName.ToLowerInvariant().Replace(' ', '-');
        var builder = new EntitySchema.Builder(entityName, slug);

        foreach (var f in fields)
        {
            if (!Enum.TryParse<FieldType>(f.Type, ignoreCase: true, out var fieldType))
                fieldType = FieldType.StringUtf8;

            builder.AddField(f.Name, fieldType, typeof(object),
                nullable: !f.Required,
                maxLength: f.MaxLength);
        }

        builder.Build(); // validates the schema

        var resultFields = fields.Select(f => new FieldSchemaInfo(
            f.Name, f.Label ?? f.Name, f.Type,
            f.Required, false, f.MaxLength
        )).ToArray();

        return new EntitySchemaInfo(entityName, slug, resultFields);
    }
}

// ── DTOs for tool input/output ──

public sealed record EntitySummary(string Name, string Slug, int FieldCount);

public sealed record EntitySchemaInfo(string Name, string Slug, FieldSchemaInfo[] Fields);

public sealed record FieldSchemaInfo(
    string Name, string Label, string Type,
    bool Required, bool ReadOnly, int MaxLength);

public sealed record FieldDefinitionInput(
    string Name, string Type,
    string? Label = null, bool Required = false, int MaxLength = 0);
