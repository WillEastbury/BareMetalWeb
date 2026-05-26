using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Metadata contract for a many-to-many relationship backed by a hidden mapping entity.
/// </summary>
public sealed record ManyToManyRelationConfig(
    string RelationName,
    DataEntityMetadata Source,
    DataEntityMetadata Target,
    string MappingSlug,
    string SourceField,
    string TargetField,
    string SourceDisplayField = "Name",
    string TargetDisplayField = "Name"
);

