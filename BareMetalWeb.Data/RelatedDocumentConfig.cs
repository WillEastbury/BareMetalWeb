using BareMetalWeb.Data;

namespace BareMetalWeb.Core;

/// <summary>
/// Describes a document-chain relationship for a field decorated with
/// <see cref="RelatedDocumentAttribute"/>.
/// </summary>
public sealed record RelatedDocumentConfig(
    /// <summary>The entity type that this document relates to (the upstream document).</summary>
    Type TargetType,
    /// <summary>The field on the target entity shown as the display label.</summary>
    string DisplayField,
    /// <summary>Entity slug for slug-based resolution (metadata-driven entities).</summary>
    string? TargetSlug = null
);
