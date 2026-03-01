namespace BareMetalWeb.Data;

/// <summary>
/// Marks a foreign-key field as a document-chain relationship.
/// Used to express sequential document workflows such as
/// Quote → Order → Dispatch → Invoice → LedgerPost.
/// The decorated field holds the ID of the preceding document in the chain;
/// BareMetalWeb uses these relationships to build Sankey diagrams and to walk
/// the document chain in the tree view.
/// </summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class RelatedDocumentAttribute : Attribute
{
    /// <summary>The entity type that this document was created from / relates to.</summary>
    public Type TargetType { get; }

    /// <summary>
    /// The field on the target entity whose value is shown as the display label.
    /// Defaults to "Name".
    /// </summary>
    public string DisplayField { get; set; } = "Name";

    public RelatedDocumentAttribute(Type targetType)
    {
        TargetType = targetType;
    }
}
