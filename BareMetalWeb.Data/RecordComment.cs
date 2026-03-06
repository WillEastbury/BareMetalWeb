using System;

namespace BareMetalWeb.Data;

/// <summary>
/// A text comment/message attached to any record in the system.
/// Provides Slack-style conversation threads on records.
/// </summary>
[DataEntity(
    "Record Comment",
    Slug = "recordcomment",
    Permissions = "Authenticated",
    ShowOnNav = false,
    IdGeneration = AutoIdStrategy.Sequential
)]
public sealed class RecordComment : BaseDataObject
{
    public RecordComment() : base() { }
    public RecordComment(string createdBy) : base(createdBy) { }

    /// <summary>Slug of the entity type this comment belongs to (e.g. "order").</summary>
    [DataField(Label = "Record Type", Required = true, Order = 1)]
    [DataIndex(IndexKind.Inverted)]
    public string RecordType { get; set; } = string.Empty;

    /// <summary>Key of the record this comment belongs to.</summary>
    [DataField(Label = "Record Key", Required = true, Order = 2)]
    [DataIndex(IndexKind.Inverted)]
    public uint RecordKey { get; set; }

    /// <summary>The comment text content.</summary>
    [DataField(Label = "Text", Required = true, Order = 3)]
    public string Text { get; set; } = string.Empty;
}
