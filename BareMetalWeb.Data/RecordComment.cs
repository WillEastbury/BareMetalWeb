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
    private const int Ord_RecordType = BaseFieldCount + 0;
    private const int Ord_RecordKey = BaseFieldCount + 1;
    private const int Ord_Text = BaseFieldCount + 2;
    internal new const int TotalFieldCount = BaseFieldCount + 3;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("RecordKey", Ord_RecordKey),
        new FieldSlot("RecordType", Ord_RecordType),
        new FieldSlot("Text", Ord_Text),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public RecordComment() : base(TotalFieldCount) { }
    public RecordComment(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Slug of the entity type this comment belongs to (e.g. "order").</summary>
    [DataField(Label = "Record Type", Required = true, Order = 1)]
    [DataIndex(IndexKind.Inverted)]
    public string RecordType
    {
        get => (string?)_values[Ord_RecordType] ?? string.Empty;
        set => _values[Ord_RecordType] = value;
    }

    /// <summary>Key of the record this comment belongs to.</summary>
    [DataField(Label = "Record Key", Required = true, Order = 2)]
    [DataIndex(IndexKind.Inverted)]
    public uint RecordKey
    {
        get => (uint)(_values[Ord_RecordKey] ?? 0u);
        set => _values[Ord_RecordKey] = value;
    }

    /// <summary>The comment text content.</summary>
    [DataField(Label = "Text", Required = true, Order = 3)]
    public string Text
    {
        get => (string?)_values[Ord_Text] ?? string.Empty;
        set => _values[Ord_Text] = value;
    }
}
