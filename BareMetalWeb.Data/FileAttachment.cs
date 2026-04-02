using System;

namespace BareMetalWeb.Data;

/// <summary>
/// Represents a file attached to any record in the system.
/// Multiple versions of the same attachment are linked via AttachmentGroupId.
/// </summary>
[DataEntity(
    "File Attachment",
    Slug = "fileattachment",
    Permissions = "Authenticated",
    ShowOnNav = false,
    IdGeneration = AutoIdStrategy.Sequential
)]
public sealed class FileAttachment : DataRecord
{
    public override string EntityTypeName => "FileAttachment";
    private const int Ord_RecordType = BaseFieldCount + 0;
    private const int Ord_RecordKey = BaseFieldCount + 1;
    private const int Ord_FileName = BaseFieldCount + 2;
    private const int Ord_ContentType = BaseFieldCount + 3;
    private const int Ord_SizeBytes = BaseFieldCount + 4;
    private const int Ord_StorageKey = BaseFieldCount + 5;
    private const int Ord_Description = BaseFieldCount + 6;
    private const int Ord_AttachmentGroupId = BaseFieldCount + 7;
    private const int Ord_VersionNumber = BaseFieldCount + 8;
    private const int Ord_IsCurrentVersion = BaseFieldCount + 9;
    internal new const int TotalFieldCount = BaseFieldCount + 10;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("AttachmentGroupId", Ord_AttachmentGroupId),
        new FieldSlot("ContentType", Ord_ContentType),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("Description", Ord_Description),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("FileName", Ord_FileName),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("IsCurrentVersion", Ord_IsCurrentVersion),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("RecordKey", Ord_RecordKey),
        new FieldSlot("RecordType", Ord_RecordType),
        new FieldSlot("SizeBytes", Ord_SizeBytes),
        new FieldSlot("StorageKey", Ord_StorageKey),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
        new FieldSlot("VersionNumber", Ord_VersionNumber),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public FileAttachment() : base(TotalFieldCount) { }
    public FileAttachment(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Slug of the entity type this file is attached to (e.g. "order", "customer").</summary>
    [DataField(Label = "Record Type", Required = true, Order = 1, List = true)]
    [DataIndex(IndexKind.Inverted)]
    public string RecordType
    {
        get => (string?)_values[Ord_RecordType] ?? string.Empty;
        set => _values[Ord_RecordType] = value;
    }

    /// <summary>Key of the record this file is attached to.</summary>
    [DataField(Label = "Record Key", Required = true, Order = 2, List = true)]
    [DataIndex(IndexKind.Inverted)]
    public uint RecordKey
    {
        get => (uint)(_values[Ord_RecordKey] ?? 0u);
        set => _values[Ord_RecordKey] = value;
    }

    /// <summary>Original file name as uploaded by the user.</summary>
    [DataField(Label = "File Name", Required = true, Order = 3, List = true)]
    public string FileName
    {
        get => (string?)_values[Ord_FileName] ?? string.Empty;
        set => _values[Ord_FileName] = value;
    }

    /// <summary>MIME content type of the file.</summary>
    [DataField(Label = "Content Type", Order = 4)]
    public string ContentType
    {
        get => (string?)_values[Ord_ContentType] ?? "application/octet-stream";
        set => _values[Ord_ContentType] = value;
    }

    /// <summary>File size in bytes.</summary>
    [DataField(Label = "Size (bytes)", Order = 5, List = true)]
    public long SizeBytes
    {
        get => (long)(_values[Ord_SizeBytes] ?? 0L);
        set => _values[Ord_SizeBytes] = value;
    }

    /// <summary>Relative storage path under the uploads root directory.</summary>
    [DataField(Label = "Storage Key", Order = 6, List = false, View = false, Edit = false, Create = false)]
    public string StorageKey
    {
        get => (string?)_values[Ord_StorageKey] ?? string.Empty;
        set => _values[Ord_StorageKey] = value;
    }

    /// <summary>Optional description or notes about this attachment.</summary>
    [DataField(Label = "Description", Order = 7, List = false)]
    public string? Description
    {
        get => (string?)_values[Ord_Description];
        set => _values[Ord_Description] = value;
    }

    /// <summary>
    /// Groups all versions of the same logical attachment together.
    /// Zero means this is the only version (no version chain).
    /// Set to the Key of the first (root) attachment in the version chain.
    /// </summary>
    [DataField(Label = "Version Group", Order = 8, List = false, View = false, Edit = false, Create = false)]
    [DataIndex(IndexKind.Inverted)]
    public uint AttachmentGroupId
    {
        get => (uint)(_values[Ord_AttachmentGroupId] ?? 0u);
        set => _values[Ord_AttachmentGroupId] = value;
    }

    /// <summary>Version number within the version group (1-based).</summary>
    [DataField(Label = "Version", Order = 9, List = true)]
    public int VersionNumber
    {
        get => (int)(_values[Ord_VersionNumber] ?? 1);
        set => _values[Ord_VersionNumber] = value;
    }

    /// <summary>Whether this is the current (latest) version of the attachment.</summary>
    [DataField(Label = "Current Version", Order = 10, List = true)]
    [DataIndex(IndexKind.Inverted)]
    public bool IsCurrentVersion
    {
        get => _values[Ord_IsCurrentVersion] is true;
        set => _values[Ord_IsCurrentVersion] = value;
    }
}
