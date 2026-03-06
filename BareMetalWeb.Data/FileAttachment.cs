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
public sealed class FileAttachment : BaseDataObject
{
    public FileAttachment() : base() { }

    public FileAttachment(string createdBy) : base(createdBy) { }

    /// <summary>Slug of the entity type this file is attached to (e.g. "order", "customer").</summary>
    [DataField(Label = "Record Type", Required = true, Order = 1, List = true)]
    [DataIndex(IndexKind.Inverted)]
    public string RecordType { get; set; } = string.Empty;

    /// <summary>Key of the record this file is attached to.</summary>
    [DataField(Label = "Record Key", Required = true, Order = 2, List = true)]
    [DataIndex(IndexKind.Inverted)]
    public uint RecordKey { get; set; }

    /// <summary>Original file name as uploaded by the user.</summary>
    [DataField(Label = "File Name", Required = true, Order = 3, List = true)]
    public string FileName { get; set; } = string.Empty;

    /// <summary>MIME content type of the file.</summary>
    [DataField(Label = "Content Type", Order = 4)]
    public string ContentType { get; set; } = "application/octet-stream";

    /// <summary>File size in bytes.</summary>
    [DataField(Label = "Size (bytes)", Order = 5, List = true)]
    public long SizeBytes { get; set; }

    /// <summary>Relative storage path under the uploads root directory.</summary>
    [DataField(Label = "Storage Key", Order = 6, List = false, View = false, Edit = false, Create = false)]
    public string StorageKey { get; set; } = string.Empty;

    /// <summary>Optional description or notes about this attachment.</summary>
    [DataField(Label = "Description", Order = 7, List = false)]
    public string? Description { get; set; }

    /// <summary>
    /// Groups all versions of the same logical attachment together.
    /// Zero means this is the only version (no version chain).
    /// Set to the Key of the first (root) attachment in the version chain.
    /// </summary>
    [DataField(Label = "Version Group", Order = 8, List = false, View = false, Edit = false, Create = false)]
    [DataIndex(IndexKind.Inverted)]
    public uint AttachmentGroupId { get; set; }

    /// <summary>Version number within the version group (1-based).</summary>
    [DataField(Label = "Version", Order = 9, List = true)]
    public int VersionNumber { get; set; } = 1;

    /// <summary>Whether this is the current (latest) version of the attachment.</summary>
    [DataField(Label = "Current Version", Order = 10, List = true)]
    [DataIndex(IndexKind.Inverted)]
    public bool IsCurrentVersion { get; set; } = true;
}
