using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// A published runtime binary that bootstrap agents can download and run.
/// Tracks version, architecture, SHA256 hash, and ring targeting.
/// </summary>
[DataEntity("Runtime Releases", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1020)]
public class RuntimeRelease : BaseDataObject
{
    public override string EntityTypeName => "RuntimeRelease";
    private new const int Ord_Version = BaseFieldCount + 0;
    private const int Ord_Architecture = BaseFieldCount + 1;
    private const int Ord_Sha256 = BaseFieldCount + 2;
    private const int Ord_FileSizeBytes = BaseFieldCount + 3;
    private const int Ord_PublishedAtUtc = BaseFieldCount + 4;
    private const int Ord_TargetRing = BaseFieldCount + 5;
    private const int Ord_IsActive = BaseFieldCount + 6;
    private const int Ord_Notes = BaseFieldCount + 7;
    internal const int TotalFieldCount = BaseFieldCount + 8;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("Architecture", Ord_Architecture),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("FileSizeBytes", Ord_FileSizeBytes),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("IsActive", Ord_IsActive),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Notes", Ord_Notes),
        new FieldSlot("PublishedAtUtc", Ord_PublishedAtUtc),
        new FieldSlot("Sha256", Ord_Sha256),
        new FieldSlot("TargetRing", Ord_TargetRing),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public RuntimeRelease() : base(TotalFieldCount) { }
    public RuntimeRelease(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Semantic version string (e.g. "1.20260312.42").</summary>
    [DataField(Label = "Version", Order = 1, Required = true, List = true, View = true, Edit = true)]
    [DataIndex]
    public new string Version
    {
        get => (string?)_values[Ord_Version] ?? string.Empty;
        set => _values[Ord_Version] = value;
    }

    /// <summary>Target CPU architecture (e.g. "Arm64", "X64").</summary>
    [DataField(Label = "Architecture", Order = 2, Required = true, List = true, View = true, Edit = true)]
    [DataIndex]
    public string Architecture
    {
        get => (string?)_values[Ord_Architecture] ?? string.Empty;
        set => _values[Ord_Architecture] = value;
    }

    /// <summary>SHA256 hash of the binary (hex-encoded, lowercase).</summary>
    [DataField(Label = "SHA256", Order = 3, Required = true, View = true)]
    public string Sha256
    {
        get => (string?)_values[Ord_Sha256] ?? string.Empty;
        set => _values[Ord_Sha256] = value;
    }

    /// <summary>Size of the binary in bytes.</summary>
    [DataField(Label = "File Size", Order = 4, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.Integer)]
    public long FileSizeBytes
    {
        get => (long)(_values[Ord_FileSizeBytes] ?? 0L);
        set => _values[Ord_FileSizeBytes] = value;
    }

    /// <summary>UTC timestamp when the release was published.</summary>
    [DataField(Label = "Published", Order = 5, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime PublishedAtUtc
    {
        get => _values[Ord_PublishedAtUtc] is DateTime dt ? dt : default;
        set => _values[Ord_PublishedAtUtc] = value;
    }

    /// <summary>Target ring for this release (e.g. "canary", "early-access", "production", "all").</summary>
    [DataField(Label = "Target Ring", Order = 6, Required = true, List = true, View = true, Edit = true)]
    [DataIndex]
    public string TargetRing
    {
        get => (string?)_values[Ord_TargetRing] ?? "canary";
        set => _values[Ord_TargetRing] = value;
    }

    /// <summary>Whether this release is active and available for download.</summary>
    [DataField(Label = "Active", Order = 7, List = true, View = true, Edit = true, FieldType = FormFieldType.YesNo)]
    public bool IsActive
    {
        get => _values[Ord_IsActive] is true;
        set => _values[Ord_IsActive] = value;
    }

    /// <summary>Optional release notes or changelog.</summary>
    [DataField(Label = "Notes", Order = 8, View = true, Edit = true, FieldType = FormFieldType.TextArea)]
    public string Notes
    {
        get => (string?)_values[Ord_Notes] ?? string.Empty;
        set => _values[Ord_Notes] = value;
    }

    public override string ToString() => $"{Version} ({Architecture})";
}
