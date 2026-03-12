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
    /// <summary>Semantic version string (e.g. "1.20260312.42").</summary>
    [DataField(Label = "Version", Order = 1, Required = true, List = true, View = true, Edit = true)]
    [DataIndex]
    public string Version { get; set; } = string.Empty;

    /// <summary>Target CPU architecture (e.g. "Arm64", "X64").</summary>
    [DataField(Label = "Architecture", Order = 2, Required = true, List = true, View = true, Edit = true)]
    [DataIndex]
    public string Architecture { get; set; } = string.Empty;

    /// <summary>SHA256 hash of the binary (hex-encoded, lowercase).</summary>
    [DataField(Label = "SHA256", Order = 3, Required = true, View = true)]
    public string Sha256 { get; set; } = string.Empty;

    /// <summary>Size of the binary in bytes.</summary>
    [DataField(Label = "File Size", Order = 4, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.Integer)]
    public long FileSizeBytes { get; set; }

    /// <summary>UTC timestamp when the release was published.</summary>
    [DataField(Label = "Published", Order = 5, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime PublishedAtUtc { get; set; }

    /// <summary>Target ring for this release (e.g. "canary", "early-access", "production", "all").</summary>
    [DataField(Label = "Target Ring", Order = 6, Required = true, List = true, View = true, Edit = true)]
    [DataIndex]
    public string TargetRing { get; set; } = "canary";

    /// <summary>Whether this release is active and available for download.</summary>
    [DataField(Label = "Active", Order = 7, List = true, View = true, Edit = true, FieldType = FormFieldType.YesNo)]
    public bool IsActive { get; set; } = true;

    /// <summary>Optional release notes or changelog.</summary>
    [DataField(Label = "Notes", Order = 8, View = true, Edit = true, FieldType = FormFieldType.TextArea)]
    public string Notes { get; set; } = string.Empty;

    public override string ToString() => $"{Version} ({Architecture})";
}
