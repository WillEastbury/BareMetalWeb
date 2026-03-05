using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// A collaborative design session ("Camel Mode"). Multiple users can share
/// a link and contribute entity/field ideas to a shared module design.
/// Each contribution is recorded with the contributor's name and timestamp.
/// </summary>
[DataEntity("Design Sessions", ShowOnNav = true, NavGroup = "Admin", NavOrder = 1008)]
public class DesignSession : RenderableDataObject
{
    [DataField(Label = "Session Name", Order = 1, Required = true)]
    public string SessionName { get; set; } = string.Empty;

    /// <summary>Unique share code for the collaboration link.</summary>
    [DataField(Label = "Share Code", Order = 2, ReadOnly = true)]
    public string ShareCode { get; set; } = Guid.NewGuid().ToString("N")[..8];

    /// <summary>Current entity design as JSON (updated by each contributor).</summary>
    [DataField(Label = "Design JSON", Order = 3, FieldType = Rendering.Models.FormFieldType.TextArea)]
    public string DesignJson { get; set; } = "{}";

    /// <summary>Pipe-separated list of contributions: "user|timestamp|description".</summary>
    [DataField(Label = "Contributions Log", Order = 4, FieldType = Rendering.Models.FormFieldType.TextArea, ReadOnly = true)]
    public string ContributionsLog { get; set; } = string.Empty;

    /// <summary>Whether the session is still accepting contributions.</summary>
    [DataField(Label = "Open", Order = 5)]
    public bool IsOpen { get; set; } = true;

    public override string ToString() => SessionName;
}
