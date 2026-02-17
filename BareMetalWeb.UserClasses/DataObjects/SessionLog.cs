using System;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

/// <summary>
/// Example entity demonstrating auto-generated GUID string IDs.
/// Each instance will receive a unique 32-character hexadecimal ID.
/// </summary>
[DataEntity("Sessions", ShowOnNav = true, NavGroup = "System", NavOrder = 90)]
public class SessionLog : RenderableDataObject
{
    // Override the base Id property to apply auto-generation with GUID string strategy
    [IdGeneration(IdGenerationStrategy.GuidString)]
    [DataField(Label = "Session ID", Order = 0, ReadOnly = true, List = true, View = true, Edit = false, Create = false)]
    public new string Id
    {
        get => base.Id;
        set => base.Id = value;
    }

    [DataField(Label = "User", Order = 1, Required = true)]
    public string UserName { get; set; } = string.Empty;

    [DataField(Label = "IP Address", Order = 2)]
    public string IpAddress { get; set; } = string.Empty;

    [DataField(Label = "User Agent", Order = 3)]
    public string UserAgent { get; set; } = string.Empty;

    [DataField(Label = "Started At", Order = 4, Required = true, FieldType = Rendering.Models.FormFieldType.DateTime)]
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;

    [DataField(Label = "Last Activity", Order = 5, FieldType = Rendering.Models.FormFieldType.DateTime)]
    public DateTime? LastActivity { get; set; }

    [DataField(Label = "Active", Order = 6)]
    public bool IsActive { get; set; } = true;
}
