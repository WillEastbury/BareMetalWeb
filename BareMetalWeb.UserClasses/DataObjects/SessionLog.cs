using System;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

/// <summary>
/// Session log — admin-only, not shown in user navigation.
/// </summary>
[DataEntity("Sessions", ShowOnNav = false, Permissions = "admin")]
public class SessionLog : BaseDataObject
{
    [DataField(Label = "User", Order = 1, Required = true)]
    [DataIndex]
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
