using System;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

/// <summary>
/// Internal session log — not exposed in the admin data UI.
/// </summary>
public class SessionLog : BaseDataObject
{
    public string UserName { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastActivity { get; set; }
    public bool IsActive { get; set; } = true;
}
