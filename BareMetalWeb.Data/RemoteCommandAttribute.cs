namespace BareMetalWeb.Data;

[AttributeUsage(AttributeTargets.Method, Inherited = true, AllowMultiple = false)]
public sealed class RemoteCommandAttribute : Attribute
{
    public string? Label { get; set; }
    public string? Icon { get; set; }
    public string? ConfirmMessage { get; set; }
    public bool Destructive { get; set; } = false;
    public string? Permission { get; set; }
    public bool OverrideEntityPermissions { get; set; } = false;
    public int Order { get; set; } = 0;
}
