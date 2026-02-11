namespace BareMetalWeb.Core.Interfaces;

public interface IMenuOption
{
    string Href { get; set; }
    string Label { get; set; }
    bool ShowOnNavBar { get; set; }
    string PermissionsNeeded { get; set; }
    bool RightAligned { get; set; }
    bool HighlightAsButton { get; set; }
    bool RequiresAnonymous { get; set; }
    bool RequiresLoggedIn { get; set; }
    string[] RequiredPermissions { get; set; }
    string? ColorClass { get; set; }
    string? Group { get; set; }
}
