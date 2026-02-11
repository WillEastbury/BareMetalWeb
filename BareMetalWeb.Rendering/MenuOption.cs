namespace BareMetalWeb.Rendering;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;

public class MenuOption : IMenuOption
{
    public string Href { get; set; }
    public string Label { get; set; }
    public bool ShowOnNavBar { get; set; }
    public string PermissionsNeeded { get; set; }
    public bool RightAligned { get; set; }
    public bool HighlightAsButton { get; set; }
    public bool RequiresAnonymous { get; set; }
    public bool RequiresLoggedIn { get; set; }
    public string[] RequiredPermissions { get; set; }
    public string? ColorClass { get; set; }
    public string? Group { get; set; }

    public MenuOption(
        string href,
        string label,
        bool showOnNavBar = true,
        string permissionsNeeded = "",
        bool rightAligned = false,
        bool highlightAsButton = false,
        bool requiresAnonymous = false,
        bool requiresLoggedIn = false,
        string[]? requiredPermissions = null,
        string? colorClass = null,
        string? group = null)
    {
        Href = href;
        Label = label;
        ShowOnNavBar = showOnNavBar;
        PermissionsNeeded = permissionsNeeded;
        RightAligned = rightAligned;
        HighlightAsButton = highlightAsButton;
        RequiresAnonymous = requiresAnonymous;
        RequiresLoggedIn = requiresLoggedIn;
        RequiredPermissions = requiredPermissions ?? Array.Empty<string>();
        ColorClass = colorClass;
        Group = group;
    }

}