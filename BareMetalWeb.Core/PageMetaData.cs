using BareMetalWeb.Interfaces;
namespace BareMetalWeb.Rendering;

public record PageMetaData(
    IHtmlTemplate Template,
    int StatusCode,
    string PermissionsNeeded = "", // AKA Anonymous if empty, or comma-separated list of permissions if needed, and a special value of "AnonymousOnly" if it should only be shown to anonymous users and hidden from logged in users regardless of permissions)
    bool ShowOnNavBar = true,
    int CacheExpiryInSeconds = -1 // in seconds; -1 means do not cache, 0 means cache indefinitely, or int in seconds for expiry
);
