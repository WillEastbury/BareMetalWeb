using System;

namespace BareMetalWeb.Data;

public sealed class UserSession : BaseDataObject
{
    public string UserId { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string[] Permissions { get; set; } = Array.Empty<string>();
    public DateTime IssuedUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresUtc { get; set; } = DateTime.UtcNow.AddHours(8);
    public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
    public bool RememberMe { get; set; }
    public bool IsRevoked { get; set; }

    public bool IsExpired(DateTime utcNow) => IsRevoked || ExpiresUtc <= utcNow;
}
