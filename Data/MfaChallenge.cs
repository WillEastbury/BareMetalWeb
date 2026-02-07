using System;

namespace BareMetalWeb.Data;

public sealed class MfaChallenge : BaseDataObject
{
    public string UserId { get; set; } = string.Empty;
    public bool RememberMe { get; set; }
    public DateTime ExpiresUtc { get; set; } = DateTime.UtcNow.AddMinutes(5);
    public bool IsUsed { get; set; }

    public bool IsExpired() => IsUsed || ExpiresUtc <= DateTime.UtcNow;
}
