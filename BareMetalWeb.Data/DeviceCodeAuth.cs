using System;

namespace BareMetalWeb.Data;

public sealed class DeviceCodeAuth : BaseDataObject
{
    public string UserCode { get; set; } = string.Empty;
    public string DeviceCode { get; set; } = string.Empty;
    public DateTime ExpiresUtc { get; set; } = DateTime.UtcNow.AddMinutes(15);
    public string Status { get; set; } = "pending"; // pending, approved, denied, expired
    public string UserId { get; set; } = string.Empty;
    public string ClientDescription { get; set; } = string.Empty;

    public bool IsExpired(DateTime utcNow) => ExpiresUtc <= utcNow;

    private static readonly char[] CodeChars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789".ToCharArray();

    public static string GenerateUserCode()
    {
        var bytes = new byte[8];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        var chars = new char[9];
        for (int i = 0; i < 4; i++)
            chars[i] = CodeChars[bytes[i] % CodeChars.Length];
        chars[4] = '-';
        for (int i = 0; i < 4; i++)
            chars[i + 5] = CodeChars[bytes[i + 4] % CodeChars.Length];
        return new string(chars);
    }

    public static string GenerateDeviceCode()
    {
        var bytes = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
