using System;

namespace BareMetalWeb.Data;

public sealed class DeviceCodeAuth : BaseDataObject
{
    public override string EntityTypeName => "DeviceCodeAuth";
    private const int Ord_UserCode = BaseFieldCount + 0;
    private const int Ord_DeviceCode = BaseFieldCount + 1;
    private const int Ord_ExpiresUtc = BaseFieldCount + 2;
    private const int Ord_Status = BaseFieldCount + 3;
    private const int Ord_UserId = BaseFieldCount + 4;
    private const int Ord_ClientDescription = BaseFieldCount + 5;
    internal new const int TotalFieldCount = BaseFieldCount + 6;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("ClientDescription", Ord_ClientDescription),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("DeviceCode", Ord_DeviceCode),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("ExpiresUtc", Ord_ExpiresUtc),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Status", Ord_Status),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("UserCode", Ord_UserCode),
        new FieldSlot("UserId", Ord_UserId),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public DeviceCodeAuth() : base(TotalFieldCount) { }
    public DeviceCodeAuth(string createdBy) : base(TotalFieldCount, createdBy) { }

    public string UserCode
    {
        get => (string?)_values[Ord_UserCode] ?? string.Empty;
        set => _values[Ord_UserCode] = value;
    }

    public string DeviceCode
    {
        get => (string?)_values[Ord_DeviceCode] ?? string.Empty;
        set => _values[Ord_DeviceCode] = value;
    }

    public DateTime ExpiresUtc
    {
        get => _values[Ord_ExpiresUtc] is DateTime dt ? dt : default;
        set => _values[Ord_ExpiresUtc] = value;
    }

    public string Status
    {
        get => (string?)_values[Ord_Status] ?? "pending";
        set => _values[Ord_Status] = value;
    }

    public string UserId
    {
        get => (string?)_values[Ord_UserId] ?? string.Empty;
        set => _values[Ord_UserId] = value;
    }

    public string ClientDescription
    {
        get => (string?)_values[Ord_ClientDescription] ?? string.Empty;
        set => _values[Ord_ClientDescription] = value;
    }

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
