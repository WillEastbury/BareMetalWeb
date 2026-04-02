using System;

namespace BareMetalWeb.Data;

public sealed class UserSession : DataRecord
{
    public override string EntityTypeName => "UserSession";
    private const int Ord_UserId = BaseFieldCount + 0;
    private const int Ord_UserName = BaseFieldCount + 1;
    private const int Ord_DisplayName = BaseFieldCount + 2;
    private const int Ord_Permissions = BaseFieldCount + 3;
    private const int Ord_IssuedUtc = BaseFieldCount + 4;
    private const int Ord_ExpiresUtc = BaseFieldCount + 5;
    private const int Ord_LastSeenUtc = BaseFieldCount + 6;
    private const int Ord_RememberMe = BaseFieldCount + 7;
    private const int Ord_IsRevoked = BaseFieldCount + 8;
    internal new const int TotalFieldCount = BaseFieldCount + 9;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("DisplayName", Ord_DisplayName),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("ExpiresUtc", Ord_ExpiresUtc),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("IsRevoked", Ord_IsRevoked),
        new FieldSlot("IssuedUtc", Ord_IssuedUtc),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("LastSeenUtc", Ord_LastSeenUtc),
        new FieldSlot("Permissions", Ord_Permissions),
        new FieldSlot("RememberMe", Ord_RememberMe),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("UserId", Ord_UserId),
        new FieldSlot("UserName", Ord_UserName),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public UserSession() : base(TotalFieldCount) { }
    public UserSession(string createdBy) : base(TotalFieldCount, createdBy) { }

    [DataIndex]
    public string UserId
    {
        get => (string?)_values[Ord_UserId] ?? string.Empty;
        set => _values[Ord_UserId] = value;
    }

    public string UserName
    {
        get => (string?)_values[Ord_UserName] ?? string.Empty;
        set => _values[Ord_UserName] = value;
    }

    public string DisplayName
    {
        get => (string?)_values[Ord_DisplayName] ?? string.Empty;
        set => _values[Ord_DisplayName] = value;
    }

    public string[] Permissions
    {
        get => (string[]?)_values[Ord_Permissions] ?? Array.Empty<string>();
        set => _values[Ord_Permissions] = value;
    }

    public DateTime IssuedUtc
    {
        get => _values[Ord_IssuedUtc] is DateTime dt ? dt : default;
        set => _values[Ord_IssuedUtc] = value;
    }

    public DateTime ExpiresUtc
    {
        get => _values[Ord_ExpiresUtc] is DateTime dt ? dt : default;
        set => _values[Ord_ExpiresUtc] = value;
    }

    public DateTime LastSeenUtc
    {
        get => _values[Ord_LastSeenUtc] is DateTime dt ? dt : default;
        set => _values[Ord_LastSeenUtc] = value;
    }

    public bool RememberMe
    {
        get => _values[Ord_RememberMe] is true;
        set => _values[Ord_RememberMe] = value;
    }

    public bool IsRevoked
    {
        get => _values[Ord_IsRevoked] is true;
        set => _values[Ord_IsRevoked] = value;
    }

    public bool IsExpired(DateTime utcNow) => IsRevoked || ExpiresUtc <= utcNow;
}
