using System;

namespace BareMetalWeb.Data;

public sealed class MfaChallenge : BaseDataObject
{
    public override string EntityTypeName => "MfaChallenge";
    private const int Ord_UserId = BaseFieldCount + 0;
    private const int Ord_RememberMe = BaseFieldCount + 1;
    private const int Ord_ExpiresUtc = BaseFieldCount + 2;
    private const int Ord_IsUsed = BaseFieldCount + 3;
    internal new const int TotalFieldCount = BaseFieldCount + 4;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("ExpiresUtc", Ord_ExpiresUtc),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("IsUsed", Ord_IsUsed),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("RememberMe", Ord_RememberMe),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("UserId", Ord_UserId),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public MfaChallenge() : base(TotalFieldCount) { }
    public MfaChallenge(string createdBy) : base(TotalFieldCount, createdBy) { }

    public string UserId
    {
        get => (string?)_values[Ord_UserId] ?? string.Empty;
        set => _values[Ord_UserId] = value;
    }

    public bool RememberMe
    {
        get => _values[Ord_RememberMe] is true;
        set => _values[Ord_RememberMe] = value;
    }

    public DateTime ExpiresUtc
    {
        get => _values[Ord_ExpiresUtc] is DateTime dt ? dt : default;
        set => _values[Ord_ExpiresUtc] = value;
    }

    public bool IsUsed
    {
        get => _values[Ord_IsUsed] is true;
        set => _values[Ord_IsUsed] = value;
    }

    public bool IsExpired() => IsUsed || ExpiresUtc <= DateTime.UtcNow;
}
