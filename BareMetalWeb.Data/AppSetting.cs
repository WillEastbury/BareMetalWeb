namespace BareMetalWeb.Data;

[DataEntity("Settings", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1, Permissions = "admin")]
public class AppSetting : DataRecord
{
    public override string EntityTypeName => "AppSetting";
    private const int Ord_SettingId = BaseFieldCount + 0;
    private const int Ord_Value = BaseFieldCount + 1;
    private const int Ord_Description = BaseFieldCount + 2;
    internal new const int TotalFieldCount = BaseFieldCount + 3;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("Description", Ord_Description),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("SettingId", Ord_SettingId),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Value", Ord_Value),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public AppSetting() : base(TotalFieldCount) { }
    public AppSetting(string createdBy) : base(TotalFieldCount, createdBy) { }

    [DataField(Label = "Setting ID", Order = 1, Required = true)]
    [DataIndex]
    public string SettingId
    {
        get => (string?)_values[Ord_SettingId] ?? string.Empty;
        set => _values[Ord_SettingId] = value;
    }

    [DataField(Label = "Value", Order = 2)]
    public string Value
    {
        get => (string?)_values[Ord_Value] ?? string.Empty;
        set => _values[Ord_Value] = value;
    }

    [DataField(Label = "Description", Order = 3)]
    public string Description
    {
        get => (string?)_values[Ord_Description] ?? string.Empty;
        set => _values[Ord_Description] = value;
    }
}
