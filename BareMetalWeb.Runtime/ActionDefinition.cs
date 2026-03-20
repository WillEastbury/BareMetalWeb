using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted descriptor for a server-side action that can be invoked against
/// an entity instance. The metadata layer describes actions; execution is
/// handled by <see cref="ICommandService"/>.
/// </summary>
[DataEntity("Action Definitions", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1003)]
public class ActionDefinition : BaseDataObject
{
    private const int Ord_EntityId = BaseFieldCount + 0;
    private const int Ord_Name = BaseFieldCount + 1;
    private const int Ord_Label = BaseFieldCount + 2;
    private const int Ord_Icon = BaseFieldCount + 3;
    private const int Ord_Permission = BaseFieldCount + 4;
    private const int Ord_EnabledWhen = BaseFieldCount + 5;
    private const int Ord_Operations = BaseFieldCount + 6;
    private new const int Ord_Version = BaseFieldCount + 7;
    internal const int TotalFieldCount = BaseFieldCount + 8;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("EnabledWhen", Ord_EnabledWhen),
        new FieldSlot("EntityId", Ord_EntityId),
        new FieldSlot("Icon", Ord_Icon),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Label", Ord_Label),
        new FieldSlot("Name", Ord_Name),
        new FieldSlot("Operations", Ord_Operations),
        new FieldSlot("Permission", Ord_Permission),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public ActionDefinition() : base(TotalFieldCount) { }
    public ActionDefinition(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Foreign key to <see cref="EntityDefinition.Id"/>.</summary>
    [DataField(Label = "Entity ID", Order = 1, Required = true)]
    [DataLookup(typeof(EntityDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string EntityId
    {
        get => (string?)_values[Ord_EntityId] ?? string.Empty;
        set => _values[Ord_EntityId] = value;
    }

    [DataField(Label = "Name", Order = 2, Required = true)]
    public string Name
    {
        get => (string?)_values[Ord_Name] ?? string.Empty;
        set => _values[Ord_Name] = value;
    }

    [DataField(Label = "Label", Order = 3)]
    public string? Label
    {
        get => (string?)_values[Ord_Label];
        set => _values[Ord_Label] = value;
    }

    [DataField(Label = "Icon", Order = 4)]
    public string? Icon
    {
        get => (string?)_values[Ord_Icon];
        set => _values[Ord_Icon] = value;
    }

    /// <summary>Permission token required to execute this action.</summary>
    [DataField(Label = "Permission", Order = 5)]
    public string? Permission
    {
        get => (string?)_values[Ord_Permission];
        set => _values[Ord_Permission] = value;
    }

    /// <summary>
    /// Boolean expression evaluated at runtime to determine whether the action
    /// button is enabled. Example: "IsResolved == false".
    /// </summary>
    [DataField(Label = "Enabled When", Order = 6)]
    public string? EnabledWhen
    {
        get => (string?)_values[Ord_EnabledWhen];
        set => _values[Ord_EnabledWhen] = value;
    }

    /// <summary>
    /// Pipe-separated list of "SetField:FieldName=Value" operations executed
    /// when this action is invoked. Example: "SetField:IsResolved=true|SetField:ResolvedBy=CurrentUser".
    /// This is intentionally declarative and limited; complex logic belongs in compiled code.
    /// </summary>
    [DataField(Label = "Operations", Order = 7)]
    public string? Operations
    {
        get => (string?)_values[Ord_Operations];
        set => _values[Ord_Operations] = value;
    }

    /// <summary>
    /// Schema version of this action definition.
    /// Increment when the command set changes to invalidate any cached expansions.
    /// Once published, the <see cref="Name"/> (ActionId) is immutable per spec §2.
    /// </summary>
    [DataField(Label = "Version", Order = 8, ReadOnly = true)]
    public new int Version
    {
        get => (int)(_values[Ord_Version] ?? 1);
        set => _values[Ord_Version] = value;
    }

    public override string ToString() => Label ?? Name;
}
