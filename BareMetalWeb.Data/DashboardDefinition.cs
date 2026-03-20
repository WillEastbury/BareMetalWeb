using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Data;

/// <summary>
/// A persisted, named collection of <see cref="DashboardTile"/> KPI definitions.
/// Each tile queries an entity aggregate (count/sum/avg/min/max) and renders as a
/// Bootstrap card in the dashboard view at <c>GET /dashboards/{id}</c>.
/// </summary>
[DataEntity("Dashboard Definitions", Slug = "dashboard-definitions", ShowOnNav = false,
    Permissions = "admin", NavGroup = "Admin", NavOrder = 95)]
public sealed class DashboardDefinition : BaseDataObject
{
    private const int Ord_Name = BaseFieldCount + 0;
    private const int Ord_Description = BaseFieldCount + 1;
    private const int Ord_TilesJson = BaseFieldCount + 2;
    internal new const int TotalFieldCount = BaseFieldCount + 3;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("Description", Ord_Description),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Name", Ord_Name),
        new FieldSlot("TilesJson", Ord_TilesJson),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public DashboardDefinition() : base(TotalFieldCount) { }
    public DashboardDefinition(string createdBy) : base(TotalFieldCount, createdBy) { }

    [DataField(Label = "Name", Order = 1, Required = true, List = true)]
    public string Name
    {
        get => (string?)_values[Ord_Name] ?? string.Empty;
        set => _values[Ord_Name] = value;
    }

    [DataField(Label = "Description", Order = 2, FieldType = FormFieldType.TextArea)]
    public string Description
    {
        get => (string?)_values[Ord_Description] ?? string.Empty;
        set => _values[Ord_Description] = value;
    }

    /// <summary>
    /// JSON-serialised list of <see cref="DashboardTile"/>.
    /// Each tile declares the entity, aggregate function and display options.
    /// </summary>
    [DataField(Label = "Tiles (JSON)", Order = 3, FieldType = FormFieldType.TextArea)]
    public string TilesJson
    {
        get => (string?)_values[Ord_TilesJson] ?? "[]";
        set => _values[Ord_TilesJson] = value;
    }

    /// <summary>Convenience accessor that deserialises <see cref="TilesJson"/>.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public List<DashboardTile> Tiles
    {
        get => BmwManualJson.DeserializeDashboardTiles(TilesJson);
        set => TilesJson = BmwManualJson.SerializeDashboardTiles(value ?? new List<DashboardTile>());
    }

    private static List<DashboardTile> DeserializeTiles(string json)
    {
        return BmwManualJson.DeserializeDashboardTiles(json);
    }

    public override string ToString() => Name;
}
