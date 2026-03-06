using System.Text.Json;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Data;

/// <summary>
/// A persisted, named collection of <see cref="DashboardTile"/> KPI definitions.
/// Each tile queries an entity aggregate (count/sum/avg/min/max) and renders as a
/// Bootstrap card in the dashboard view at <c>GET /dashboards/{id}</c>.
/// </summary>
[DataEntity("Dashboard Definitions", Slug = "dashboard-definitions", ShowOnNav = true,
    Permissions = "admin", NavGroup = "Admin", NavOrder = 95)]
public sealed class DashboardDefinition : BaseDataObject
{
    public DashboardDefinition() : base() { }
    public DashboardDefinition(string createdBy) : base(createdBy) { }

    [DataField(Label = "Name", Order = 1, Required = true, List = true)]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Description", Order = 2, FieldType = FormFieldType.TextArea)]
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// JSON-serialised list of <see cref="DashboardTile"/>.
    /// Each tile declares the entity, aggregate function and display options.
    /// </summary>
    [DataField(Label = "Tiles (JSON)", Order = 3, FieldType = FormFieldType.TextArea)]
    public string TilesJson { get; set; } = "[]";

    /// <summary>Convenience accessor that deserialises <see cref="TilesJson"/>.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public List<DashboardTile> Tiles
    {
        get => DeserializeTiles(TilesJson);
        set => TilesJson = JsonSerializer.Serialize(value ?? new List<DashboardTile>());
    }

    private static List<DashboardTile> DeserializeTiles(string json)
    {
        try
        {
            return string.IsNullOrWhiteSpace(json)
                ? new List<DashboardTile>()
                : JsonSerializer.Deserialize<List<DashboardTile>>(json) ?? new List<DashboardTile>();
        }
        catch
        {
            return new List<DashboardTile>();
        }
    }

    public override string ToString() => Name;
}
