using System.Collections.Generic;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for DashboardDefinition records and DashboardTile models.
/// </summary>
public class DashboardDefinitionTests
{
    [Fact]
    public void DashboardDefinition_DefaultTilesJson_IsEmptyArray()
    {
        var def = SystemEntitySchemas.DashboardDefinition.CreateRecord();
        def.SetFieldValue(DashboardDefinitionFields.Name, "Test");
        Assert.Equal("[]", DashboardDefinitionHelper.GetTilesJson(def));
    }

    [Fact]
    public void DashboardDefinition_Tiles_RoundTrip()
    {
        var def = SystemEntitySchemas.DashboardDefinition.CreateRecord();
        def.SetFieldValue(DashboardDefinitionFields.Name, "Test");
        var tiles = new List<DashboardTile>
        {
            new DashboardTile
            {
                Title = "Orders Today",
                Icon = "bi-bag",
                Color = "success",
                EntitySlug = "orders",
                AggregateFunction = "count",
                ValuePrefix = "",
                ValueSuffix = ""
            },
            new DashboardTile
            {
                Title = "Revenue",
                Icon = "bi-currency-dollar",
                Color = "primary",
                EntitySlug = "orders",
                AggregateFunction = "sum",
                AggregateField = "Amount",
                ValuePrefix = "$",
                DecimalPlaces = 2
            }
        };

        def.SetFieldValue(DashboardDefinitionFields.TilesJson, BmwManualJson.SerializeDashboardTiles(tiles));

        // Re-read via helper
        var read = DashboardDefinitionHelper.GetTiles(def);
        Assert.Equal(2, read.Count);
        Assert.Equal("Orders Today", read[0].Title);
        Assert.Equal("bi-bag", read[0].Icon);
        Assert.Equal("success", read[0].Color);
        Assert.Equal("orders", read[0].EntitySlug);
        Assert.Equal("count", read[0].AggregateFunction);

        Assert.Equal("Revenue", read[1].Title);
        Assert.Equal("sum", read[1].AggregateFunction);
        Assert.Equal("Amount", read[1].AggregateField);
        Assert.Equal("$", read[1].ValuePrefix);
        Assert.Equal(2, read[1].DecimalPlaces);
    }

    [Fact]
    public void DashboardDefinition_InvalidJson_ReturnEmptyList()
    {
        var def = SystemEntitySchemas.DashboardDefinition.CreateRecord();
        def.SetFieldValue(DashboardDefinitionFields.TilesJson, "NOT_VALID_JSON");
        var tiles = DashboardDefinitionHelper.GetTiles(def);
        Assert.NotNull(tiles);
        Assert.Empty(tiles);
    }

    [Fact]
    public void DashboardDefinition_GetName_ReturnsName()
    {
        var def = SystemEntitySchemas.DashboardDefinition.CreateRecord();
        def.SetFieldValue(DashboardDefinitionFields.Name, "Exec KPIs");
        Assert.Equal("Exec KPIs", DashboardDefinitionHelper.GetName(def));
    }

    [Fact]
    public void DashboardTile_DefaultValues_AreReasonable()
    {
        var tile = new DashboardTile();
        Assert.Equal("bi-bar-chart-fill", tile.Icon);
        Assert.Equal("primary", tile.Color);
        Assert.Equal("count", tile.AggregateFunction);
        Assert.Equal(-1, tile.DecimalPlaces);
        Assert.Equal(string.Empty, tile.ValuePrefix);
        Assert.Equal(string.Empty, tile.ValueSuffix);
    }

    [Fact]
    public void DashboardTile_Filter_RoundTrip()
    {
        var def = SystemEntitySchemas.DashboardDefinition.CreateRecord();
        def.SetFieldValue(DashboardDefinitionFields.Name, "Test");
        def.SetFieldValue(DashboardDefinitionFields.TilesJson, BmwManualJson.SerializeDashboardTiles(new List<DashboardTile>
        {
            new DashboardTile
            {
                Title = "Pending Orders",
                EntitySlug = "orders",
                FilterField = "Status",
                FilterValue = "Pending"
            }
        }));

        var round = DashboardDefinitionHelper.GetTiles(def);
        Assert.Equal("Status", round[0].FilterField);
        Assert.Equal("Pending", round[0].FilterValue);
    }

    [Fact]
    public void DashboardDefinition_IsRegistrable_AsEntity()
    {
        var schema = SystemEntitySchemas.DashboardDefinition;
        Assert.NotNull(schema);
        Assert.Equal("dashboard-definitions", schema.Slug);
    }
}
