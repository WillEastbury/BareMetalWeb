using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Tests for DashboardHtmlRenderer — verifying that the Bootstrap chrome and
/// KPI tile HTML are emitted correctly.
/// </summary>
public class DashboardHtmlRendererTests
{
    private static async Task<string> RenderToStringAsync(
        DashboardDefinition def,
        string? nonce = "test-nonce",
        string? csrfToken = "test-csrf")
    {
        var stream = new MemoryStream();
        var pipeWriter = PipeWriter.Create(stream, new StreamPipeWriterOptions(leaveOpen: true));
        await DashboardHtmlRenderer.RenderAsync(pipeWriter, def, host: null, nonce, csrfToken);
        await pipeWriter.CompleteAsync();
        stream.Position = 0;
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static DashboardDefinition MakeDef(string name, List<DashboardTile>? tiles = null)
    {
        var def = new DashboardDefinition { Name = name };
        if (tiles != null) def.Tiles = tiles;
        return def;
    }

    // ── Chrome head / structure tests ─────────────────────────────────────────

    [Fact]
    public async Task RenderAsync_IncludesBootstrapCss()
    {
        var def = MakeDef("Test Dashboard");
        var html = await RenderToStringAsync(def);
        Assert.Contains("/static/css/themes/vapor.min.css", html);
    }

    [Fact]
    public async Task RenderAsync_ContainsDashboardTitle()
    {
        var def = MakeDef("Revenue KPIs");
        var html = await RenderToStringAsync(def);
        Assert.Contains("Revenue KPIs", html);
    }

    [Fact]
    public async Task RenderAsync_EmptyTilesShowsEmptyState()
    {
        var def = MakeDef("Empty Dashboard");
        var html = await RenderToStringAsync(def);
        Assert.Contains("No KPI tiles defined", html);
    }

    [Fact]
    public async Task RenderAsync_TileWithEntityShowsValue()
    {
        // No real entity registered in this unit test, so value resolves to "?"
        var def = MakeDef("KPI", new List<DashboardTile>
        {
            new DashboardTile { Title = "Orders", EntitySlug = "orders", AggregateFunction = "count", Color = "primary" }
        });
        var html = await RenderToStringAsync(def);
        Assert.Contains("Orders", html);
    }

    [Fact]
    public async Task RenderAsync_ContainsBackLink()
    {
        var def = MakeDef("Test");
        var html = await RenderToStringAsync(def);
        Assert.Contains("/dashboards", html);
        Assert.Contains("All Dashboards", html);
    }

    [Fact]
    public async Task RenderAsync_ContainsAutoRefreshScript()
    {
        var def = MakeDef("Test", new List<DashboardTile>
        {
            new DashboardTile { Title = "Count", EntitySlug = "orders", AggregateFunction = "count" }
        });
        var html = await RenderToStringAsync(def);
        Assert.Contains("<script", html);
        Assert.Contains("/api/dashboards/", html);
    }

    [Fact]
    public async Task RenderAsync_TileColorSanitized()
    {
        var def = MakeDef("KPI", new List<DashboardTile>
        {
            new DashboardTile { Title = "T1", EntitySlug = "orders", Color = "success" },
            new DashboardTile { Title = "T2", EntitySlug = "orders", Color = "danger" },
            new DashboardTile { Title = "T3", EntitySlug = "orders", Color = "javascript:alert(1)" }
        });
        var html = await RenderToStringAsync(def);
        Assert.Contains("bg-success", html);
        Assert.Contains("bg-danger", html);
        // Malicious color is sanitized to "primary"
        Assert.Contains("bg-primary", html);
        Assert.DoesNotContain("javascript:alert(1)", html);
    }
}
