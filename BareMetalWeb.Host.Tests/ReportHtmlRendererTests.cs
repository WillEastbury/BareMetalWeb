using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Tests for ReportHtmlRenderer — verifying that the Bootstrap/VNext-style chrome
/// is emitted and that report content is rendered correctly.
/// </summary>
public class ReportHtmlRendererTests
{
    private static async Task<string> RenderToStringAsync(
        ReportResult result,
        string title = "Test Report",
        string description = "",
        IReadOnlyList<ReportParameter>? parameters = null,
        IReadOnlyDictionary<string, string>? parameterValues = null,
        string reportId = "",
        string? nonce = "test-nonce",
        string? csrfToken = "test-csrf")
    {
        var stream = new MemoryStream();
        var pipeWriter = PipeWriter.Create(stream, new StreamPipeWriterOptions(leaveOpen: true));
        await ReportHtmlRenderer.RenderAsync(
            pipeWriter, result, title, description, parameters, parameterValues, reportId,
            host: null, nonce, csrfToken);
        await pipeWriter.CompleteAsync();
        stream.Position = 0;
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static ReportResult MakeResult(string[][] rows, params string[] columns)
    {
        return new ReportResult
        {
            ColumnLabels = columns,
            Rows = rows,
            TotalRows = rows.Length,
            IsTruncated = false,
            GeneratedAt = new DateTime(2026, 1, 15, 12, 0, 0, DateTimeKind.Utc)
        };
    }

    // ── Chrome head / footer ─────────────────────────────────────────────────

    [Fact]
    public async Task RenderAsync_IncludesBootstrapCss()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result);

        // Assert – theme bundle is now served locally (no CDN dependency)
        Assert.Contains("/static/css/themes/vapor.min.css", html);
    }

    [Fact]
    public async Task RenderAsync_IncludesBootstrapIcons()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result);

        // Assert – bootstrap-icons are now embedded in the per-theme CSS bundle;
        // the rendered page references the theme bundle link, not a separate CDN link.
        Assert.Contains("/static/css/themes/", html);
        Assert.DoesNotContain("cdn.jsdelivr.net/npm/bootstrap-icons", html);
    }

    [Fact]
    public async Task RenderAsync_IncludesSiteCss()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result);

        // Assert
        Assert.Contains("site.css", html);
    }

    [Fact]
    public async Task RenderAsync_IncludesCsrfMetaTag_WhenTokenProvided()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result, csrfToken: "mytoken");

        // Assert
        Assert.Contains("csrf-token", html);
        Assert.Contains("mytoken", html);
    }

    [Fact]
    public async Task RenderAsync_IncludesBootstrapJs()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result);

        // Assert
        Assert.Contains("bootstrap.bundle.min.js", html);
    }

    [Fact]
    public async Task RenderAsync_IncludesBundleJs()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result);

        // Assert
        Assert.Contains("bundle.js", html);
    }

    // ── RenderAsync content ──────────────────────────────────────────────────

    [Fact]
    public async Task RenderAsync_OutputsValidHtml()
    {
        // Arrange
        var result = MakeResult(new[] { new[] { "Alice", "30" } }, "Name", "Age");

        // Act
        var html = await RenderToStringAsync(result);

        // Assert
        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("Alice", html);
        Assert.Contains("30", html);
    }

    [Fact]
    public async Task RenderAsync_IncludesTitleInPage()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result, "My Special Report");

        // Assert
        Assert.Contains("My Special Report", html);
    }

    [Fact]
    public async Task RenderAsync_RendersColumnHeaders()
    {
        // Arrange
        var result = MakeResult(new[] { new[] { "v1", "v2" } }, "Column A", "Column B");

        // Act
        var html = await RenderToStringAsync(result);

        // Assert
        Assert.Contains("Column A", html);
        Assert.Contains("Column B", html);
    }

    [Fact]
    public async Task RenderAsync_RendersDataRows()
    {
        // Arrange
        var result = MakeResult(
            new[]
            {
                new[] { "Row1Col1", "Row1Col2" },
                new[] { "Row2Col1", "Row2Col2" }
            },
            "C1", "C2");

        // Act
        var html = await RenderToStringAsync(result);

        // Assert
        Assert.Contains("Row1Col1", html);
        Assert.Contains("Row2Col2", html);
    }

    [Fact]
    public async Task RenderAsync_ShowsTruncatedWarning_WhenTruncated()
    {
        // Arrange
        var result = new ReportResult
        {
            ColumnLabels = new[] { "X" },
            Rows = new[] { new[] { "a" } },
            TotalRows = 1,
            IsTruncated = true,
            GeneratedAt = DateTime.UtcNow
        };

        // Act
        var html = await RenderToStringAsync(result);

        // Assert
        Assert.Contains("capped at", html);
    }

    [Fact]
    public async Task RenderAsync_IncludesExportCsvLink_WhenReportIdProvided()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result, reportId: "rpt-123");

        // Assert
        Assert.Contains("/api/reports/rpt-123?format=csv", html);
    }

    [Fact]
    public async Task RenderAsync_NoExportLink_WhenReportIdEmpty()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result, reportId: "");

        // Assert
        Assert.DoesNotContain("format=csv", html);
    }

    [Fact]
    public async Task RenderAsync_RendersDescription_WhenProvided()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result, description: "A detailed report description");

        // Assert
        Assert.Contains("A detailed report description", html);
    }

    [Fact]
    public async Task RenderAsync_RendersParameterForm_WhenParametersProvided()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");
        var parameters = new List<ReportParameter>
        {
            new ReportParameter { Name = "startDate", Label = "Start Date", DefaultValue = "2026-01-01" }
        };

        // Act
        var html = await RenderToStringAsync(result, parameters: parameters);

        // Assert
        Assert.Contains("Start Date", html);
        Assert.Contains("startDate", html);
    }

    [Fact]
    public async Task RenderAsync_EscapesHtmlInCellValues()
    {
        // Arrange
        var result = MakeResult(new[] { new[] { "<script>alert('xss')</script>" } }, "Col");

        // Act
        var html = await RenderToStringAsync(result);

        // Assert — raw script tag should not appear, only encoded form
        Assert.DoesNotContain("<script>alert('xss')</script>", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    [Fact]
    public async Task RenderAsync_UsesBootstrapTableClasses()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result);

        // Assert — Bootstrap table classes used instead of custom CSS
        Assert.Contains("table table-hover", html);
        Assert.Contains("table-light", html);
    }

    [Fact]
    public async Task RenderAsync_IncludesBackToReportsLink()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result);

        // Assert
        Assert.Contains("/reports", html);
    }

    [Fact]
    public async Task RenderAsync_DoesNotContainOldEmbeddedCss()
    {
        // Arrange
        var result = MakeResult(Array.Empty<string[]>(), "Col");

        // Act
        var html = await RenderToStringAsync(result);

        // Assert — old standalone embedded CSS should not be present
        Assert.DoesNotContain("bm-table", html);
        Assert.DoesNotContain("report-header", html);
        Assert.DoesNotContain("btn-run", html);
    }
}

