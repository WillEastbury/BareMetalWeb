using System.Buffers;
using System.Text;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Host.Tests;

public class BmwLayoutGrammarTests
{
    [Fact]
    public void Stack_EmitsCorrectTags()
    {
        var sb = new StringBuilder();
        BmwLayoutGrammar.Stack(sb);
        sb.Append("content");
        BmwLayoutGrammar.EndStack(sb);
        Assert.Equal("<ds>content</ds>", sb.ToString());
    }

    [Fact]
    public void Row_EmitsCorrectTags()
    {
        var sb = new StringBuilder();
        BmwLayoutGrammar.Row(sb);
        sb.Append("content");
        BmwLayoutGrammar.EndRow(sb);
        Assert.Equal("<dr>content</dr>", sb.ToString());
    }

    [Fact]
    public void Row_WithCols_EmitsColsAttribute()
    {
        var sb = new StringBuilder();
        BmwLayoutGrammar.Row(sb, 3);
        BmwLayoutGrammar.EndRow(sb);
        Assert.Equal("<dr cols=3></dr>", sb.ToString());
    }

    [Fact]
    public void Col_EmitsCorrectTags()
    {
        var sb = new StringBuilder();
        BmwLayoutGrammar.Col(sb);
        sb.Append("cell");
        BmwLayoutGrammar.EndCol(sb);
        Assert.Equal("<dc>cell</dc>", sb.ToString());
    }

    [Fact]
    public void Box_EmitsCorrectTags()
    {
        var sb = new StringBuilder();
        BmwLayoutGrammar.Box(sb);
        sb.Append("panel");
        BmwLayoutGrammar.EndBox(sb);
        Assert.Equal("<db>panel</db>", sb.ToString());
    }

    [Fact]
    public void Nav_EmitsCorrectTags()
    {
        var sb = new StringBuilder();
        BmwLayoutGrammar.Nav(sb);
        sb.Append("title");
        BmwLayoutGrammar.EndNav(sb);
        Assert.Equal("<dn>title</dn>", sb.ToString());
    }

    [Fact]
    public void Table_EmitsCorrectTags()
    {
        var sb = new StringBuilder();
        BmwLayoutGrammar.Table(sb);
        sb.Append("<table></table>");
        BmwLayoutGrammar.EndTable(sb);
        Assert.Equal("<ta><table></table></ta>", sb.ToString());
    }

    [Fact]
    public void Chart_EmitsCorrectTags()
    {
        var sb = new StringBuilder();
        BmwLayoutGrammar.Chart(sb);
        BmwLayoutGrammar.EndChart(sb);
        Assert.Equal("<ch></ch>", sb.ToString());
    }

    [Fact]
    public void Gantt_EmitsCorrectTags()
    {
        var sb = new StringBuilder();
        BmwLayoutGrammar.Gantt(sb);
        BmwLayoutGrammar.EndGantt(sb);
        Assert.Equal("<gt></gt>", sb.ToString());
    }

    [Fact]
    public void Calendar_EmitsCorrectTags()
    {
        var sb = new StringBuilder();
        BmwLayoutGrammar.Calendar(sb);
        BmwLayoutGrammar.EndCalendar(sb);
        Assert.Equal("<cl></cl>", sb.ToString());
    }

    [Fact]
    public void WriteStack_ToBufferWriter()
    {
        var buffer = new ArrayBufferWriter<byte>();
        BmwLayoutGrammar.WriteStack(buffer);
        BmwLayoutGrammar.WriteEndStack(buffer);
        Assert.Equal("<ds></ds>", Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    [Fact]
    public void WriteRow_WithCols_ToBufferWriter()
    {
        var buffer = new ArrayBufferWriter<byte>();
        BmwLayoutGrammar.WriteRow(buffer, 2);
        BmwLayoutGrammar.WriteCol(buffer);
        BmwLayoutGrammar.WriteEndCol(buffer);
        BmwLayoutGrammar.WriteCol(buffer);
        BmwLayoutGrammar.WriteEndCol(buffer);
        BmwLayoutGrammar.WriteEndRow(buffer);
        Assert.Equal("<dr cols=2><dc></dc><dc></dc></dr>", Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    [Fact]
    public void WriteBox_ToBufferWriter()
    {
        var buffer = new ArrayBufferWriter<byte>();
        BmwLayoutGrammar.WriteBox(buffer);
        BmwLayoutGrammar.WriteEndBox(buffer);
        Assert.Equal("<db></db>", Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    [Fact]
    public void WriteNav_ToBufferWriter()
    {
        var buffer = new ArrayBufferWriter<byte>();
        BmwLayoutGrammar.WriteNav(buffer);
        BmwLayoutGrammar.WriteEndNav(buffer);
        Assert.Equal("<dn></dn>", Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    [Fact]
    public void WriteTable_ToBufferWriter()
    {
        var buffer = new ArrayBufferWriter<byte>();
        BmwLayoutGrammar.WriteTable(buffer);
        BmwLayoutGrammar.WriteEndTable(buffer);
        Assert.Equal("<ta></ta>", Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    [Fact]
    public void WriteChart_Gantt_Calendar_ToBufferWriter()
    {
        var buffer = new ArrayBufferWriter<byte>();
        BmwLayoutGrammar.WriteChart(buffer);
        BmwLayoutGrammar.WriteEndChart(buffer);
        BmwLayoutGrammar.WriteGantt(buffer);
        BmwLayoutGrammar.WriteEndGantt(buffer);
        BmwLayoutGrammar.WriteCalendar(buffer);
        BmwLayoutGrammar.WriteEndCalendar(buffer);
        Assert.Equal("<ch></ch><gt></gt><cl></cl>", Encoding.UTF8.GetString(buffer.WrittenSpan));
    }

    [Fact]
    public void BuildDashboardLayout_GeneratesCorrectStructure()
    {
        var html = BmwLayoutGrammar.BuildDashboardLayout(
            "Sales Dashboard",
            2,
            new[] { "Revenue", "Orders", "Customers" });

        Assert.Contains("<dn>Sales Dashboard</dn>", html);
        Assert.Contains("<ds>", html);
        Assert.Contains("</ds>", html);
        Assert.Contains("<dr cols=2>", html);
        Assert.Contains("<dc>", html);
        Assert.Contains("<db>", html);
        Assert.Contains("<strong>Revenue</strong>", html);
        Assert.Contains("<strong>Orders</strong>", html);
        Assert.Contains("<strong>Customers</strong>", html);
    }

    [Fact]
    public void BuildDashboardLayout_EscapesHtml()
    {
        var html = BmwLayoutGrammar.BuildDashboardLayout(
            "Test <script>alert('xss')</script>",
            1,
            new[] { "Panel <b>1</b>" });

        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("&lt;b&gt;", html);
    }

    [Fact]
    public void NestedLayout_ComposesCorrectly()
    {
        var sb = new StringBuilder();
        BmwLayoutGrammar.Stack(sb);
        BmwLayoutGrammar.Nav(sb);
        sb.Append("Dashboard");
        BmwLayoutGrammar.EndNav(sb);
        BmwLayoutGrammar.Row(sb, 3);
        for (int i = 0; i < 3; i++)
        {
            BmwLayoutGrammar.Col(sb);
            BmwLayoutGrammar.Box(sb);
            sb.Append("Panel " + i);
            BmwLayoutGrammar.EndBox(sb);
            BmwLayoutGrammar.EndCol(sb);
        }
        BmwLayoutGrammar.EndRow(sb);
        BmwLayoutGrammar.Table(sb);
        sb.Append("<table><tr><td>data</td></tr></table>");
        BmwLayoutGrammar.EndTable(sb);
        BmwLayoutGrammar.EndStack(sb);

        var html = sb.ToString();
        Assert.StartsWith("<ds>", html);
        Assert.EndsWith("</ds>", html);
        Assert.Contains("<dn>Dashboard</dn>", html);
        Assert.Contains("<dr cols=3>", html);
        Assert.Contains("<dc><db>Panel 0</db></dc>", html);
        Assert.Contains("<ta><table>", html);
    }
}
