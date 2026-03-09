using System.Buffers;
using System.Text;

namespace BareMetalWeb.Rendering;

/// <summary>
/// BMW UI Layout Grammar — generates compact custom HTML elements instead of
/// verbose Bootstrap div+class constructs. Each tag is a 2-letter mnemonic:
///   ds=stack  dr=row  dc=column  db=box  dn=nav  ta=table  ch=chart  gt=gantt  cl=calendar
///
/// Example output: &lt;ds&gt;&lt;dr&gt;&lt;dc&gt;content&lt;/dc&gt;&lt;dc&gt;sidebar&lt;/dc&gt;&lt;/dr&gt;&lt;/ds&gt;
///
/// Styling is provided by bmw.css (~800 bytes) which defines flexbox/grid
/// behaviour for these unknown-to-the-browser elements.
/// </summary>
public static class BmwLayoutGrammar
{
    // Tag constants — use ReadOnlySpan<byte> for zero-allocation writes
    private static readonly byte[] StackOpen = "<ds>"u8.ToArray();
    private static readonly byte[] StackClose = "</ds>"u8.ToArray();
    private static readonly byte[] RowOpen = "<dr>"u8.ToArray();
    private static readonly byte[] RowClose = "</dr>"u8.ToArray();
    private static readonly byte[] ColOpen = "<dc>"u8.ToArray();
    private static readonly byte[] ColClose = "</dc>"u8.ToArray();
    private static readonly byte[] BoxOpen = "<db>"u8.ToArray();
    private static readonly byte[] BoxClose = "</db>"u8.ToArray();
    private static readonly byte[] NavOpen = "<dn>"u8.ToArray();
    private static readonly byte[] NavClose = "</dn>"u8.ToArray();
    private static readonly byte[] TableOpen = "<ta>"u8.ToArray();
    private static readonly byte[] TableClose = "</ta>"u8.ToArray();
    private static readonly byte[] ChartOpen = "<ch>"u8.ToArray();
    private static readonly byte[] ChartClose = "</ch>"u8.ToArray();
    private static readonly byte[] GanttOpen = "<gt>"u8.ToArray();
    private static readonly byte[] GanttClose = "</gt>"u8.ToArray();
    private static readonly byte[] CalendarOpen = "<cl>"u8.ToArray();
    private static readonly byte[] CalendarClose = "</cl>"u8.ToArray();

    // Row with cols attribute
    private static readonly byte[] RowCols2Open = "<dr cols=2>"u8.ToArray();
    private static readonly byte[] RowCols3Open = "<dr cols=3>"u8.ToArray();
    private static readonly byte[] RowCols4Open = "<dr cols=4>"u8.ToArray();

    /// <summary>Write a BMW layout tag to a StringBuilder (string rendering path).</summary>
    public static void Stack(StringBuilder sb) => sb.Append("<ds>");
    public static void EndStack(StringBuilder sb) => sb.Append("</ds>");
    public static void Row(StringBuilder sb, int cols = 0)
    {
        if (cols > 1) { sb.Append("<dr cols="); sb.Append(cols); sb.Append('>'); }
        else sb.Append("<dr>");
    }
    public static void EndRow(StringBuilder sb) => sb.Append("</dr>");
    public static void Col(StringBuilder sb) => sb.Append("<dc>");
    public static void EndCol(StringBuilder sb) => sb.Append("</dc>");
    public static void Box(StringBuilder sb) => sb.Append("<db>");
    public static void EndBox(StringBuilder sb) => sb.Append("</db>");
    public static void Nav(StringBuilder sb) => sb.Append("<dn>");
    public static void EndNav(StringBuilder sb) => sb.Append("</dn>");
    public static void Table(StringBuilder sb) => sb.Append("<ta>");
    public static void EndTable(StringBuilder sb) => sb.Append("</ta>");
    public static void Chart(StringBuilder sb) => sb.Append("<ch>");
    public static void EndChart(StringBuilder sb) => sb.Append("</ch>");
    public static void Gantt(StringBuilder sb) => sb.Append("<gt>");
    public static void EndGantt(StringBuilder sb) => sb.Append("</gt>");
    public static void Calendar(StringBuilder sb) => sb.Append("<cl>");
    public static void EndCalendar(StringBuilder sb) => sb.Append("</cl>");

    /// <summary>Write BMW layout tags to a byte buffer (binary rendering path).</summary>
    public static void WriteStack(IBufferWriter<byte> writer) => Write(writer, StackOpen);
    public static void WriteEndStack(IBufferWriter<byte> writer) => Write(writer, StackClose);
    public static void WriteRow(IBufferWriter<byte> writer, int cols = 0)
    {
        if (cols == 2) Write(writer, RowCols2Open);
        else if (cols == 3) Write(writer, RowCols3Open);
        else if (cols == 4) Write(writer, RowCols4Open);
        else Write(writer, RowOpen);
    }
    public static void WriteEndRow(IBufferWriter<byte> writer) => Write(writer, RowClose);
    public static void WriteCol(IBufferWriter<byte> writer) => Write(writer, ColOpen);
    public static void WriteEndCol(IBufferWriter<byte> writer) => Write(writer, ColClose);
    public static void WriteBox(IBufferWriter<byte> writer) => Write(writer, BoxOpen);
    public static void WriteEndBox(IBufferWriter<byte> writer) => Write(writer, BoxClose);
    public static void WriteNav(IBufferWriter<byte> writer) => Write(writer, NavOpen);
    public static void WriteEndNav(IBufferWriter<byte> writer) => Write(writer, NavClose);
    public static void WriteTable(IBufferWriter<byte> writer) => Write(writer, TableOpen);
    public static void WriteEndTable(IBufferWriter<byte> writer) => Write(writer, TableClose);
    public static void WriteChart(IBufferWriter<byte> writer) => Write(writer, ChartOpen);
    public static void WriteEndChart(IBufferWriter<byte> writer) => Write(writer, ChartClose);
    public static void WriteGantt(IBufferWriter<byte> writer) => Write(writer, GanttOpen);
    public static void WriteEndGantt(IBufferWriter<byte> writer) => Write(writer, GanttClose);
    public static void WriteCalendar(IBufferWriter<byte> writer) => Write(writer, CalendarOpen);
    public static void WriteEndCalendar(IBufferWriter<byte> writer) => Write(writer, CalendarClose);

    private static void Write(IBufferWriter<byte> writer, byte[] data)
    {
        var span = writer.GetSpan(data.Length);
        data.CopyTo(span);
        writer.Advance(data.Length);
    }

    /// <summary>
    /// Generate a complete dashboard layout from metadata using BMW grammar.
    /// Returns an HTML string using ds/dr/dc/db/ta/ch tags.
    /// </summary>
    public static string BuildDashboardLayout(string title, int columns, string[] panelTitles)
    {
        var sb = new StringBuilder(512);
        Nav(sb); sb.Append(System.Net.WebUtility.HtmlEncode(title)); EndNav(sb);
        Stack(sb);
        for (int i = 0; i < panelTitles.Length; i += columns)
        {
            Row(sb, columns);
            for (int j = i; j < i + columns && j < panelTitles.Length; j++)
            {
                Col(sb);
                Box(sb);
                sb.Append("<strong>");
                sb.Append(System.Net.WebUtility.HtmlEncode(panelTitles[j]));
                sb.Append("</strong>");
                EndBox(sb);
                EndCol(sb);
            }
            EndRow(sb);
        }
        EndStack(sb);
        return sb.ToString();
    }
}
