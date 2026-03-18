using System.Buffers;
using System.Text.Json;

namespace BareMetalWeb.Data;

/// <summary>
/// Manual JSON serialization for all Data-layer DTOs.
/// Uses Utf8JsonWriter/Utf8JsonReader directly — no JsonSerializer, no reflection, full AOT/trim safety.
/// </summary>
internal static class BmwManualJson
{
    // ── FieldChange ──────────────────────────────────────────────────────────

    internal static string SerializeFieldChanges(List<FieldChange> list)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        WriteFieldChangeList(w, list);
        w.Flush();
        return System.Text.Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static List<FieldChange> DeserializeFieldChanges(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try { return ReadFieldChangeList(System.Text.Encoding.UTF8.GetBytes(json)); }
        catch { return new(); }
    }

    private static void WriteFieldChangeList(Utf8JsonWriter w, List<FieldChange> list)
    {
        w.WriteStartArray();
        foreach (var item in list)
        {
            w.WriteStartObject();
            w.WriteString("FieldName"u8, item.FieldName);
            if (item.OldValue != null) w.WriteString("OldValue"u8, item.OldValue); else w.WriteNull("OldValue"u8);
            if (item.NewValue != null) w.WriteString("NewValue"u8, item.NewValue); else w.WriteNull("NewValue"u8);
            w.WriteEndObject();
        }
        w.WriteEndArray();
    }

    private static List<FieldChange> ReadFieldChangeList(ReadOnlySpan<byte> utf8)
    {
        var list = new List<FieldChange>();
        var reader = new Utf8JsonReader(utf8);
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartArray) return list;
        while (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
        {
            string fieldName = "", oldValue = null!, newValue = null!;
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                if (reader.ValueTextEquals("FieldName"u8)) { reader.Read(); fieldName = reader.GetString() ?? ""; }
                else if (reader.ValueTextEquals("OldValue"u8)) { reader.Read(); oldValue = reader.TokenType == JsonTokenType.Null ? null! : reader.GetString()!; }
                else if (reader.ValueTextEquals("NewValue"u8)) { reader.Read(); newValue = reader.TokenType == JsonTokenType.Null ? null! : reader.GetString()!; }
                else { reader.Read(); reader.TrySkip(); }
            }
            list.Add(new FieldChange(fieldName, oldValue, newValue));
        }
        return list;
    }

    // ── DashboardTile ────────────────────────────────────────────────────────

    internal static string SerializeDashboardTiles(List<DashboardTile> list)
    {
        var buf = new ArrayBufferWriter<byte>(512);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartArray();
        foreach (var t in list)
        {
            w.WriteStartObject();
            w.WriteString("Title"u8, t.Title);
            w.WriteString("Icon"u8, t.Icon);
            w.WriteString("Color"u8, t.Color);
            w.WriteString("EntitySlug"u8, t.EntitySlug);
            w.WriteString("AggregateFunction"u8, t.AggregateFunction);
            w.WriteString("AggregateField"u8, t.AggregateField);
            w.WriteString("FilterField"u8, t.FilterField);
            w.WriteString("FilterValue"u8, t.FilterValue);
            w.WriteString("ValuePrefix"u8, t.ValuePrefix);
            w.WriteString("ValueSuffix"u8, t.ValueSuffix);
            w.WriteNumber("DecimalPlaces"u8, t.DecimalPlaces);
            w.WriteString("SparklineEntitySlug"u8, t.SparklineEntitySlug);
            w.WriteString("SparklineGroupField"u8, t.SparklineGroupField);
            w.WriteString("SparklineAggregateFunction"u8, t.SparklineAggregateFunction);
            w.WriteString("SparklineAggregateField"u8, t.SparklineAggregateField);
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.Flush();
        return System.Text.Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static List<DashboardTile> DeserializeDashboardTiles(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try
        {
            var list = new List<DashboardTile>();
            var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartArray) return list;
            while (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
            {
                var t = new DashboardTile();
                while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                {
                    if (reader.ValueTextEquals("Title"u8)) { reader.Read(); t.Title = reader.GetString() ?? ""; }
                    else if (reader.ValueTextEquals("Icon"u8)) { reader.Read(); t.Icon = reader.GetString() ?? "bi-bar-chart-fill"; }
                    else if (reader.ValueTextEquals("Color"u8)) { reader.Read(); t.Color = reader.GetString() ?? "primary"; }
                    else if (reader.ValueTextEquals("EntitySlug"u8)) { reader.Read(); t.EntitySlug = reader.GetString() ?? ""; }
                    else if (reader.ValueTextEquals("AggregateFunction"u8)) { reader.Read(); t.AggregateFunction = reader.GetString() ?? "count"; }
                    else if (reader.ValueTextEquals("AggregateField"u8)) { reader.Read(); t.AggregateField = reader.GetString() ?? ""; }
                    else if (reader.ValueTextEquals("FilterField"u8)) { reader.Read(); t.FilterField = reader.GetString() ?? ""; }
                    else if (reader.ValueTextEquals("FilterValue"u8)) { reader.Read(); t.FilterValue = reader.GetString() ?? ""; }
                    else if (reader.ValueTextEquals("ValuePrefix"u8)) { reader.Read(); t.ValuePrefix = reader.GetString() ?? ""; }
                    else if (reader.ValueTextEquals("ValueSuffix"u8)) { reader.Read(); t.ValueSuffix = reader.GetString() ?? ""; }
                    else if (reader.ValueTextEquals("DecimalPlaces"u8)) { reader.Read(); t.DecimalPlaces = reader.GetInt32(); }
                    else if (reader.ValueTextEquals("SparklineEntitySlug"u8)) { reader.Read(); t.SparklineEntitySlug = reader.GetString() ?? ""; }
                    else if (reader.ValueTextEquals("SparklineGroupField"u8)) { reader.Read(); t.SparklineGroupField = reader.GetString() ?? ""; }
                    else if (reader.ValueTextEquals("SparklineAggregateFunction"u8)) { reader.Read(); t.SparklineAggregateFunction = reader.GetString() ?? "count"; }
                    else if (reader.ValueTextEquals("SparklineAggregateField"u8)) { reader.Read(); t.SparklineAggregateField = reader.GetString() ?? ""; }
                    else { reader.Read(); reader.TrySkip(); }
                }
                list.Add(t);
            }
            return list;
        }
        catch { return new(); }
    }

    // ── ReportJoin ───────────────────────────────────────────────────────────

    internal static string SerializeReportJoins(List<ReportJoin> list)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartArray();
        foreach (var j in list)
        {
            w.WriteStartObject();
            w.WriteString("FromEntity"u8, j.FromEntity);
            w.WriteString("FromField"u8, j.FromField);
            w.WriteString("ToEntity"u8, j.ToEntity);
            w.WriteString("ToField"u8, j.ToField);
            w.WriteNumber("Type"u8, (int)j.Type);
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.Flush();
        return System.Text.Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static List<ReportJoin> DeserializeReportJoins(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try { return ReadList(json, ReadReportJoin); }
        catch { return new(); }
    }

    private static ReportJoin ReadReportJoin(ref Utf8JsonReader reader)
    {
        var j = new ReportJoin();
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            if (reader.ValueTextEquals("FromEntity"u8)) { reader.Read(); j.FromEntity = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("FromField"u8)) { reader.Read(); j.FromField = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("ToEntity"u8)) { reader.Read(); j.ToEntity = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("ToField"u8)) { reader.Read(); j.ToField = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Type"u8)) { reader.Read(); j.Type = (JoinType)reader.GetInt32(); }
            else { reader.Read(); reader.TrySkip(); }
        }
        return j;
    }

    // ── ReportColumn ─────────────────────────────────────────────────────────

    internal static string SerializeReportColumns(List<ReportColumn> list)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartArray();
        foreach (var c in list)
        {
            w.WriteStartObject();
            w.WriteString("Entity"u8, c.Entity);
            w.WriteString("Field"u8, c.Field);
            w.WriteString("Label"u8, c.Label);
            w.WriteString("Format"u8, c.Format);
            w.WriteNumber("Aggregate"u8, (int)c.Aggregate);
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.Flush();
        return System.Text.Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static List<ReportColumn> DeserializeReportColumns(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try { return ReadList(json, ReadReportColumn); }
        catch { return new(); }
    }

    private static ReportColumn ReadReportColumn(ref Utf8JsonReader reader)
    {
        var c = new ReportColumn();
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            if (reader.ValueTextEquals("Entity"u8)) { reader.Read(); c.Entity = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Field"u8)) { reader.Read(); c.Field = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Label"u8)) { reader.Read(); c.Label = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Format"u8)) { reader.Read(); c.Format = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Aggregate"u8)) { reader.Read(); c.Aggregate = (AggregateFunction)reader.GetInt32(); }
            else { reader.Read(); reader.TrySkip(); }
        }
        return c;
    }

    // ── ReportFilter ─────────────────────────────────────────────────────────

    internal static string SerializeReportFilters(List<ReportFilter> list)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartArray();
        foreach (var f in list)
        {
            w.WriteStartObject();
            w.WriteString("Entity"u8, f.Entity);
            w.WriteString("Field"u8, f.Field);
            w.WriteString("Operator"u8, f.Operator);
            w.WriteString("Value"u8, f.Value);
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.Flush();
        return System.Text.Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static List<ReportFilter> DeserializeReportFilters(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try { return ReadList(json, ReadReportFilter); }
        catch { return new(); }
    }

    private static ReportFilter ReadReportFilter(ref Utf8JsonReader reader)
    {
        var f = new ReportFilter();
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            if (reader.ValueTextEquals("Entity"u8)) { reader.Read(); f.Entity = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Field"u8)) { reader.Read(); f.Field = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Operator"u8)) { reader.Read(); f.Operator = reader.GetString() ?? "="; }
            else if (reader.ValueTextEquals("Value"u8)) { reader.Read(); f.Value = reader.GetString() ?? ""; }
            else { reader.Read(); reader.TrySkip(); }
        }
        return f;
    }

    // ── ReportParameter ──────────────────────────────────────────────────────

    internal static string SerializeReportParameters(List<ReportParameter> list)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartArray();
        foreach (var p in list)
        {
            w.WriteStartObject();
            w.WriteString("Name"u8, p.Name);
            w.WriteString("Label"u8, p.Label);
            w.WriteString("Type"u8, p.Type);
            w.WriteString("DefaultValue"u8, p.DefaultValue);
            if (p.Options != null)
            {
                w.WriteStartArray("Options"u8);
                foreach (var o in p.Options) w.WriteStringValue(o);
                w.WriteEndArray();
            }
            if (p.FieldSource != null) w.WriteString("FieldSource"u8, p.FieldSource);
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.Flush();
        return System.Text.Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static List<ReportParameter> DeserializeReportParameters(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try { return ReadList(json, ReadReportParameter); }
        catch { return new(); }
    }

    private static ReportParameter ReadReportParameter(ref Utf8JsonReader reader)
    {
        var p = new ReportParameter();
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            if (reader.ValueTextEquals("Name"u8)) { reader.Read(); p.Name = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Label"u8)) { reader.Read(); p.Label = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Type"u8)) { reader.Read(); p.Type = reader.GetString() ?? "string"; }
            else if (reader.ValueTextEquals("DefaultValue"u8)) { reader.Read(); p.DefaultValue = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("FieldSource"u8)) { reader.Read(); p.FieldSource = reader.GetString(); }
            else if (reader.ValueTextEquals("Options"u8))
            {
                reader.Read(); // StartArray
                p.Options = new List<string>();
                while (reader.Read() && reader.TokenType == JsonTokenType.String)
                    p.Options.Add(reader.GetString() ?? "");
            }
            else { reader.Read(); reader.TrySkip(); }
        }
        return p;
    }

    // ── ViewProjection ───────────────────────────────────────────────────────

    internal static string SerializeViewProjections(List<ViewProjection> list)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartArray();
        foreach (var p in list)
        {
            w.WriteStartObject();
            w.WriteString("Entity"u8, p.Entity);
            w.WriteString("Field"u8, p.Field);
            w.WriteString("Alias"u8, p.Alias);
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.Flush();
        return System.Text.Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static List<ViewProjection> DeserializeViewProjections(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try { return ReadList(json, ReadViewProjection); }
        catch { return new(); }
    }

    private static ViewProjection ReadViewProjection(ref Utf8JsonReader reader)
    {
        var p = new ViewProjection();
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            if (reader.ValueTextEquals("Entity"u8)) { reader.Read(); p.Entity = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Field"u8)) { reader.Read(); p.Field = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Alias"u8)) { reader.Read(); p.Alias = reader.GetString() ?? ""; }
            else { reader.Read(); reader.TrySkip(); }
        }
        return p;
    }

    // ── ViewJoinDefinition ───────────────────────────────────────────────────

    internal static string SerializeViewJoins(List<ViewJoinDefinition> list)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartArray();
        foreach (var j in list)
        {
            w.WriteStartObject();
            w.WriteString("SourceEntity"u8, j.SourceEntity);
            w.WriteString("SourceField"u8, j.SourceField);
            w.WriteString("TargetEntity"u8, j.TargetEntity);
            w.WriteString("TargetField"u8, j.TargetField);
            w.WriteNumber("Type"u8, (int)j.Type);
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.Flush();
        return System.Text.Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static List<ViewJoinDefinition> DeserializeViewJoins(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try { return ReadList(json, ReadViewJoin); }
        catch { return new(); }
    }

    private static ViewJoinDefinition ReadViewJoin(ref Utf8JsonReader reader)
    {
        var j = new ViewJoinDefinition();
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            if (reader.ValueTextEquals("SourceEntity"u8)) { reader.Read(); j.SourceEntity = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("SourceField"u8)) { reader.Read(); j.SourceField = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("TargetEntity"u8)) { reader.Read(); j.TargetEntity = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("TargetField"u8)) { reader.Read(); j.TargetField = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Type"u8)) { reader.Read(); j.Type = (JoinType)reader.GetInt32(); }
            else { reader.Read(); reader.TrySkip(); }
        }
        return j;
    }

    // ── ViewFilterDefinition ─────────────────────────────────────────────────

    internal static string SerializeViewFilters(List<ViewFilterDefinition> list)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartArray();
        foreach (var f in list)
        {
            w.WriteStartObject();
            w.WriteString("Entity"u8, f.Entity);
            w.WriteString("Field"u8, f.Field);
            w.WriteString("Operator"u8, f.Operator);
            w.WriteString("Value"u8, f.Value);
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.Flush();
        return System.Text.Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static List<ViewFilterDefinition> DeserializeViewFilters(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try { return ReadList(json, ReadViewFilter); }
        catch { return new(); }
    }

    private static ViewFilterDefinition ReadViewFilter(ref Utf8JsonReader reader)
    {
        var f = new ViewFilterDefinition();
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            if (reader.ValueTextEquals("Entity"u8)) { reader.Read(); f.Entity = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Field"u8)) { reader.Read(); f.Field = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Operator"u8)) { reader.Read(); f.Operator = reader.GetString() ?? "="; }
            else if (reader.ValueTextEquals("Value"u8)) { reader.Read(); f.Value = reader.GetString() ?? ""; }
            else { reader.Read(); reader.TrySkip(); }
        }
        return f;
    }

    // ── ViewSortDefinition ───────────────────────────────────────────────────

    internal static string SerializeViewSorts(List<ViewSortDefinition> list)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartArray();
        foreach (var s in list)
        {
            w.WriteStartObject();
            w.WriteString("Entity"u8, s.Entity);
            w.WriteString("Field"u8, s.Field);
            w.WriteBoolean("Descending"u8, s.Descending);
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.Flush();
        return System.Text.Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static List<ViewSortDefinition> DeserializeViewSorts(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try { return ReadList(json, ReadViewSort); }
        catch { return new(); }
    }

    private static ViewSortDefinition ReadViewSort(ref Utf8JsonReader reader)
    {
        var s = new ViewSortDefinition();
        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
        {
            if (reader.ValueTextEquals("Entity"u8)) { reader.Read(); s.Entity = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Field"u8)) { reader.Read(); s.Field = reader.GetString() ?? ""; }
            else if (reader.ValueTextEquals("Descending"u8)) { reader.Read(); s.Descending = reader.GetBoolean(); }
            else { reader.Read(); reader.TrySkip(); }
        }
        return s;
    }

    // ── SchemaDefinitionFile (WAL) ───────────────────────────────────────────

    internal static byte[] SerializeSchemaFile(SchemaDefinitionFile schema)
    {
        var buf = new ArrayBufferWriter<byte>(512);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        w.WriteNumber("Version"u8, schema.Version);
        w.WriteNumber("Hash"u8, schema.Hash);
        if (schema.Architecture != null) w.WriteString("Architecture"u8, schema.Architecture);
        w.WriteStartArray("Members"u8);
        foreach (var m in schema.Members)
        {
            w.WriteStartObject();
            w.WriteString("Name"u8, m.Name);
            w.WriteString("TypeName"u8, m.TypeName);
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.WriteEndObject();
        w.Flush();
        return buf.WrittenSpan.ToArray();
    }

    internal static SchemaDefinitionFile? DeserializeSchemaFile(ReadOnlySpan<byte> utf8)
    {
        try
        {
            var file = new SchemaDefinitionFile();
            var reader = new Utf8JsonReader(utf8);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) return null;
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                if (reader.ValueTextEquals("Version"u8)) { reader.Read(); file.Version = reader.GetInt32(); }
                else if (reader.ValueTextEquals("Hash"u8)) { reader.Read(); file.Hash = reader.GetUInt32(); }
                else if (reader.ValueTextEquals("Architecture"u8)) { reader.Read(); file.Architecture = reader.GetString(); }
                else if (reader.ValueTextEquals("Members"u8))
                {
                    reader.Read(); // StartArray
                    while (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
                    {
                        var m = new MemberSignatureFile();
                        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                        {
                            if (reader.ValueTextEquals("Name"u8)) { reader.Read(); m.Name = reader.GetString() ?? ""; }
                            else if (reader.ValueTextEquals("TypeName"u8)) { reader.Read(); m.TypeName = reader.GetString() ?? ""; }
                            else { reader.Read(); reader.TrySkip(); }
                        }
                        file.Members.Add(m);
                    }
                }
                else { reader.Read(); reader.TrySkip(); }
            }
            return file;
        }
        catch { return null; }
    }

    // ── Shared reader helper ─────────────────────────────────────────────────

    private delegate T ItemReader<T>(ref Utf8JsonReader reader);

    private static List<T> ReadList<T>(string json, ItemReader<T> readItem)
    {
        var list = new List<T>();
        var reader = new Utf8JsonReader(System.Text.Encoding.UTF8.GetBytes(json));
        if (!reader.Read() || reader.TokenType != JsonTokenType.StartArray) return list;
        while (reader.Read() && reader.TokenType == JsonTokenType.StartObject)
            list.Add(readItem(ref reader));
        return list;
    }
}
