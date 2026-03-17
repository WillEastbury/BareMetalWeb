using System.Text;
using System.Text.Json;

namespace BareMetalWeb.Data;

/// <summary>
/// AOT/trim-safe JSON serialization helpers that replace System.Text.Json.JsonSerializer
/// with Utf8JsonWriter (write) and JsonDocument/JsonElement (read).
/// No source-generated contexts, no reflection, no dynamic code generation.
/// </summary>
internal static class ManualJsonHelper
{
    // ────────────── Generic list helpers ──────────────

    internal static string SerializeList<T>(List<T> list, Action<Utf8JsonWriter, T> writeItem)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartArray();
            foreach (var item in list)
                writeItem(w, item);
            w.WriteEndArray();
        }
        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    internal static List<T> DeserializeList<T>(string json, Func<JsonElement, T> readItem)
    {
        if (string.IsNullOrWhiteSpace(json)) return new List<T>();
        using var doc = JsonDocument.Parse(json);
        var list = new List<T>();
        foreach (var el in doc.RootElement.EnumerateArray())
            list.Add(readItem(el));
        return list;
    }

    internal static string SerializeObject<T>(T obj, Action<Utf8JsonWriter, T> writeItem)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            writeItem(w, obj);
        }
        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    internal static byte[] SerializeObjectToUtf8<T>(T obj, Action<Utf8JsonWriter, T> writeItem)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            writeItem(w, obj);
        }
        return buffer.ToArray();
    }

    internal static T? DeserializeObject<T>(string json, Func<JsonElement, T> readItem)
    {
        if (string.IsNullOrWhiteSpace(json)) return default;
        using var doc = JsonDocument.Parse(json);
        return readItem(doc.RootElement);
    }

    internal static T? DeserializeObject<T>(ReadOnlySpan<byte> utf8Json, Func<JsonElement, T> readItem)
    {
        if (utf8Json.IsEmpty) return default;
        using var doc = JsonDocument.Parse(utf8Json.ToArray().AsMemory());
        return readItem(doc.RootElement);
    }

    // ────────────── FieldChange ──────────────

    internal static void WriteFieldChange(Utf8JsonWriter w, FieldChange fc)
    {
        w.WriteStartObject();
        w.WriteString("FieldName", fc.FieldName);
        if (fc.OldValue is not null) w.WriteString("OldValue", fc.OldValue);
        if (fc.NewValue is not null) w.WriteString("NewValue", fc.NewValue);
        w.WriteEndObject();
    }

    internal static FieldChange ReadFieldChange(JsonElement el)
    {
        var fc = new FieldChange();
        foreach (var prop in el.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "FieldName": fc.FieldName = prop.Value.GetString() ?? string.Empty; break;
                case "OldValue": fc.OldValue = prop.Value.ValueKind == JsonValueKind.Null ? null : prop.Value.GetString(); break;
                case "NewValue": fc.NewValue = prop.Value.ValueKind == JsonValueKind.Null ? null : prop.Value.GetString(); break;
            }
        }
        return fc;
    }

    // ────────────── ReportJoin ──────────────

    internal static void WriteReportJoin(Utf8JsonWriter w, ReportJoin rj)
    {
        w.WriteStartObject();
        w.WriteString("FromEntity", rj.FromEntity);
        w.WriteString("FromField", rj.FromField);
        w.WriteString("ToEntity", rj.ToEntity);
        w.WriteString("ToField", rj.ToField);
        w.WriteNumber("Type", (int)rj.Type);
        w.WriteEndObject();
    }

    internal static ReportJoin ReadReportJoin(JsonElement el)
    {
        var rj = new ReportJoin();
        foreach (var prop in el.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "FromEntity": rj.FromEntity = prop.Value.GetString() ?? string.Empty; break;
                case "FromField": rj.FromField = prop.Value.GetString() ?? string.Empty; break;
                case "ToEntity": rj.ToEntity = prop.Value.GetString() ?? string.Empty; break;
                case "ToField": rj.ToField = prop.Value.GetString() ?? string.Empty; break;
                case "Type": rj.Type = (JoinType)prop.Value.GetInt32(); break;
            }
        }
        return rj;
    }

    // ────────────── ReportColumn ──────────────

    internal static void WriteReportColumn(Utf8JsonWriter w, ReportColumn rc)
    {
        w.WriteStartObject();
        w.WriteString("Entity", rc.Entity);
        w.WriteString("Field", rc.Field);
        w.WriteString("Label", rc.Label);
        w.WriteString("Format", rc.Format);
        w.WriteNumber("Aggregate", (int)rc.Aggregate);
        w.WriteEndObject();
    }

    internal static ReportColumn ReadReportColumn(JsonElement el)
    {
        var rc = new ReportColumn();
        foreach (var prop in el.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "Entity": rc.Entity = prop.Value.GetString() ?? string.Empty; break;
                case "Field": rc.Field = prop.Value.GetString() ?? string.Empty; break;
                case "Label": rc.Label = prop.Value.GetString() ?? string.Empty; break;
                case "Format": rc.Format = prop.Value.GetString() ?? string.Empty; break;
                case "Aggregate": rc.Aggregate = (AggregateFunction)prop.Value.GetInt32(); break;
            }
        }
        return rc;
    }

    // ────────────── ReportFilter ──────────────

    internal static void WriteReportFilter(Utf8JsonWriter w, ReportFilter rf)
    {
        w.WriteStartObject();
        w.WriteString("Entity", rf.Entity);
        w.WriteString("Field", rf.Field);
        w.WriteString("Operator", rf.Operator);
        w.WriteString("Value", rf.Value);
        w.WriteEndObject();
    }

    internal static ReportFilter ReadReportFilter(JsonElement el)
    {
        var rf = new ReportFilter();
        foreach (var prop in el.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "Entity": rf.Entity = prop.Value.GetString() ?? string.Empty; break;
                case "Field": rf.Field = prop.Value.GetString() ?? string.Empty; break;
                case "Operator": rf.Operator = prop.Value.GetString() ?? "="; break;
                case "Value": rf.Value = prop.Value.GetString() ?? string.Empty; break;
            }
        }
        return rf;
    }

    // ────────────── ReportParameter ──────────────

    internal static void WriteReportParameter(Utf8JsonWriter w, ReportParameter rp)
    {
        w.WriteStartObject();
        w.WriteString("Name", rp.Name);
        w.WriteString("Label", rp.Label);
        w.WriteString("Type", rp.Type);
        w.WriteString("DefaultValue", rp.DefaultValue);
        if (rp.Options is not null)
        {
            w.WriteStartArray("Options");
            foreach (var o in rp.Options) w.WriteStringValue(o);
            w.WriteEndArray();
        }
        if (rp.FieldSource is not null) w.WriteString("FieldSource", rp.FieldSource);
        w.WriteEndObject();
    }

    internal static ReportParameter ReadReportParameter(JsonElement el)
    {
        var rp = new ReportParameter();
        foreach (var prop in el.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "Name": rp.Name = prop.Value.GetString() ?? string.Empty; break;
                case "Label": rp.Label = prop.Value.GetString() ?? string.Empty; break;
                case "Type": rp.Type = prop.Value.GetString() ?? "string"; break;
                case "DefaultValue": rp.DefaultValue = prop.Value.GetString() ?? string.Empty; break;
                case "Options":
                    if (prop.Value.ValueKind == JsonValueKind.Array)
                    {
                        rp.Options = new List<string>();
                        foreach (var item in prop.Value.EnumerateArray())
                            rp.Options.Add(item.GetString() ?? string.Empty);
                    }
                    break;
                case "FieldSource": rp.FieldSource = prop.Value.ValueKind == JsonValueKind.Null ? null : prop.Value.GetString(); break;
            }
        }
        return rp;
    }

    // ────────────── ViewProjection ──────────────

    internal static void WriteViewProjection(Utf8JsonWriter w, ViewProjection vp)
    {
        w.WriteStartObject();
        w.WriteString("Entity", vp.Entity);
        w.WriteString("Field", vp.Field);
        w.WriteString("Alias", vp.Alias);
        w.WriteEndObject();
    }

    internal static ViewProjection ReadViewProjection(JsonElement el)
    {
        var vp = new ViewProjection();
        foreach (var prop in el.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "Entity": vp.Entity = prop.Value.GetString() ?? string.Empty; break;
                case "Field": vp.Field = prop.Value.GetString() ?? string.Empty; break;
                case "Alias": vp.Alias = prop.Value.GetString() ?? string.Empty; break;
            }
        }
        return vp;
    }

    // ────────────── ViewJoinDefinition ──────────────

    internal static void WriteViewJoinDefinition(Utf8JsonWriter w, ViewJoinDefinition vj)
    {
        w.WriteStartObject();
        w.WriteString("SourceEntity", vj.SourceEntity);
        w.WriteString("SourceField", vj.SourceField);
        w.WriteString("TargetEntity", vj.TargetEntity);
        w.WriteString("TargetField", vj.TargetField);
        w.WriteNumber("Type", (int)vj.Type);
        w.WriteEndObject();
    }

    internal static ViewJoinDefinition ReadViewJoinDefinition(JsonElement el)
    {
        var vj = new ViewJoinDefinition();
        foreach (var prop in el.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "SourceEntity": vj.SourceEntity = prop.Value.GetString() ?? string.Empty; break;
                case "SourceField": vj.SourceField = prop.Value.GetString() ?? string.Empty; break;
                case "TargetEntity": vj.TargetEntity = prop.Value.GetString() ?? string.Empty; break;
                case "TargetField": vj.TargetField = prop.Value.GetString() ?? string.Empty; break;
                case "Type": vj.Type = (JoinType)prop.Value.GetInt32(); break;
            }
        }
        return vj;
    }

    // ────────────── ViewFilterDefinition ──────────────

    internal static void WriteViewFilterDefinition(Utf8JsonWriter w, ViewFilterDefinition vf)
    {
        w.WriteStartObject();
        w.WriteString("Entity", vf.Entity);
        w.WriteString("Field", vf.Field);
        w.WriteString("Operator", vf.Operator);
        w.WriteString("Value", vf.Value);
        w.WriteEndObject();
    }

    internal static ViewFilterDefinition ReadViewFilterDefinition(JsonElement el)
    {
        var vf = new ViewFilterDefinition();
        foreach (var prop in el.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "Entity": vf.Entity = prop.Value.GetString() ?? string.Empty; break;
                case "Field": vf.Field = prop.Value.GetString() ?? string.Empty; break;
                case "Operator": vf.Operator = prop.Value.GetString() ?? "="; break;
                case "Value": vf.Value = prop.Value.GetString() ?? string.Empty; break;
            }
        }
        return vf;
    }

    // ────────────── ViewSortDefinition ──────────────

    internal static void WriteViewSortDefinition(Utf8JsonWriter w, ViewSortDefinition vs)
    {
        w.WriteStartObject();
        w.WriteString("Entity", vs.Entity);
        w.WriteString("Field", vs.Field);
        w.WriteBoolean("Descending", vs.Descending);
        w.WriteEndObject();
    }

    internal static ViewSortDefinition ReadViewSortDefinition(JsonElement el)
    {
        var vs = new ViewSortDefinition();
        foreach (var prop in el.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "Entity": vs.Entity = prop.Value.GetString() ?? string.Empty; break;
                case "Field": vs.Field = prop.Value.GetString() ?? string.Empty; break;
                case "Descending": vs.Descending = prop.Value.GetBoolean(); break;
            }
        }
        return vs;
    }

    // ────────────── DashboardTile ──────────────

    internal static void WriteDashboardTile(Utf8JsonWriter w, DashboardTile dt)
    {
        w.WriteStartObject();
        w.WriteString("Title", dt.Title);
        w.WriteString("Icon", dt.Icon);
        w.WriteString("Color", dt.Color);
        w.WriteString("EntitySlug", dt.EntitySlug);
        w.WriteString("AggregateFunction", dt.AggregateFunction);
        w.WriteString("AggregateField", dt.AggregateField);
        w.WriteString("FilterField", dt.FilterField);
        w.WriteString("FilterValue", dt.FilterValue);
        w.WriteString("ValuePrefix", dt.ValuePrefix);
        w.WriteString("ValueSuffix", dt.ValueSuffix);
        w.WriteNumber("DecimalPlaces", dt.DecimalPlaces);
        w.WriteString("SparklineEntitySlug", dt.SparklineEntitySlug);
        w.WriteString("SparklineGroupField", dt.SparklineGroupField);
        w.WriteString("SparklineAggregateFunction", dt.SparklineAggregateFunction);
        w.WriteString("SparklineAggregateField", dt.SparklineAggregateField);
        w.WriteEndObject();
    }

    internal static DashboardTile ReadDashboardTile(JsonElement el)
    {
        var dt = new DashboardTile();
        foreach (var prop in el.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "Title": dt.Title = prop.Value.GetString() ?? string.Empty; break;
                case "Icon": dt.Icon = prop.Value.GetString() ?? "bi-bar-chart-fill"; break;
                case "Color": dt.Color = prop.Value.GetString() ?? "primary"; break;
                case "EntitySlug": dt.EntitySlug = prop.Value.GetString() ?? string.Empty; break;
                case "AggregateFunction": dt.AggregateFunction = prop.Value.GetString() ?? "count"; break;
                case "AggregateField": dt.AggregateField = prop.Value.GetString() ?? string.Empty; break;
                case "FilterField": dt.FilterField = prop.Value.GetString() ?? string.Empty; break;
                case "FilterValue": dt.FilterValue = prop.Value.GetString() ?? string.Empty; break;
                case "ValuePrefix": dt.ValuePrefix = prop.Value.GetString() ?? string.Empty; break;
                case "ValueSuffix": dt.ValueSuffix = prop.Value.GetString() ?? string.Empty; break;
                case "DecimalPlaces": dt.DecimalPlaces = prop.Value.GetInt32(); break;
                case "SparklineEntitySlug": dt.SparklineEntitySlug = prop.Value.GetString() ?? string.Empty; break;
                case "SparklineGroupField": dt.SparklineGroupField = prop.Value.GetString() ?? string.Empty; break;
                case "SparklineAggregateFunction": dt.SparklineAggregateFunction = prop.Value.GetString() ?? "count"; break;
                case "SparklineAggregateField": dt.SparklineAggregateField = prop.Value.GetString() ?? string.Empty; break;
            }
        }
        return dt;
    }

    // ────────────── SchemaDefinitionFile ──────────────

    internal static void WriteSchemaDefinitionFile(Utf8JsonWriter w, SchemaDefinitionFile sdf)
    {
        w.WriteStartObject();
        w.WriteNumber("Version", sdf.Version);
        w.WriteNumber("Hash", sdf.Hash);
        if (sdf.Architecture is not null) w.WriteString("Architecture", sdf.Architecture);
        w.WriteStartArray("Members");
        foreach (var m in sdf.Members)
            WriteMemberSignatureFile(w, m);
        w.WriteEndArray();
        w.WriteEndObject();
    }

    internal static SchemaDefinitionFile ReadSchemaDefinitionFile(JsonElement el)
    {
        var sdf = new SchemaDefinitionFile();
        foreach (var prop in el.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "Version": sdf.Version = prop.Value.GetInt32(); break;
                case "Hash": sdf.Hash = prop.Value.GetUInt32(); break;
                case "Architecture": sdf.Architecture = prop.Value.ValueKind == JsonValueKind.Null ? null : prop.Value.GetString(); break;
                case "Members":
                    sdf.Members = new List<MemberSignatureFile>();
                    foreach (var item in prop.Value.EnumerateArray())
                        sdf.Members.Add(ReadMemberSignatureFile(item));
                    break;
            }
        }
        return sdf;
    }

    // ────────────── MemberSignatureFile ──────────────

    internal static void WriteMemberSignatureFile(Utf8JsonWriter w, MemberSignatureFile msf)
    {
        w.WriteStartObject();
        w.WriteString("Name", msf.Name);
        w.WriteString("TypeName", msf.TypeName);
        if (msf.BlittableSize is not null) w.WriteNumber("BlittableSize", msf.BlittableSize.Value);
        w.WriteEndObject();
    }

    internal static MemberSignatureFile ReadMemberSignatureFile(JsonElement el)
    {
        var msf = new MemberSignatureFile();
        foreach (var prop in el.EnumerateObject())
        {
            switch (prop.Name)
            {
                case "Name": msf.Name = prop.Value.GetString() ?? string.Empty; break;
                case "TypeName": msf.TypeName = prop.Value.GetString() ?? string.Empty; break;
                case "BlittableSize": msf.BlittableSize = prop.Value.ValueKind == JsonValueKind.Null ? null : prop.Value.GetInt32(); break;
            }
        }
        return msf;
    }

    // ────────────── Dictionary helpers ──────────────

    internal static string SerializeDictStringString(Dictionary<string, string> dict)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();
            foreach (var kvp in dict)
                w.WriteString(kvp.Key, kvp.Value);
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    internal static byte[] SerializeDictStringStringToUtf8(Dictionary<string, string> dict)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartObject();
            foreach (var kvp in dict)
                w.WriteString(kvp.Key, kvp.Value);
            w.WriteEndObject();
        }
        return buffer.ToArray();
    }

    /// <summary>
    /// Parses a JSON string to a Dictionary&lt;string, JsonElement&gt; using JsonDocument,
    /// replacing JsonSerializer.Deserialize&lt;Dictionary&lt;string, JsonElement&gt;&gt;.
    /// The returned dictionary clones each JsonElement so it remains valid after the
    /// JsonDocument is disposed.
    /// </summary>
    internal static Dictionary<string, JsonElement> ParseJsonElementDict(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var dict = new Dictionary<string, JsonElement>();
        foreach (var prop in doc.RootElement.EnumerateObject())
            dict[prop.Name] = prop.Value.Clone();
        return dict;
    }
}
