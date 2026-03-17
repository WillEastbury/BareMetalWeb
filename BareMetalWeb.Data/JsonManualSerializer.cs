using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace BareMetalWeb.Data;

/// <summary>
/// Manual Utf8JsonWriter/Utf8JsonReader serialization helpers — no JsonSerializer dependency.
/// </summary>
internal static class JsonManualSerializer
{
    // ── Generic list helpers ─────────────────────────────────────────────────

    internal static string SerializeList<T>(List<T> items, Action<Utf8JsonWriter, T> writeItem)
    {
        var buffer = new ArrayBufferWriter<byte>(256);
        using var writer = new Utf8JsonWriter(buffer);
        writer.WriteStartArray();
        foreach (var item in items)
            writeItem(writer, item);
        writer.WriteEndArray();
        writer.Flush();
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    internal static List<T> DeserializeList<T>(string? json, ReadItem<T> readItem) where T : new()
    {
        if (string.IsNullOrWhiteSpace(json)) return new List<T>();
        try
        {
            var bytes = Encoding.UTF8.GetBytes(json);
            var reader = new Utf8JsonReader(bytes);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartArray)
                return new List<T>();

            var list = new List<T>();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndArray) break;
                if (reader.TokenType == JsonTokenType.StartObject)
                    list.Add(readItem(ref reader));
            }
            return list;
        }
        catch
        {
            return new List<T>();
        }
    }

    internal delegate T ReadItem<T>(ref Utf8JsonReader reader);

    // ── FieldChange ──────────────────────────────────────────────────────────

    internal static void WriteFieldChange(Utf8JsonWriter w, FieldChange fc)
    {
        w.WriteStartObject();
        w.WriteString("FieldName"u8, fc.FieldName);
        if (fc.OldValue is not null)
            w.WriteString("OldValue"u8, fc.OldValue);
        else
            w.WriteNull("OldValue"u8);
        if (fc.NewValue is not null)
            w.WriteString("NewValue"u8, fc.NewValue);
        else
            w.WriteNull("NewValue"u8);
        w.WriteEndObject();
    }

    internal static FieldChange ReadFieldChange(ref Utf8JsonReader r)
    {
        var fc = new FieldChange();
        while (r.Read())
        {
            if (r.TokenType == JsonTokenType.EndObject) break;
            if (r.TokenType == JsonTokenType.PropertyName)
            {
                var prop = r.GetString();
                r.Read();
                switch (prop)
                {
                    case "FieldName": fc.FieldName = r.GetString() ?? string.Empty; break;
                    case "OldValue": fc.OldValue = r.TokenType == JsonTokenType.Null ? null : r.GetString(); break;
                    case "NewValue": fc.NewValue = r.TokenType == JsonTokenType.Null ? null : r.GetString(); break;
                }
            }
        }
        return fc;
    }

    internal static string SerializeFieldChanges(List<FieldChange> items) =>
        SerializeList(items, WriteFieldChange);

    internal static List<FieldChange> DeserializeFieldChanges(string? json) =>
        DeserializeList(json, ReadFieldChange);

    // ── DashboardTile ────────────────────────────────────────────────────────

    internal static void WriteDashboardTile(Utf8JsonWriter w, DashboardTile t)
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

    internal static DashboardTile ReadDashboardTile(ref Utf8JsonReader r)
    {
        var t = new DashboardTile();
        while (r.Read())
        {
            if (r.TokenType == JsonTokenType.EndObject) break;
            if (r.TokenType == JsonTokenType.PropertyName)
            {
                var prop = r.GetString();
                r.Read();
                switch (prop)
                {
                    case "Title": t.Title = r.GetString() ?? string.Empty; break;
                    case "Icon": t.Icon = r.GetString() ?? "bi-bar-chart-fill"; break;
                    case "Color": t.Color = r.GetString() ?? "primary"; break;
                    case "EntitySlug": t.EntitySlug = r.GetString() ?? string.Empty; break;
                    case "AggregateFunction": t.AggregateFunction = r.GetString() ?? "count"; break;
                    case "AggregateField": t.AggregateField = r.GetString() ?? string.Empty; break;
                    case "FilterField": t.FilterField = r.GetString() ?? string.Empty; break;
                    case "FilterValue": t.FilterValue = r.GetString() ?? string.Empty; break;
                    case "ValuePrefix": t.ValuePrefix = r.GetString() ?? string.Empty; break;
                    case "ValueSuffix": t.ValueSuffix = r.GetString() ?? string.Empty; break;
                    case "DecimalPlaces": t.DecimalPlaces = r.GetInt32(); break;
                    case "SparklineEntitySlug": t.SparklineEntitySlug = r.GetString() ?? string.Empty; break;
                    case "SparklineGroupField": t.SparklineGroupField = r.GetString() ?? string.Empty; break;
                    case "SparklineAggregateFunction": t.SparklineAggregateFunction = r.GetString() ?? "count"; break;
                    case "SparklineAggregateField": t.SparklineAggregateField = r.GetString() ?? string.Empty; break;
                }
            }
        }
        return t;
    }

    internal static string SerializeDashboardTiles(List<DashboardTile> items) =>
        SerializeList(items, WriteDashboardTile);

    internal static List<DashboardTile> DeserializeDashboardTiles(string? json) =>
        DeserializeList(json, ReadDashboardTile);

    // ── ReportJoin ───────────────────────────────────────────────────────────

    internal static void WriteReportJoin(Utf8JsonWriter w, ReportJoin j)
    {
        w.WriteStartObject();
        w.WriteString("FromEntity"u8, j.FromEntity);
        w.WriteString("FromField"u8, j.FromField);
        w.WriteString("ToEntity"u8, j.ToEntity);
        w.WriteString("ToField"u8, j.ToField);
        w.WriteString("Type"u8, j.Type.ToString());
        w.WriteEndObject();
    }

    internal static ReportJoin ReadReportJoin(ref Utf8JsonReader r)
    {
        var j = new ReportJoin();
        while (r.Read())
        {
            if (r.TokenType == JsonTokenType.EndObject) break;
            if (r.TokenType == JsonTokenType.PropertyName)
            {
                var prop = r.GetString();
                r.Read();
                switch (prop)
                {
                    case "FromEntity": j.FromEntity = r.GetString() ?? string.Empty; break;
                    case "FromField": j.FromField = r.GetString() ?? string.Empty; break;
                    case "ToEntity": j.ToEntity = r.GetString() ?? string.Empty; break;
                    case "ToField": j.ToField = r.GetString() ?? string.Empty; break;
                    case "Type":
                        if (r.TokenType == JsonTokenType.String)
                        { if (Enum.TryParse<JoinType>(r.GetString(), out var jt)) j.Type = jt; }
                        else if (r.TokenType == JsonTokenType.Number)
                            j.Type = (JoinType)r.GetInt32();
                        break;
                }
            }
        }
        return j;
    }

    internal static string SerializeReportJoins(List<ReportJoin> items) =>
        SerializeList(items, WriteReportJoin);

    internal static List<ReportJoin> DeserializeReportJoins(string? json) =>
        DeserializeList(json, ReadReportJoin);

    // ── ReportColumn ─────────────────────────────────────────────────────────

    internal static void WriteReportColumn(Utf8JsonWriter w, ReportColumn c)
    {
        w.WriteStartObject();
        w.WriteString("Entity"u8, c.Entity);
        w.WriteString("Field"u8, c.Field);
        w.WriteString("Label"u8, c.Label);
        w.WriteString("Format"u8, c.Format);
        w.WriteString("Aggregate"u8, c.Aggregate.ToString());
        w.WriteEndObject();
    }

    internal static ReportColumn ReadReportColumn(ref Utf8JsonReader r)
    {
        var c = new ReportColumn();
        while (r.Read())
        {
            if (r.TokenType == JsonTokenType.EndObject) break;
            if (r.TokenType == JsonTokenType.PropertyName)
            {
                var prop = r.GetString();
                r.Read();
                switch (prop)
                {
                    case "Entity": c.Entity = r.GetString() ?? string.Empty; break;
                    case "Field": c.Field = r.GetString() ?? string.Empty; break;
                    case "Label": c.Label = r.GetString() ?? string.Empty; break;
                    case "Format": c.Format = r.GetString() ?? string.Empty; break;
                    case "Aggregate":
                        if (r.TokenType == JsonTokenType.String)
                        { if (Enum.TryParse<AggregateFunction>(r.GetString(), out var af)) c.Aggregate = af; }
                        else if (r.TokenType == JsonTokenType.Number)
                            c.Aggregate = (AggregateFunction)r.GetInt32();
                        break;
                }
            }
        }
        return c;
    }

    internal static string SerializeReportColumns(List<ReportColumn> items) =>
        SerializeList(items, WriteReportColumn);

    internal static List<ReportColumn> DeserializeReportColumns(string? json) =>
        DeserializeList(json, ReadReportColumn);

    // ── ReportFilter ─────────────────────────────────────────────────────────

    internal static void WriteReportFilter(Utf8JsonWriter w, ReportFilter f)
    {
        w.WriteStartObject();
        w.WriteString("Entity"u8, f.Entity);
        w.WriteString("Field"u8, f.Field);
        w.WriteString("Operator"u8, f.Operator);
        w.WriteString("Value"u8, f.Value);
        w.WriteEndObject();
    }

    internal static ReportFilter ReadReportFilter(ref Utf8JsonReader r)
    {
        var f = new ReportFilter();
        while (r.Read())
        {
            if (r.TokenType == JsonTokenType.EndObject) break;
            if (r.TokenType == JsonTokenType.PropertyName)
            {
                var prop = r.GetString();
                r.Read();
                switch (prop)
                {
                    case "Entity": f.Entity = r.GetString() ?? string.Empty; break;
                    case "Field": f.Field = r.GetString() ?? string.Empty; break;
                    case "Operator": f.Operator = r.GetString() ?? "="; break;
                    case "Value": f.Value = r.GetString() ?? string.Empty; break;
                }
            }
        }
        return f;
    }

    internal static string SerializeReportFilters(List<ReportFilter> items) =>
        SerializeList(items, WriteReportFilter);

    internal static List<ReportFilter> DeserializeReportFilters(string? json) =>
        DeserializeList(json, ReadReportFilter);

    // ── ReportParameter ──────────────────────────────────────────────────────

    internal static void WriteReportParameter(Utf8JsonWriter w, ReportParameter p)
    {
        w.WriteStartObject();
        w.WriteString("Name"u8, p.Name);
        w.WriteString("Label"u8, p.Label);
        w.WriteString("Type"u8, p.Type);
        w.WriteString("DefaultValue"u8, p.DefaultValue);
        if (p.Options is not null)
        {
            w.WriteStartArray("Options"u8);
            foreach (var o in p.Options) w.WriteStringValue(o);
            w.WriteEndArray();
        }
        if (p.FieldSource is not null)
            w.WriteString("FieldSource"u8, p.FieldSource);
        w.WriteEndObject();
    }

    internal static ReportParameter ReadReportParameter(ref Utf8JsonReader r)
    {
        var p = new ReportParameter();
        while (r.Read())
        {
            if (r.TokenType == JsonTokenType.EndObject) break;
            if (r.TokenType == JsonTokenType.PropertyName)
            {
                var prop = r.GetString();
                r.Read();
                switch (prop)
                {
                    case "Name": p.Name = r.GetString() ?? string.Empty; break;
                    case "Label": p.Label = r.GetString() ?? string.Empty; break;
                    case "Type": p.Type = r.GetString() ?? "string"; break;
                    case "DefaultValue": p.DefaultValue = r.GetString() ?? string.Empty; break;
                    case "FieldSource": p.FieldSource = r.TokenType == JsonTokenType.Null ? null : r.GetString(); break;
                    case "Options":
                        if (r.TokenType == JsonTokenType.StartArray)
                        {
                            p.Options = new List<string>();
                            while (r.Read() && r.TokenType != JsonTokenType.EndArray)
                                p.Options.Add(r.GetString() ?? string.Empty);
                        }
                        break;
                }
            }
        }
        return p;
    }

    internal static string SerializeReportParameters(List<ReportParameter> items) =>
        SerializeList(items, WriteReportParameter);

    internal static List<ReportParameter> DeserializeReportParameters(string? json) =>
        DeserializeList(json, ReadReportParameter);

    // ── ViewProjection ───────────────────────────────────────────────────────

    internal static void WriteViewProjection(Utf8JsonWriter w, ViewProjection vp)
    {
        w.WriteStartObject();
        w.WriteString("Entity"u8, vp.Entity);
        w.WriteString("Field"u8, vp.Field);
        w.WriteString("Alias"u8, vp.Alias);
        w.WriteEndObject();
    }

    internal static ViewProjection ReadViewProjection(ref Utf8JsonReader r)
    {
        var vp = new ViewProjection();
        while (r.Read())
        {
            if (r.TokenType == JsonTokenType.EndObject) break;
            if (r.TokenType == JsonTokenType.PropertyName)
            {
                var prop = r.GetString();
                r.Read();
                switch (prop)
                {
                    case "Entity": vp.Entity = r.GetString() ?? string.Empty; break;
                    case "Field": vp.Field = r.GetString() ?? string.Empty; break;
                    case "Alias": vp.Alias = r.GetString() ?? string.Empty; break;
                }
            }
        }
        return vp;
    }

    internal static string SerializeViewProjections(List<ViewProjection> items) =>
        SerializeList(items, WriteViewProjection);

    internal static List<ViewProjection> DeserializeViewProjections(string? json) =>
        DeserializeList(json, ReadViewProjection);

    // ── ViewJoinDefinition ───────────────────────────────────────────────────

    internal static void WriteViewJoin(Utf8JsonWriter w, ViewJoinDefinition j)
    {
        w.WriteStartObject();
        w.WriteString("SourceEntity"u8, j.SourceEntity);
        w.WriteString("SourceField"u8, j.SourceField);
        w.WriteString("TargetEntity"u8, j.TargetEntity);
        w.WriteString("TargetField"u8, j.TargetField);
        w.WriteString("Type"u8, j.Type.ToString());
        w.WriteEndObject();
    }

    internal static ViewJoinDefinition ReadViewJoin(ref Utf8JsonReader r)
    {
        var j = new ViewJoinDefinition();
        while (r.Read())
        {
            if (r.TokenType == JsonTokenType.EndObject) break;
            if (r.TokenType == JsonTokenType.PropertyName)
            {
                var prop = r.GetString();
                r.Read();
                switch (prop)
                {
                    case "SourceEntity": j.SourceEntity = r.GetString() ?? string.Empty; break;
                    case "SourceField": j.SourceField = r.GetString() ?? string.Empty; break;
                    case "TargetEntity": j.TargetEntity = r.GetString() ?? string.Empty; break;
                    case "TargetField": j.TargetField = r.GetString() ?? string.Empty; break;
                    case "Type":
                        if (r.TokenType == JsonTokenType.String)
                        { if (Enum.TryParse<JoinType>(r.GetString(), out var jt)) j.Type = jt; }
                        else if (r.TokenType == JsonTokenType.Number)
                            j.Type = (JoinType)r.GetInt32();
                        break;
                }
            }
        }
        return j;
    }

    internal static string SerializeViewJoins(List<ViewJoinDefinition> items) =>
        SerializeList(items, WriteViewJoin);

    internal static List<ViewJoinDefinition> DeserializeViewJoins(string? json) =>
        DeserializeList(json, ReadViewJoin);

    // ── ViewFilterDefinition ─────────────────────────────────────────────────

    internal static void WriteViewFilter(Utf8JsonWriter w, ViewFilterDefinition f)
    {
        w.WriteStartObject();
        w.WriteString("Entity"u8, f.Entity);
        w.WriteString("Field"u8, f.Field);
        w.WriteString("Operator"u8, f.Operator);
        w.WriteString("Value"u8, f.Value);
        w.WriteEndObject();
    }

    internal static ViewFilterDefinition ReadViewFilter(ref Utf8JsonReader r)
    {
        var f = new ViewFilterDefinition();
        while (r.Read())
        {
            if (r.TokenType == JsonTokenType.EndObject) break;
            if (r.TokenType == JsonTokenType.PropertyName)
            {
                var prop = r.GetString();
                r.Read();
                switch (prop)
                {
                    case "Entity": f.Entity = r.GetString() ?? string.Empty; break;
                    case "Field": f.Field = r.GetString() ?? string.Empty; break;
                    case "Operator": f.Operator = r.GetString() ?? "="; break;
                    case "Value": f.Value = r.GetString() ?? string.Empty; break;
                }
            }
        }
        return f;
    }

    internal static string SerializeViewFilters(List<ViewFilterDefinition> items) =>
        SerializeList(items, WriteViewFilter);

    internal static List<ViewFilterDefinition> DeserializeViewFilters(string? json) =>
        DeserializeList(json, ReadViewFilter);

    // ── ViewSortDefinition ───────────────────────────────────────────────────

    internal static void WriteViewSort(Utf8JsonWriter w, ViewSortDefinition s)
    {
        w.WriteStartObject();
        w.WriteString("Entity"u8, s.Entity);
        w.WriteString("Field"u8, s.Field);
        w.WriteBoolean("Descending"u8, s.Descending);
        w.WriteEndObject();
    }

    internal static ViewSortDefinition ReadViewSort(ref Utf8JsonReader r)
    {
        var s = new ViewSortDefinition();
        while (r.Read())
        {
            if (r.TokenType == JsonTokenType.EndObject) break;
            if (r.TokenType == JsonTokenType.PropertyName)
            {
                var prop = r.GetString();
                r.Read();
                switch (prop)
                {
                    case "Entity": s.Entity = r.GetString() ?? string.Empty; break;
                    case "Field": s.Field = r.GetString() ?? string.Empty; break;
                    case "Descending": s.Descending = r.GetBoolean(); break;
                }
            }
        }
        return s;
    }

    internal static string SerializeViewSorts(List<ViewSortDefinition> items) =>
        SerializeList(items, WriteViewSort);

    internal static List<ViewSortDefinition> DeserializeViewSorts(string? json) =>
        DeserializeList(json, ReadViewSort);

    // ── SchemaDefinitionFile ─────────────────────────────────────────────────

    internal static byte[] SerializeSchemaDefinitionFile(SchemaDefinitionFile schema)
    {
        var buffer = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buffer);
        w.WriteStartObject();
        w.WriteNumber("Version"u8, schema.Version);
        w.WriteNumber("Hash"u8, schema.Hash);
        if (schema.Architecture is not null)
            w.WriteString("Architecture"u8, schema.Architecture);
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
        return buffer.WrittenSpan.ToArray();
    }

    internal static SchemaDefinitionFile? DeserializeSchemaDefinitionFile(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty) return null;
        try
        {
            var reader = new Utf8JsonReader(bytes);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                return null;

            var schema = new SchemaDefinitionFile();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject) break;
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    var prop = reader.GetString();
                    reader.Read();
                    switch (prop)
                    {
                        case "Version": schema.Version = reader.GetInt32(); break;
                        case "Hash": schema.Hash = reader.GetUInt32(); break;
                        case "Architecture": schema.Architecture = reader.TokenType == JsonTokenType.Null ? null : reader.GetString(); break;
                        case "Members":
                            if (reader.TokenType == JsonTokenType.StartArray)
                            {
                                while (reader.Read())
                                {
                                    if (reader.TokenType == JsonTokenType.EndArray) break;
                                    if (reader.TokenType == JsonTokenType.StartObject)
                                    {
                                        var m = new MemberSignatureFile();
                                        while (reader.Read())
                                        {
                                            if (reader.TokenType == JsonTokenType.EndObject) break;
                                            if (reader.TokenType == JsonTokenType.PropertyName)
                                            {
                                                var mProp = reader.GetString();
                                                reader.Read();
                                                switch (mProp)
                                                {
                                                    case "Name": m.Name = reader.GetString() ?? string.Empty; break;
                                                    case "TypeName": m.TypeName = reader.GetString() ?? string.Empty; break;
                                                }
                                            }
                                        }
                                        schema.Members.Add(m);
                                    }
                                }
                            }
                            break;
                    }
                }
            }
            return schema;
        }
        catch
        {
            return null;
        }
    }
}
