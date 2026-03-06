using System.Text.Json;

namespace BareMetalWeb.Data;

internal static class DataJsonWriter
{
    internal static string ToJsonString(object? value)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            WriteValue(w, value);
        }
        return System.Text.Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    internal static List<Dictionary<string, string>> ParseListOfStringDicts(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var result = new List<Dictionary<string, string>>();
        foreach (var row in doc.RootElement.EnumerateArray())
        {
            var dict = new Dictionary<string, string>();
            foreach (var prop in row.EnumerateObject())
                dict[prop.Name] = prop.Value.GetString() ?? "";
            result.Add(dict);
        }
        return result;
    }

    internal static Dictionary<string, string> ParseStringDict(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var prop in doc.RootElement.EnumerateObject())
            dict[prop.Name] = prop.Value.GetString() ?? "";
        return dict;
    }

    internal static void WriteValue(Utf8JsonWriter w, object? value)
    {
        if (value == null) { w.WriteNullValue(); return; }
        switch (value)
        {
            case JsonElement el: el.WriteTo(w); return;
            case string s: w.WriteStringValue(s); return;
            case bool b: w.WriteBooleanValue(b); return;
            case int i: w.WriteNumberValue(i); return;
            case uint u: w.WriteNumberValue(u); return;
            case long l: w.WriteNumberValue(l); return;
            case double d: w.WriteNumberValue(d); return;
            case decimal m: w.WriteNumberValue(m); return;
            case float f: w.WriteNumberValue(f); return;
            case DateTime dt: w.WriteStringValue(dt.ToString("O")); return;
            case DateTimeOffset dto: w.WriteStringValue(dto.ToString("O")); return;
            case Guid g: w.WriteStringValue(g); return;
        }
        if (value is IDictionary<string, object?> objDict)
        {
            w.WriteStartObject();
            foreach (var kvp in objDict) { w.WritePropertyName(kvp.Key); WriteValue(w, kvp.Value); }
            w.WriteEndObject();
            return;
        }
        if (value is IDictionary<string, string?> snDict)
        {
            w.WriteStartObject();
            foreach (var kvp in snDict) { w.WritePropertyName(kvp.Key); w.WriteStringValue(kvp.Value); }
            w.WriteEndObject();
            return;
        }
        if (value is IDictionary<string, string> sDict)
        {
            w.WriteStartObject();
            foreach (var kvp in sDict) { w.WritePropertyName(kvp.Key); w.WriteStringValue(kvp.Value); }
            w.WriteEndObject();
            return;
        }
        if (value is System.Collections.IEnumerable enumerable and not string)
        {
            w.WriteStartArray();
            foreach (var item in enumerable) WriteValue(w, item);
            w.WriteEndArray();
            return;
        }
        w.WriteStringValue(value.ToString());
    }
}
