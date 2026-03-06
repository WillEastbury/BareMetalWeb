using System.Text.Json;

namespace BareMetalWeb.Host;

internal static class JsonWriterHelper
{
    private static readonly JsonWriterOptions s_compact = new();
    private static readonly JsonWriterOptions s_indented = new() { Indented = true };

    internal static string ToJsonString(object? value, bool indented = false)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer, indented ? s_indented : s_compact))
        {
            WriteValue(w, value);
        }
        return System.Text.Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    internal static async ValueTask WriteResponseAsync(
        Microsoft.AspNetCore.Http.HttpResponse response,
        object? value,
        bool indented = false,
        CancellationToken ct = default)
    {
        response.ContentType = "application/json";
        await using var w = new Utf8JsonWriter(response.Body, indented ? s_indented : s_compact);
        WriteValue(w, value);
        await w.FlushAsync(ct);
    }

    internal static void WriteValue(Utf8JsonWriter w, object? value)
    {
        if (value is null) { w.WriteNullValue(); return; }
        switch (value)
        {
            case JsonElement el: el.WriteTo(w); return;
            case string s: w.WriteStringValue(s); return;
            case bool b: w.WriteBooleanValue(b); return;
            case int i: w.WriteNumberValue(i); return;
            case uint u: w.WriteNumberValue(u); return;
            case long l: w.WriteNumberValue(l); return;
            case ulong ul: w.WriteNumberValue(ul); return;
            case double d: w.WriteNumberValue(d); return;
            case decimal m: w.WriteNumberValue(m); return;
            case float f: w.WriteNumberValue(f); return;
            case DateTime dt: w.WriteStringValue(dt.ToString("O")); return;
            case DateTimeOffset dto: w.WriteStringValue(dto.ToString("O")); return;
            case Guid g: w.WriteStringValue(g); return;
        }
        if (value is IDictionary<string, object?> dict)
        {
            w.WriteStartObject();
            foreach (var kvp in dict) { w.WritePropertyName(kvp.Key); WriteValue(w, kvp.Value); }
            w.WriteEndObject();
            return;
        }
        if (value is IDictionary<string, string?> sdict)
        {
            w.WriteStartObject();
            foreach (var kvp in sdict) { w.WritePropertyName(kvp.Key); w.WriteStringValue(kvp.Value); }
            w.WriteEndObject();
            return;
        }
        if (value is IDictionary<string, string> sdict2)
        {
            w.WriteStartObject();
            foreach (var kvp in sdict2) { w.WritePropertyName(kvp.Key); w.WriteStringValue(kvp.Value); }
            w.WriteEndObject();
            return;
        }
        if (value is IDictionary<string, object> odict)
        {
            w.WriteStartObject();
            foreach (var kvp in odict) { w.WritePropertyName(kvp.Key); WriteValue(w, kvp.Value); }
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
