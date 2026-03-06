using System.Text.Json;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

/// <summary>
/// Thin Host-layer wrapper over <see cref="BareMetalWeb.Data.DataJsonWriter"/>
/// adding ASP.NET-specific response writing.
/// </summary>
internal static class JsonWriterHelper
{
    private static readonly JsonWriterOptions s_compact = new();
    private static readonly JsonWriterOptions s_indented = new() { Indented = true };

    internal static string ToJsonString(object? value, bool indented = false)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer, indented ? s_indented : s_compact))
        {
            Data.DataJsonWriter.WriteValue(w, value);
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
        Data.DataJsonWriter.WriteValue(w, value);
        await w.FlushAsync(ct);
    }

    internal static void WriteValue(Utf8JsonWriter w, object? value)
        => Data.DataJsonWriter.WriteValue(w, value);
}
