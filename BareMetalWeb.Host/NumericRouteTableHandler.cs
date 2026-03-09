using System.Text;
using BareMetalWeb.Core;

namespace BareMetalWeb.Host;

/// <summary>
/// Serves the <c>GET /bmw/routes</c> endpoint: exports the numeric route table
/// as a JSON array so clients can build requests using route IDs instead of paths.
/// </summary>
public static class NumericRouteTableHandler
{
    public static async ValueTask WriteRoutesAsync(BmwContext context)
    {
        var app = context.App as BareMetalWebServer;
        if (app == null)
        {
            context.StatusCode = 500;
            return;
        }

        var table = app.NumericRoutes;
        var entries = table.GetAllEntries();

        // Pre-size: ~80 bytes per entry is a reasonable estimate
        var sb = new StringBuilder(entries.Length * 80 + 32);
        sb.Append("{\"count\":");
        sb.Append(entries.Length);
        sb.Append(",\"routes\":[");

        for (int i = 0; i < entries.Length; i++)
        {
            if (i > 0) sb.Append(',');

            var key = entries[i].RouteKey;
            int spaceIdx = key.IndexOf(' ');
            var verb = spaceIdx > 0 ? key[..spaceIdx] : "ALL";
            var path = spaceIdx > 0 ? key[(spaceIdx + 1)..] : key;

            sb.Append("{\"id\":");
            sb.Append(i);
            sb.Append(",\"verb\":\"");
            sb.Append(verb);
            sb.Append("\",\"path\":\"");
            AppendJsonEscaped(sb, path);
            sb.Append("\"}");
        }

        sb.Append("]}");

        context.StatusCode = 200;
        context.ContentType = "application/json; charset=utf-8";
        await context.WriteResponseAsync(sb.ToString(), context.RequestAborted);
    }

    private static void AppendJsonEscaped(StringBuilder sb, string value)
    {
        foreach (char c in value)
        {
            switch (c)
            {
                case '"':  sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:   sb.Append(c); break;
            }
        }
    }
}
