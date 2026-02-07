using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace BareMetalWeb.WebServer;

public static class RouteMatching
{
    public static bool TryMatch(string path, string template, out Dictionary<string, string> parameters)
    {
        parameters = new();

        if (template.StartsWith("regex:", StringComparison.OrdinalIgnoreCase))
        {
            var pattern = template[6..];
            return Regex.IsMatch(path, pattern);
        }

        var pathSegments = path.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        var templateSegments = template.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        var pathIndex = 0;

        for (int i = 0; i < templateSegments.Length; i++)
        {
            string templateSegment = templateSegments[i];

            if (templateSegment.StartsWith("{*") && templateSegment.EndsWith("}"))
            {
                string key = templateSegment[2..^1];
                var remainder = pathIndex >= pathSegments.Length
                    ? string.Empty
                    : string.Join("/", pathSegments.Skip(pathIndex));
                parameters[key] = remainder;
                return true;
            }

            if (pathIndex >= pathSegments.Length)
                return false;

            string pathSegment = pathSegments[pathIndex];

            if (templateSegment.StartsWith("{") && templateSegment.EndsWith("}"))
            {
                string key = templateSegment[1..^1];
                parameters[key] = pathSegment;
            }
            else if (!string.Equals(templateSegment, pathSegment, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            pathIndex++;
        }

        return pathIndex == pathSegments.Length;
    }
}
