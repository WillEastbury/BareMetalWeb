using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace BareMetalWeb.Host;

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

        // Span-based segment matching: avoids Split() array allocations on every call.
        var pathSpan = path.AsSpan().Trim('/');
        var templateSpan = template.AsSpan().Trim('/');

        // Walk both spans segment by segment simultaneously.
        while (true)
        {
            ReadOnlySpan<char> pathSeg;
            ReadOnlySpan<char> tmplSeg;

            int pathSlash = pathSpan.IndexOf('/');
            if (pathSlash < 0)
            {
                pathSeg = pathSpan;
                pathSpan = ReadOnlySpan<char>.Empty;
            }
            else
            {
                pathSeg = pathSpan[..pathSlash];
                pathSpan = pathSpan[(pathSlash + 1)..];
            }

            int tmplSlash = templateSpan.IndexOf('/');
            if (tmplSlash < 0)
            {
                tmplSeg = templateSpan;
                templateSpan = ReadOnlySpan<char>.Empty;
            }
            else
            {
                tmplSeg = templateSpan[..tmplSlash];
                templateSpan = templateSpan[(tmplSlash + 1)..];
            }

            // Both exhausted simultaneously → full match
            if (tmplSeg.IsEmpty && pathSeg.IsEmpty)
                return true;

            // Template exhausted but path still has segments → no match
            if (tmplSeg.IsEmpty)
                return false;

            // Wildcard segment {*key} — consumes the rest of the path
            if (tmplSeg.StartsWith("{*".AsSpan()) && tmplSeg[^1] == '}')
            {
                var key = tmplSeg[2..^1].ToString();
                // Reconstruct the remainder: current pathSeg + any leftover pathSpan
                string remainder;
                if (pathSpan.IsEmpty)
                    remainder = pathSeg.ToString();
                else if (pathSeg.IsEmpty)
                    remainder = pathSpan.ToString();
                else
                    remainder = string.Concat(pathSeg, "/", pathSpan);
                parameters[key] = remainder;
                return true;
            }

            // Path exhausted but template still has segments → no match
            if (pathSeg.IsEmpty)
                return false;

            if (tmplSeg[0] == '{' && tmplSeg[^1] == '}')
            {
                // Named parameter segment
                parameters[tmplSeg[1..^1].ToString()] = pathSeg.ToString();
            }
            else if (!tmplSeg.Equals(pathSeg, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // If both spans are now empty we consumed the last segment
            if (pathSpan.IsEmpty && templateSpan.IsEmpty)
                return true;
        }
    }
}
