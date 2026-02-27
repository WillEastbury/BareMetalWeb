using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace BareMetalWeb.Host;

/// <summary>The kind of a pre-compiled route segment.</summary>
public enum RouteSegmentKind { Literal, Parameter, CatchAll }

/// <summary>A single pre-compiled segment of a route template.</summary>
public readonly struct RouteSegment
{
    public readonly RouteSegmentKind Kind;
    /// <summary>The literal text, parameter name, or catch-all name for this segment.</summary>
    public readonly string Value;

    public RouteSegment(RouteSegmentKind kind, string value)
    {
        Kind = kind;
        Value = value;
    }
}

/// <summary>
/// A route template compiled once at registration time.
/// Stores the verb, pre-parsed segments, and pre-computed counts to eliminate
/// per-request template re-parsing.
/// </summary>
public sealed class CompiledRoute
{
    /// <summary>HTTP verb (e.g. "GET", "POST", "ALL") extracted from the route key.</summary>
    public readonly string Verb;
    /// <summary>Pre-parsed path segments (literal / parameter / catch-all).</summary>
    public readonly RouteSegment[] Segments;
    /// <summary>Number of literal segments — used to sort routes by specificity.</summary>
    public readonly int LiteralSegmentCount;
    /// <summary>Number of named parameter + catch-all segments — used to pre-size the result dictionary.</summary>
    public readonly int ParameterCount;
    /// <summary>True when the template is a regex: pattern.</summary>
    public readonly bool IsRegex;
    /// <summary>Compiled regex for regex: patterns; null otherwise.</summary>
    public readonly Regex? RegexPattern;

    /// <param name="routeKey">Full route key as stored in the routes dictionary, e.g. "GET /users/{id}".</param>
    public CompiledRoute(string routeKey)
    {
        int spaceIdx = routeKey.IndexOf(' ');
        if (spaceIdx <= 0)
        {
            // Malformed key — store as-is so it is skipped gracefully.
            Verb = routeKey;
            Segments = Array.Empty<RouteSegment>();
            return;
        }

        Verb = routeKey[..spaceIdx];
        var templateStr = routeKey[(spaceIdx + 1)..];

        if (templateStr.StartsWith("regex:", StringComparison.OrdinalIgnoreCase))
        {
            IsRegex = true;
            RegexPattern = new Regex(templateStr[6..], RegexOptions.Compiled);
            Segments = Array.Empty<RouteSegment>();
            return;
        }

        // Parse path template into segments.
        var span = templateStr.AsSpan().Trim('/');
        // Estimate segment count from slash count to avoid list resizing in common cases.
        int slashCount = 0;
        foreach (char c in span) if (c == '/') slashCount++;
        var segs = new RouteSegment[slashCount + (span.IsEmpty ? 0 : 1)];
        int segCount = 0;
        int litCount = 0;
        int paramCount = 0;

        while (!span.IsEmpty)
        {
            int slash = span.IndexOf('/');
            ReadOnlySpan<char> seg;
            if (slash < 0)
            {
                seg = span;
                span = ReadOnlySpan<char>.Empty;
            }
            else
            {
                seg = span[..slash];
                span = span[(slash + 1)..];
            }

            if (seg.StartsWith("{*".AsSpan()) && seg[^1] == '}')
            {
                segs[segCount++] = new RouteSegment(RouteSegmentKind.CatchAll, seg[2..^1].ToString());
                paramCount++;
            }
            else if (seg.Length > 0 && seg[0] == '{' && seg[^1] == '}')
            {
                segs[segCount++] = new RouteSegment(RouteSegmentKind.Parameter, seg[1..^1].ToString());
                paramCount++;
            }
            else
            {
                segs[segCount++] = new RouteSegment(RouteSegmentKind.Literal, seg.ToString());
                litCount++;
            }
        }

        Segments = segCount == segs.Length ? segs : segs[..segCount];
        LiteralSegmentCount = litCount;
        ParameterCount = paramCount;
    }
}

public static class RouteMatching
{
    /// <summary>
    /// When true, literal route segments are matched with <see cref="StringComparison.Ordinal"/> (case-sensitive).
    /// When false (default), matching uses <see cref="StringComparison.OrdinalIgnoreCase"/>.
    /// Configure once at startup before routes are registered.
    /// </summary>
    public static bool CaseSensitive { get; set; } = false;

    /// <summary>
    /// Match a request path against a pre-compiled route template.
    /// All template segments are resolved from the compiled representation — no re-parsing occurs.
    /// </summary>
    public static bool TryMatch(string path, CompiledRoute compiled, out Dictionary<string, string> parameters)
    {
        if (compiled.IsRegex)
        {
            parameters = new(0);
            return compiled.RegexPattern!.IsMatch(path);
        }

        // Pre-size the dictionary to the exact parameter count — avoids rehashing.
        parameters = new(compiled.ParameterCount);

        var pathSpan = path.AsSpan().Trim('/');
        var segments = compiled.Segments;
        int segIdx = 0;
        var comparison = CaseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

        while (true)
        {
            // Advance one segment from the path.
            ReadOnlySpan<char> pathSeg;
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

            bool noMoreSegments = segIdx >= segments.Length;

            // Both exhausted simultaneously → full match.
            if (noMoreSegments && pathSeg.IsEmpty)
                return true;

            // Template exhausted but path still has segments → no match.
            if (noMoreSegments)
                return false;

            var seg = segments[segIdx++];

            // Wildcard segment {*key} — consumes the rest of the path.
            if (seg.Kind == RouteSegmentKind.CatchAll)
            {
                string remainder;
                if (pathSpan.IsEmpty)
                    remainder = pathSeg.ToString();
                else if (pathSeg.IsEmpty)
                    remainder = pathSpan.ToString();
                else
                    remainder = string.Concat(pathSeg, "/", pathSpan);
                parameters[seg.Value] = remainder;
                return true;
            }

            // Path exhausted but template still has non-catch-all segments → no match.
            if (pathSeg.IsEmpty)
                return false;

            if (seg.Kind == RouteSegmentKind.Parameter)
            {
                parameters[seg.Value] = pathSeg.ToString();
            }
            else if (!pathSeg.Equals(seg.Value.AsSpan(), comparison))
            {
                return false;
            }

            // Both exhausted at the same time → full match.
            if (pathSpan.IsEmpty && segIdx >= segments.Length)
                return true;
        }
    }

    /// <summary>
    /// Match a request path against a route template string (original API, kept for compatibility).
    /// Prefer the <see cref="CompiledRoute"/> overload in performance-critical call sites.
    /// </summary>
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
        var comparison = CaseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

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
            else if (!tmplSeg.Equals(pathSeg, comparison))
            {
                return false;
            }

            // If both spans are now empty we consumed the last segment
            if (pathSpan.IsEmpty && templateSpan.IsEmpty)
                return true;
        }
    }
}
