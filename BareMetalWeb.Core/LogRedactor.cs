namespace BareMetalWeb.Core;

/// <summary>
/// PII redaction for log output using simple char-scanning — no regex on the hot path.
/// Structured log fields (IP, userId) are masked directly by the logger; this class
/// handles free-text message scanning only during the background flush, never inline
/// on the request thread.
/// </summary>
public static class LogRedactor
{
    /// <summary>Masks an IP address, preserving only the first octet. O(n) single-pass scan.</summary>
    public static string RedactIp(string? ip)
    {
        if (string.IsNullOrEmpty(ip) || ip == "unknown")
            return ip ?? "unknown";

        // IPv6: keep first two groups
        int colonIdx = ip.IndexOf(':');
        if (colonIdx >= 0)
        {
            int second = ip.IndexOf(':', colonIdx + 1);
            return second > 0 ? string.Concat(ip.AsSpan(0, second), ":***") : "***";
        }

        // IPv4: keep first octet
        int dotIdx = ip.IndexOf('.');
        return dotIdx > 0 ? string.Concat(ip.AsSpan(0, dotIdx), ".*.*.*") : ip;
    }

    /// <summary>Masks an email: keeps first 2 chars of local part + domain. No regex.</summary>
    public static string RedactEmail(string? email)
    {
        if (string.IsNullOrEmpty(email))
            return email ?? "";

        int at = email.IndexOf('@');
        if (at < 0) return email;

        int keep = Math.Min(2, at);
        return string.Concat(email.AsSpan(0, keep), "***", email.AsSpan(at));
    }

    /// <summary>
    /// Scans free-text for email-like patterns (x@y.z) and replaces them in-place.
    /// Single-pass O(n), no regex, no allocations when no '@' is found.
    /// </summary>
    public static string RedactFreeText(string input)
    {
        if (string.IsNullOrEmpty(input) || input.IndexOf('@') < 0)
            return input;

        // Only allocate if we actually find an email pattern
        var chars = input.AsSpan();
        Span<Range> atPositions = stackalloc Range[32]; // up to 32 emails per message
        int atCount = 0;

        for (int i = 0; i < chars.Length && atCount < 32; i++)
        {
            if (chars[i] == '@')
            {
                // Walk backward to find local part start
                int localStart = i - 1;
                while (localStart >= 0 && IsEmailChar(chars[localStart]))
                    localStart--;
                localStart++;

                // Walk forward to find domain end
                int domainEnd = i + 1;
                bool hasDot = false;
                while (domainEnd < chars.Length && (IsEmailChar(chars[domainEnd]) || chars[domainEnd] == '.'))
                {
                    if (chars[domainEnd] == '.') hasDot = true;
                    domainEnd++;
                }

                if (hasDot && i - localStart >= 1 && domainEnd - i > 2)
                {
                    atPositions[atCount++] = new Range(localStart, domainEnd);
                    i = domainEnd - 1; // skip past this match
                }
            }
        }

        if (atCount == 0)
            return input;

        // Build result with redacted emails
        var sb = new System.Text.StringBuilder(input.Length);
        int pos = 0;
        for (int j = 0; j < atCount; j++)
        {
            var range = atPositions[j];
            var (start, end) = (range.Start.Value, range.End.Value);
            sb.Append(input, pos, start - pos); // text before email

            var email = input.AsSpan(start, end - start);
            int at = email.IndexOf('@');
            int keep = Math.Min(2, at);
            sb.Append(email[..keep]);
            sb.Append("***");
            sb.Append(email[at..]); // @domain.com
            pos = end;
        }
        sb.Append(input, pos, input.Length - pos);
        return sb.ToString();
    }

    private static bool IsEmailChar(char c) =>
        (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '.' || c == '_' ||
        c == '%' || c == '+' || c == '-';

    /// <summary>
    /// Strips file paths and line numbers from .NET stack trace frames (` in /path/file.cs:line N`),
    /// keeping only type and method names. Always applied to exception stacks regardless of RedactPII.
    /// </summary>
    public static string RedactStackTrace(string stackTrace)
    {
        if (string.IsNullOrEmpty(stackTrace))
            return stackTrace;

        var lines = stackTrace.Split('\n');
        var sb = new System.Text.StringBuilder(stackTrace.Length);
        foreach (var line in lines)
        {
            var trimmed = line.TrimEnd('\r');
            // Stack frame lines contain " in <path>:line N" — strip that portion
            int inIdx = trimmed.IndexOf(" in ", StringComparison.Ordinal);
            if (inIdx > 0 && trimmed.IndexOf(":line ", inIdx, StringComparison.Ordinal) > inIdx)
            {
                sb.Append(trimmed, 0, inIdx);
                sb.Append('\n');
            }
            else
            {
                sb.Append(trimmed);
                sb.Append('\n');
            }
        }

        var result = sb.ToString();
        // Preserve original trailing-newline behaviour
        if (!stackTrace.EndsWith('\n') && result.EndsWith('\n'))
            result = result[..^1];
        return result;
    }
}
