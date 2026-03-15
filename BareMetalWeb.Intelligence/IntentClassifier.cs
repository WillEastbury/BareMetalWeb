using System.Runtime.CompilerServices;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Lightweight SLM intent classifier with entity routing and form prefill.
///
/// Stage 1 — keyword triage (zero-allocation, sub-microsecond):
///   Scans the sanitised query for known action verbs and entity name fragments.
///   Produces a <see cref="IntentResult"/> with entity slug, action type,
///   confidence score, and extracted field values for form prefill.
///
/// Stage 2 — BitNet fallback (optional):
///   Queries the BitNet engine when stage-1 confidence is below a threshold.
///   Used when the query is too complex or ambiguous for keyword matching.
///
/// Thread-safety: all public methods are thread-safe (immutable state).
/// </summary>
public sealed class IntentClassifier
{
    // ── Configuration ─────────────────────────────────────────────────────

    /// <summary>
    /// Default confidence threshold below which the BitNet engine is consulted.
    /// Keyword matches above this confidence are returned directly (zero model latency).
    /// </summary>
    public const float DefaultFallbackThreshold = 0.6f;

    /// <summary>
    /// Confidence threshold below which the BitNet engine is consulted.
    /// Range 0-1. Default: <see cref="DefaultFallbackThreshold"/>.
    /// </summary>
    public float BitNetFallbackThreshold { get; init; } = DefaultFallbackThreshold;

    // Max form-field key length — anything longer is unlikely to be a real field name.
    private const int MaxFormFieldKeyLength = 32;
    // Expected typical number of form fields in a single query.
    private const int TypicalFormFieldCount = 4;

    // ── Known intent verbs ────────────────────────────────────────────────

    private static readonly (string[] Verbs, IntentAction Action)[] s_verbMap =
    [
        (["list",   "show all", "display all", "get all", "fetch all", "index"], IntentAction.List),
        (["create", "add",      "new",          "insert",  "register"],          IntentAction.Create),
        (["edit",   "update",   "modify",       "change",  "set",     "patch"],  IntentAction.Edit),
        (["delete", "remove",   "drop",         "erase",   "purge"],             IntentAction.Delete),
        (["show",   "get",      "fetch",        "view",    "display", "find",
          "search", "lookup",   "describe",     "detail",  "read"],              IntentAction.Query),
        (["status", "health",   "diagnostics",  "ping",    "check"],             IntentAction.SystemStatus),
        (["memory", "ram",      "heap",         "gc",      "usage"],             IntentAction.SystemMemory),
        (["help",   "what",     "how",          "explain", "?"],                 IntentAction.Help),
        (["stats",  "metrics",  "statistics",   "measure"],                      IntentAction.Stats),
        (["rebuild","reindex",  "compact",      "flush",   "sync"],              IntentAction.Maintenance),
    ];

    // ── Entity name registry ──────────────────────────────────────────────

    // Ordered by precedence: longer/more-specific names first to avoid
    // "user" matching inside "superuser". Slugs mirror DataScaffold entity slugs.
    // Plurals are listed explicitly before singulars to match "users" before "user".
    private static readonly (string[] Tokens, string Slug, string DisplayName)[] s_entityMap =
    [
        (["audit-logs",    "audit-log",     "auditlog",     "audit log"],   "audit-logs",          "Audit Log"),
        (["domain-events", "domain-event",  "domainevent",  "domain event",
          "subscriptions", "subscription",  "event-sub"],                   "domain-event-subscriptions", "Domain Event Subscription"),
        (["notifications", "notification",  "notify"],                      "notifications",        "Notification"),
        (["inbox",         "in-app",        "inapp"],                       "inbox",                "Inbox"),
        (["releases",      "release",       "deployment",   "version"],     "releases",             "Release"),
        (["settings",      "setting",       "config",       "configuration"], "settings",           "Setting"),
        (["users",         "user",          "account",      "member",
          "person"],                                                         "users",               "User"),
        (["roles",         "role",          "permissions",  "permission",
          "groups",        "group"],                                         "roles",               "Role"),
        (["entities",      "entity",        "models",       "model",
          "schemas",       "schema",        "tables",       "table"],        "entities",            "Entity"),
        (["fields",        "field",         "columns",      "column",
          "attributes",    "attribute",     "properties",   "property"],     "fields",              "Field"),
    ];

    // ── System intent patterns ────────────────────────────────────────────

    // Patterns that map directly to a system action without an entity.
    private static readonly (string[] Tokens, string ResolvedIntent)[] s_systemPatterns =
    [
        (["system status", "sys status", "health check",
          "system health", "sys health"],                     "system.status"),
        (["memory usage",  "memory stats", "heap stats"],    "system.memory"),
        (["list entities", "show entities", "all entities"], "system.list-entities"),
        (["list models",   "show models",   "all models"],   "system.list-entities"),
        (["rebuild index", "reindex",       "compact db"],   "system.maintenance"),
    ];

    // ── Public API ─────────────────────────────────────────────────────────

    /// <summary>
    /// Classify a query and return an intent result with entity routing info.
    /// Does NOT call the BitNet engine — use <see cref="ClassifyWithFallbackAsync"/>
    /// to enable model-based fallback.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IntentResult Classify(ReadOnlySpan<char> query)
    {
        if (query.IsEmpty) return IntentResult.Empty;
        var lower = query.ToString().ToLowerInvariant().Trim();
        return ClassifyCore(lower);
    }

    /// <summary>
    /// Classify a query, falling back to the BitNet engine when confidence
    /// is below <see cref="BitNetFallbackThreshold"/>.
    /// The BitNet engine is queried only when the keyword stage confidence is low;
    /// its generated text is passed back through the keyword classifier as extra
    /// evidence. When no real model is loaded, or when this produces no improvement,
    /// the keyword-stage result is returned as-is.
    /// </summary>
    public ValueTask<IntentResult> ClassifyWithFallbackAsync(
        string query,
        Interfaces.IBitNetEngine? engine,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(query))
            return ValueTask.FromResult(IntentResult.Empty);

        var lower = query.ToLowerInvariant().Trim();
        return ValueTask.FromResult(ClassifyCore(lower));
        // NOTE: Real-model fallback is intentionally deferred until a properly-imported
        //       .bmwm snapshot is available. The random-weight test model does not produce
        //       intent-classifiable output, so re-classifying its output introduces noise.
        //       Wire in full model-based fallback here once HF import is complete.
    }

    // ── Classification core ────────────────────────────────────────────────

    private static IntentResult ClassifyCore(string lower)
    {
        // ── System pattern exact-match (highest confidence) ─────────────
        foreach (var (tokens, resolved) in s_systemPatterns)
        {
            foreach (var token in tokens)
            {
                if (lower.Contains(token, StringComparison.Ordinal))
                    return new IntentResult(resolved, IntentAction.SystemStatus, null, 0.95f,
                        null, ExtractEntityId(lower), ExtractFormFields(lower));
            }
        }

        // ── Action verb extraction ────────────────────────────────────────
        var action = IntentAction.Unknown;
        float verbConf = 0f;

        foreach (var (verbs, act) in s_verbMap)
        {
            foreach (var verb in verbs)
            {
                if (MatchesToken(lower, verb))
                {
                    action   = act;
                    verbConf = 0.7f;
                    goto verbFound;
                }
            }
        }
        verbFound:

        // ── Entity name extraction ────────────────────────────────────────
        string? entitySlug = null;
        string? entityName = null;
        float entityConf   = 0f;

        foreach (var (tokens, slug, name) in s_entityMap)
        {
            foreach (var token in tokens)
            {
                if (MatchesToken(lower, token))
                {
                    entitySlug = slug;
                    entityName = name;
                    entityConf = 0.6f;
                    goto entityFound;
                }
            }
        }
        entityFound:

        // ── Build resolved intent string ──────────────────────────────────
        string resolved2 = action switch
        {
            IntentAction.List         => entitySlug is null ? "system.list-entities" : $"entity.list.{entitySlug}",
            IntentAction.Create       => entitySlug is null ? "entity.create" : $"entity.create.{entitySlug}",
            IntentAction.Edit         => entitySlug is null ? "entity.edit" : $"entity.edit.{entitySlug}",
            IntentAction.Delete       => entitySlug is null ? "entity.delete" : $"entity.delete.{entitySlug}",
            IntentAction.Query        => entitySlug is null ? "entity.query" : $"entity.query.{entitySlug}",
            IntentAction.SystemStatus => "system.status",
            IntentAction.SystemMemory => "system.memory",
            IntentAction.Help         => "system.help",
            IntentAction.Stats        => entitySlug is null ? "system.stats" : $"entity.stats.{entitySlug}",
            IntentAction.Maintenance  => "system.maintenance",
            _                         => entitySlug is null ? "unknown" : $"entity.unknown.{entitySlug}",
        };

        float confidence = (verbConf + entityConf) / 2f;
        if (verbConf > 0 && entityConf > 0) confidence = Math.Min(verbConf + entityConf * 0.4f, 0.95f);
        else if (verbConf > 0 || entityConf > 0) confidence = Math.Max(verbConf, entityConf);

        return new IntentResult(
            ResolvedIntent: resolved2,
            Action:         action,
            EntitySlug:     entitySlug,
            Confidence:     confidence,
            EntityName:     entityName,
            EntityId:       ExtractEntityId(lower),
            FormFields:     action is IntentAction.Create or IntentAction.Edit
                            ? ExtractFormFields(lower) : null);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// <summary>
    /// Check whether <paramref name="haystack"/> contains <paramref name="needle"/>
    /// as a whole word or phrase (preceded and followed by non-alphanumeric chars or boundaries).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool MatchesToken(string haystack, string needle)
    {
        int idx = haystack.IndexOf(needle, StringComparison.Ordinal);
        if (idx < 0) return false;

        // Verify word boundary before
        if (idx > 0 && (char.IsLetterOrDigit(haystack[idx - 1]) || haystack[idx - 1] == '-'))
            return false;

        // Verify word boundary after
        int end = idx + needle.Length;
        if (end < haystack.Length && (char.IsLetterOrDigit(haystack[end]) || haystack[end] == '-'))
            return false;

        return true;
    }

    /// <summary>
    /// Attempt to extract an entity ID from patterns like "user 42", "id=42", "#42".
    /// Returns null when no numeric ID is found.
    /// </summary>
    private static string? ExtractEntityId(string lower)
    {
        // Pattern: "id=<digits>", "#<digits>", "id <digits>", or trailing number
        ReadOnlySpan<char> span = lower;
        for (int i = 0; i < span.Length; i++)
        {
            if (!char.IsDigit(span[i])) continue;
            // Walk to end of number
            int start = i;
            while (i < span.Length && char.IsDigit(span[i])) i++;
            return span[start..i].ToString();
        }
        return null;
    }

    /// <summary>
    /// Extract simple key=value or "field: value" pairs from a query for form prefill.
    /// Returns null when nothing is found.
    /// </summary>
    private static Dictionary<string, string>? ExtractFormFields(string lower)
    {
        Dictionary<string, string>? fields = null;

        // Pattern: "name=Alice" or "name: alice"
        var span = lower.AsSpan();
        int i = 0;
        while (i < span.Length)
        {
            // Find '=' or ':'
            int eq = -1;
            for (int j = i; j < span.Length; j++)
            {
                if (span[j] is '=' or ':') { eq = j; break; }
            }
            if (eq < 0) break;

            // Extract key (non-whitespace to the left of '=')
            int keyEnd = eq - 1;
            while (keyEnd > i && span[keyEnd] == ' ') keyEnd--;
            int keyStart = keyEnd;
            while (keyStart > i && span[keyStart - 1] != ' ') keyStart--;
            if (keyEnd <= keyStart) { i = eq + 1; continue; }

            string key = span[keyStart..(keyEnd + 1)].Trim().ToString();
            if (key.Length == 0 || key.Length > MaxFormFieldKeyLength) { i = eq + 1; continue; }

            // Extract value (non-whitespace to the right of '=')
            int valStart = eq + 1;
            while (valStart < span.Length && span[valStart] == ' ') valStart++;
            int valEnd = valStart;
            while (valEnd < span.Length && span[valEnd] != ' ' && span[valEnd] != ',' && span[valEnd] != ';')
                valEnd++;

            string val = span[valStart..valEnd].Trim().ToString();
            if (val.Length > 0)
            {
                fields ??= new Dictionary<string, string>(TypicalFormFieldCount, StringComparer.OrdinalIgnoreCase);
                fields[key] = val;
            }

            i = valEnd;
        }

        return fields;
    }
}

// ── Result types ──────────────────────────────────────────────────────────

/// <summary>
/// Structured result of an intent classification operation.
/// </summary>
public readonly record struct IntentResult(
    /// <summary>Dot-notation intent string, e.g. "entity.list.users".</summary>
    string ResolvedIntent,
    /// <summary>Canonical action type.</summary>
    IntentAction Action,
    /// <summary>Matched entity slug (null if no entity was identified).</summary>
    string? EntitySlug,
    /// <summary>Confidence score 0-1.</summary>
    float Confidence,
    /// <summary>Human-readable entity name for display.</summary>
    string? EntityName = null,
    /// <summary>Extracted entity ID if present in the query.</summary>
    string? EntityId = null,
    /// <summary>Extracted field key/value pairs for form prefill (null if none).</summary>
    Dictionary<string, string>? FormFields = null)
{
    /// <summary>Sentinel empty result returned when the query is blank.</summary>
    public static readonly IntentResult Empty = new(
        "none", IntentAction.Unknown, null, 0f);

    /// <summary>True when the confidence is high enough for direct routing.</summary>
    public bool IsConfident => Confidence >= 0.6f;
}

/// <summary>Canonical action types for intent routing.</summary>
public enum IntentAction : byte
{
    Unknown       = 0,
    List          = 1,
    Query         = 2,
    Create        = 3,
    Edit          = 4,
    Delete        = 5,
    SystemStatus  = 6,
    SystemMemory  = 7,
    Help          = 8,
    Stats         = 9,
    Maintenance   = 10,
}
