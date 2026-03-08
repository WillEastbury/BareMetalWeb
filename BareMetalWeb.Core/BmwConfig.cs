namespace BareMetalWeb.Core;

/// <summary>
/// Minimal bootstrap configuration loaded from a pipe-delimited text file
/// (<c>Metal.config</c>). Each line is <c>key|value</c>. Lines starting
/// with <c>#</c> are comments. Blank lines are ignored.
/// <para>
/// This provides only the handful of values needed before the data store is
/// available (data root, log folder, listen address, thread pool tuning).
/// Once the data store is up, runtime configuration flows through
/// <c>SettingsService</c> / <c>WellKnownSettings</c>.
/// </para>
/// </summary>
public sealed class BmwConfig
{
    private readonly Dictionary<string, string> _values;

    private BmwConfig(Dictionary<string, string> values)
    {
        _values = values;
    }

    /// <summary>
    /// Loads a <c>Metal.config</c> file from the given directory.
    /// If the file does not exist an empty config is returned.
    /// </summary>
    public static BmwConfig Load(string directory)
    {
        var path = Path.Combine(directory, "Metal.config");
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (!File.Exists(path))
            return new BmwConfig(values);

        foreach (var rawLine in File.ReadLines(path))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line[0] == '#')
                continue;

            int pipe = line.IndexOf('|');
            if (pipe < 0)
                continue;

            var key = line[..pipe].Trim();
            var value = line[(pipe + 1)..].Trim();

            if (key.Length > 0)
                values[key] = value;
        }

        return new BmwConfig(values);
    }

    /// <summary>Get a string value, or <paramref name="defaultValue"/> if absent.</summary>
    public string GetValue(string key, string defaultValue = "")
        => _values.TryGetValue(key, out var v) ? v : defaultValue;

    /// <summary>Get a typed value with conversion. Supports int, bool, string.</summary>
    public T GetValue<T>(string key, T defaultValue)
    {
        if (!_values.TryGetValue(key, out var raw))
            return defaultValue;

        var type = typeof(T);

        if (type == typeof(string))
            return (T)(object)raw;

        if (type == typeof(int) && int.TryParse(raw, out var i))
            return (T)(object)i;

        if (type == typeof(bool))
        {
            if (string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) || raw == "1")
                return (T)(object)true;
            if (string.Equals(raw, "false", StringComparison.OrdinalIgnoreCase) || raw == "0")
                return (T)(object)false;
        }

        if (type == typeof(double) && double.TryParse(raw, out var d))
            return (T)(object)d;

        if (type == typeof(long) && long.TryParse(raw, out var l))
            return (T)(object)l;

        return defaultValue;
    }

    /// <summary>Get a string array value (pipe-delimited within the value, using comma separator).</summary>
    public string[] GetArray(string key)
    {
        if (!_values.TryGetValue(key, out var raw) || string.IsNullOrWhiteSpace(raw))
            return Array.Empty<string>();

        var parts = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts;
    }

    /// <summary>Check whether a key exists.</summary>
    public bool HasKey(string key) => _values.ContainsKey(key);

    /// <summary>Returns all loaded keys (for diagnostics).</summary>
    public IEnumerable<string> Keys => _values.Keys;

    // ── Validation ────────────────────────────────────────────────────────────

    private static readonly HashSet<string> s_secretKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "EntraId.ClientSecret", "Admin.AllowWipeData"
    };

    /// <summary>
    /// Validates configuration values and returns a list of errors.
    /// If the list is non-empty, the server should fail-fast.
    /// </summary>
    public List<string> Validate()
    {
        var errors = new List<string>();

        // Port range validation
        ValidatePortRange(errors, "Kestrel.Port", 1, 65535);
        ValidatePortRange(errors, "Https.RedirectPort", 0, 65535); // 0 = disabled

        // Positive integer validation
        ValidatePositiveInt(errors, "Kestrel.MaxStreamsPerConnection");
        ValidatePositiveInt(errors, "Kestrel.InitialConnectionWindowSize");
        ValidatePositiveInt(errors, "Kestrel.InitialStreamWindowSize");
        ValidatePositiveInt(errors, "Kestrel.MaxConcurrentConnections");
        ValidatePositiveInt(errors, "Kestrel.KeepAliveTimeoutSeconds");
        ValidatePositiveInt(errors, "Kestrel.RequestHeadersTimeoutSeconds");
        ValidatePositiveInt(errors, "Kestrel.MaxRequestBodySizeMB");
        ValidatePositiveInt(errors, "ClientRequests.NormalRpsThreshold");
        ValidatePositiveInt(errors, "ClientRequests.SuspiciousRpsThreshold");
        ValidatePositiveInt(errors, "ClientRequests.BlockDurationMinutes");
        ValidatePositiveInt(errors, "StaticFiles.CacheSeconds");
        ValidatePositiveInt(errors, "Backup.IntervalMinutes");
        ValidatePositiveInt(errors, "Backup.RetentionDays");

        // Boolean validation
        ValidateBool(errors, "Kestrel.Http2Enabled");
        ValidateBool(errors, "Kestrel.Http3Enabled");
        ValidateBool(errors, "StaticFiles.Enabled");
        ValidateBool(errors, "Auth.AllowAccountCreation");
        ValidateBool(errors, "Multitenancy.Enabled");
        ValidateBool(errors, "Data.ResetOnStartup");
        ValidateBool(errors, "EntraId.Enabled");
        ValidateBool(errors, "Backup.Enabled");

        // Enum validation
        if (_values.TryGetValue("Https.RedirectMode", out var redirectMode))
        {
            if (!Enum.TryParse<HttpsRedirectMode>(redirectMode, ignoreCase: true, out _))
                errors.Add($"Https.RedirectMode: invalid value '{redirectMode}' (expected: Off, Always, IfAvailable)");
        }

        if (_values.TryGetValue("Logging.MinLevel", out var logLevel))
        {
            if (!Enum.TryParse<BmwLogLevel>(logLevel, ignoreCase: true, out _))
                errors.Add($"Logging.MinLevel: invalid value '{logLevel}' (expected: Trace, Debug, Info, Warn, Error, Fatal, Off)");
        }

        // EntraID — if enabled, require TenantId and ClientId
        if (GetValue("EntraId.Enabled", false))
        {
            if (string.IsNullOrWhiteSpace(GetValue("EntraId.TenantId")))
                errors.Add("EntraId.TenantId is required when EntraId.Enabled=true");
            if (string.IsNullOrWhiteSpace(GetValue("EntraId.ClientId")))
                errors.Add("EntraId.ClientId is required when EntraId.Enabled=true");
        }

        return errors;
    }

    /// <summary>
    /// Logs the loaded configuration to the console with secrets masked.
    /// </summary>
    public void LogConfiguration()
    {
        Console.WriteLine($"[BMW Config] Loaded {_values.Count} configuration key(s):");
        foreach (var kvp in _values.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
        {
            var display = s_secretKeys.Contains(kvp.Key) && !string.IsNullOrEmpty(kvp.Value)
                ? "****"
                : kvp.Value;
            Console.WriteLine($"[BMW Config]   {kvp.Key} = {display}");
        }
    }

    private void ValidatePortRange(List<string> errors, string key, int min, int max)
    {
        if (!_values.TryGetValue(key, out var raw)) return;
        if (!int.TryParse(raw, out var port))
            errors.Add($"{key}: '{raw}' is not a valid integer");
        else if (port < min || port > max)
            errors.Add($"{key}: {port} is out of range ({min}–{max})");
    }

    private void ValidatePositiveInt(List<string> errors, string key)
    {
        if (!_values.TryGetValue(key, out var raw)) return;
        if (!int.TryParse(raw, out var val))
            errors.Add($"{key}: '{raw}' is not a valid integer");
        else if (val < 0)
            errors.Add($"{key}: {val} must be >= 0");
    }

    private void ValidateBool(List<string> errors, string key)
    {
        if (!_values.TryGetValue(key, out var raw)) return;
        if (!string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(raw, "false", StringComparison.OrdinalIgnoreCase) &&
            raw != "1" && raw != "0")
            errors.Add($"{key}: '{raw}' is not a valid boolean (expected: true, false, 1, 0)");
    }
}
