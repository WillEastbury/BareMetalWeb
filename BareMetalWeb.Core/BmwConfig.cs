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
}
