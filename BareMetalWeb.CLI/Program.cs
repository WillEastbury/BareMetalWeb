using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace BareMetalWeb.CLI;

// AOT-compatible JSON contexts
[JsonSerializable(typeof(BmwConfig))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(Dictionary<string, JsonElement>[]))]
[JsonSerializable(typeof(JsonDocument))]
[JsonSerializable(typeof(JsonElement))]
[JsonSerializable(typeof(JsonElement[]))]
[JsonSerializable(typeof(MetaEntity[]))]
[JsonSerializable(typeof(MetaField[]))]
[JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal partial class BmwJsonContext : JsonSerializerContext { }

internal sealed class BmwConfig
{
    public string Url { get; set; } = "";
    public string ApiKey { get; set; } = "";
}

internal sealed class MetaEntity
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("slug")] public string Slug { get; set; } = "";
    [JsonPropertyName("permissions")] public string Permissions { get; set; } = "";
    [JsonPropertyName("showOnNav")] public bool ShowOnNav { get; set; }
    [JsonPropertyName("navGroup")] public string? NavGroup { get; set; }
    [JsonPropertyName("fields")] public MetaField[] Fields { get; set; } = [];
}

internal sealed class MetaField
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("label")] public string Label { get; set; } = "";
    [JsonPropertyName("type")] public string Type { get; set; } = "";
    [JsonPropertyName("order")] public int Order { get; set; }
    [JsonPropertyName("required")] public bool Required { get; set; }
    [JsonPropertyName("list")] public bool List { get; set; }
    [JsonPropertyName("view")] public bool View { get; set; }
    [JsonPropertyName("edit")] public bool Edit { get; set; }
    [JsonPropertyName("create")] public bool Create { get; set; }
    [JsonPropertyName("readOnly")] public bool ReadOnly { get; set; }
}

internal static class Program
{
    private static string ConfigDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".metal");
    private static string ConfigPath => Path.Combine(ConfigDir, "config.json");
    private static string CookiePath => Path.Combine(ConfigDir, "cookies");

    private static CookieContainer _cookies = new();
    private static BmwConfig _config = new();
    private static HttpClient _http = null!;
    private static MetaEntity[]? _meta;

    static async Task<int> Main(string[] args)
    {
        try
        {
        LoadConfig();
        InitHttpClient();

        if (args.Length == 0)
        {
            PrintUsage();
            return 0;
        }

        var cmd = args[0].ToLowerInvariant();
        var rest = args[1..];

        try
        {
            return cmd switch
            {
                "connect" => Connect(rest),
                "login" => await Login(rest),
                "types" => await ListTypes(),
                "list" => await ListEntities(rest),
                "get" => await GetEntity(rest),
                "create" => await CreateEntity(rest),
                "update" => await UpdateEntity(rest),
                "delete" => await DeleteEntity(rest),
                "query" => await QueryEntities(rest),
                "first" => await FirstEntity(rest),
                "config" => ShowConfig(),
                "help" or "--help" or "-h" => Help(0),
                _ => Help(1, $"Unknown command: {cmd}")
            };
        }
        catch (HttpRequestException ex)
        {
            Console.Error.WriteLine($"HTTP error: {ex.Message}");
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
        } // end outer try
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Fatal: {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
            return 255;
        }
    }

    // --- connect ---
    static int Connect(string[] args)
    {
        if (args.Length < 1) return Help(1, "Usage: metal connect <url> [api-key]");
        _config.Url = args[0].TrimEnd('/');
        _config.ApiKey = args.Length > 1 ? args[1] : "";
        SaveConfig();
        InitHttpClient();
        Console.WriteLine($"Connected to {_config.Url}");
        if (!string.IsNullOrEmpty(_config.ApiKey))
            Console.WriteLine("API key set.");
        return 0;
    }

    // --- login ---
    static async Task<int> Login(string[] args)
    {
        if (string.IsNullOrEmpty(_config.Url)) return Help(1, "Not connected. Run: metal connect <url>");

        // metal login --outofband → device code flow (no browser)
        // metal login → device code flow (opens browser)
        // metal login <user> <pass> → direct credentials
        bool outOfBand = args.Any(a => a == "--outofband");
        var filtered = args.Where(a => a != "--outofband").ToArray();

        if (filtered.Length >= 2)
            return await LoginDirect(filtered[0], filtered[1]);
        if (filtered.Length == 0)
            return await LoginDeviceCode(!outOfBand);

        // Single arg — ambiguous, treat as username and prompt for password
        Console.Write("Password: "); var pass = ReadPassword();
        return await LoginDirect(filtered[0], pass);
    }

    static async Task<int> LoginDirect(string user, string pass)
    {
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("username", user),
            new KeyValuePair<string, string>("password", pass)
        });
        var resp = await _http.PostAsync("/login", content);
        if (resp.IsSuccessStatusCode || resp.StatusCode == HttpStatusCode.Redirect || resp.StatusCode == HttpStatusCode.Found)
        {
            SaveCookies();
            Console.WriteLine("Login successful. Session saved.");
            return 0;
        }
        Console.Error.WriteLine($"Login failed: {resp.StatusCode}");
        return 1;
    }

    static async Task<int> LoginDeviceCode(bool openBrowser)
    {
        // Step 1: Request device code
        var resp = await _http.PostAsync("/api/device/code", new StringContent("{}", Encoding.UTF8, "application/json"));
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(body);
        var deviceCode = doc.RootElement.GetProperty("device_code").GetString()!;
        var userCode = doc.RootElement.GetProperty("user_code").GetString()!;
        var verifyUrl = doc.RootElement.GetProperty("verification_url").GetString()!;
        var interval = doc.RootElement.GetProperty("interval").GetInt32();
        var expiresIn = doc.RootElement.GetProperty("expires_in").GetInt32();

        // Step 2: Display code and optionally open browser
        Console.WriteLine();
        Console.WriteLine("  To sign in, open your browser to:");
        Console.WriteLine($"    {verifyUrl}");
        Console.WriteLine();
        Console.WriteLine($"  Enter code: {userCode}");
        Console.WriteLine();

        if (openBrowser)
        {
            var url = $"{verifyUrl}?code={Uri.EscapeDataString(userCode)}";
            try
            {
                if (OperatingSystem.IsWindows())
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
                else if (OperatingSystem.IsMacOS())
                    System.Diagnostics.Process.Start("open", url);
                else
                    System.Diagnostics.Process.Start("xdg-open", url);
                Console.WriteLine("  Browser opened. Waiting for approval...");
            }
            catch
            {
                Console.WriteLine("  Could not open browser. Please open the URL manually.");
            }
        }
        else
        {
            Console.WriteLine("  Waiting for approval...");
        }
        Console.WriteLine();

        // Step 3: Poll for approval
        var deadline = DateTime.UtcNow.AddSeconds(expiresIn);
        while (DateTime.UtcNow < deadline)
        {
            await Task.Delay(interval * 1000);
            var pollBody = JsonSerializer.Serialize(new Dictionary<string, string> { ["device_code"] = deviceCode }, BmwJsonContext.Default.DictionaryStringString);
            var pollResp = await _http.PostAsync("/api/device/token", new StringContent(pollBody, Encoding.UTF8, "application/json"));
            var pollText = await pollResp.Content.ReadAsStringAsync();
            var pollDoc = JsonDocument.Parse(pollText);
            var status = pollDoc.RootElement.GetProperty("status").GetString();

            if (status == "approved")
            {
                SaveCookies();
                var userName = pollDoc.RootElement.TryGetProperty("user", out var u) ? u.GetString() : "unknown";
                Console.WriteLine($"  Logged in as {userName}. Session saved.");
                return 0;
            }
            if (status == "expired" || status == "denied")
            {
                Console.Error.WriteLine($"  Login {status}.");
                return 1;
            }
            Console.Write(".");
        }
        Console.Error.WriteLine("\n  Login timed out.");
        return 1;
    }

    // --- types ---
    static async Task<int> ListTypes()
    {
        var meta = await FetchMeta();
        if (meta == null) return 1;
        Console.WriteLine($"{"Slug",-25} {"Name",-30} {"Permissions",-20} Fields");
        Console.WriteLine(new string('-', 85));
        foreach (var e in meta)
            Console.WriteLine($"{e.Slug,-25} {e.Name,-30} {e.Permissions,-20} {e.Fields.Length}");
        return 0;
    }

    // --- list ---
    static async Task<int> ListEntities(string[] args)
    {
        if (args.Length < 1) return Help(1, "Usage: metal list <type>");
        var slug = args[0];
        var resp = await _http.GetAsync($"/api/{slug}");
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        var items = JsonSerializer.Deserialize(body, BmwJsonContext.Default.JsonElement);
        await PrintTable(slug, items);
        return 0;
    }

    // --- get ---
    static async Task<int> GetEntity(string[] args)
    {
        if (args.Length < 2) return Help(1, "Usage: metal get <type> <id>");
        var resp = await _http.GetAsync($"/api/{args[0]}/{args[1]}");
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        PrintJson(body);
        return 0;
    }

    // --- create ---
    static async Task<int> CreateEntity(string[] args)
    {
        if (args.Length < 2) return Help(1, "Usage: metal create <type> key=value [key=value...]");
        var slug = args[0];
        var obj = ParseKeyValues(args[1..]);
        var json = JsonSerializer.Serialize(obj, BmwJsonContext.Default.DictionaryStringString);
        var resp = await _http.PostAsync($"/api/{slug}",
            new StringContent(json, Encoding.UTF8, "application/json"));
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        Console.WriteLine("Created:");
        PrintJson(body);
        return 0;
    }

    // --- update ---
    static async Task<int> UpdateEntity(string[] args)
    {
        if (args.Length < 3) return Help(1, "Usage: metal update <type> <id> key=value [key=value...]");
        var slug = args[0]; var id = args[1];
        var obj = ParseKeyValues(args[2..]);
        var json = JsonSerializer.Serialize(obj, BmwJsonContext.Default.DictionaryStringString);
        var req = new HttpRequestMessage(HttpMethod.Patch, $"/api/{slug}/{id}")
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var resp = await _http.SendAsync(req);
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        Console.WriteLine("Updated:");
        PrintJson(body);
        return 0;
    }

    // --- delete ---
    static async Task<int> DeleteEntity(string[] args)
    {
        if (args.Length < 2) return Help(1, "Usage: metal delete <type> <id>");
        var resp = await _http.DeleteAsync($"/api/{args[0]}/{args[1]}");
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        Console.WriteLine("Deleted.");
        return 0;
    }

    // --- query ---
    static async Task<int> QueryEntities(string[] args)
    {
        if (args.Length < 1) return Help(1, "Usage: metal query <type> [field=X] [op=eq] [value=Y] [q=text] [sort=F] [dir=asc] [skip=0] [top=10]");
        var slug = args[0];
        var qs = new StringBuilder();
        for (int i = 1; i < args.Length; i++)
        {
            var eqIdx = args[i].IndexOf('=');
            if (eqIdx <= 0) continue;
            var k = args[i][..eqIdx]; var v = args[i][(eqIdx + 1)..];
            qs.Append(qs.Length == 0 ? '?' : '&');
            qs.Append(Uri.EscapeDataString(k)).Append('=').Append(Uri.EscapeDataString(v));
        }
        var resp = await _http.GetAsync($"/api/{slug}{qs}");
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        var items = JsonSerializer.Deserialize(body, BmwJsonContext.Default.JsonElement);
        await PrintTable(slug, items);
        return 0;
    }

    // --- first ---
    static async Task<int> FirstEntity(string[] args)
    {
        if (args.Length < 1) return Help(1, "Usage: metal first <type> [q=text] [field=X op=eq value=Y] [sort=F] [dir=asc|desc]");
        var slug = args[0];
        // Default sort by CreatedOnUtc desc (newest first), overridable
        var hasSort = args.Skip(1).Any(a => a.StartsWith("sort=", StringComparison.OrdinalIgnoreCase));
        var qs = new StringBuilder("?top=1");
        if (!hasSort)
            qs.Append("&sort=CreatedOnUtc&dir=desc");
        for (int i = 1; i < args.Length; i++)
        {
            var eqIdx = args[i].IndexOf('=');
            if (eqIdx <= 0) continue;
            var k = args[i][..eqIdx]; var v = args[i][(eqIdx + 1)..];
            qs.Append('&').Append(Uri.EscapeDataString(k)).Append('=').Append(Uri.EscapeDataString(v));
        }
        var resp = await _http.GetAsync($"/api/{slug}{qs}");
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        var items = JsonSerializer.Deserialize(body, BmwJsonContext.Default.JsonElement);
        if (items.ValueKind == JsonValueKind.Array && items.GetArrayLength() == 0)
        {
            Console.WriteLine("No results.");
            return 0;
        }
        var first = items.ValueKind == JsonValueKind.Array ? items[0] : items;
        foreach (var prop in first.EnumerateObject())
        {
            var val = prop.Value.ValueKind == JsonValueKind.String ? prop.Value.GetString() : prop.Value.ToString();
            Console.WriteLine($"  {prop.Name,-20} {val}");
        }
        return 0;
    }

    // --- config ---
    static int ShowConfig()
    {
        Console.WriteLine($"URL:     {_config.Url}");
        Console.WriteLine($"API Key: {(string.IsNullOrEmpty(_config.ApiKey) ? "(none)" : "***" + _config.ApiKey[^4..])}");
        Console.WriteLine($"Config:  {ConfigPath}");
        Console.WriteLine($"Cookies: {CookiePath}");
        return 0;
    }

    // --- helpers ---
    static async Task<MetaEntity[]?> FetchMeta()
    {
        if (_meta != null) return _meta;
        if (string.IsNullOrEmpty(_config.Url)) { Console.Error.WriteLine("Not connected. Run: metal connect <url>"); return null; }
        var resp = await _http.GetAsync("/api/_meta");
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return null; }
        var body = await resp.Content.ReadAsStringAsync();
        _meta = JsonSerializer.Deserialize(body, BmwJsonContext.Default.MetaEntityArray);
        return _meta;
    }

    static async Task PrintTable(string slug, JsonElement items)
    {
        if (items.ValueKind != JsonValueKind.Array) { Console.WriteLine(items.ToString()); return; }
        var meta = await FetchMeta();
        var entity = meta?.FirstOrDefault(e => string.Equals(e.Slug, slug, StringComparison.OrdinalIgnoreCase));
        var listFields = entity?.Fields.Where(f => f.List).OrderBy(f => f.Order).Select(f => f.Name).ToArray();

        // Collect all rows to compute column widths
        var rows = new List<string[]>();
        string[] headers;
        if (listFields != null && listFields.Length > 0)
        {
            headers = new[] { "Id" }.Concat(listFields).ToArray();
        }
        else
        {
            // Fallback: use keys from first item
            var first = items.EnumerateArray().FirstOrDefault();
            headers = first.ValueKind == JsonValueKind.Object
                ? first.EnumerateObject().Select(p => p.Name).Take(6).ToArray()
                : new[] { "Value" };
        }

        foreach (var item in items.EnumerateArray())
        {
            var row = new string[headers.Length];
            for (int i = 0; i < headers.Length; i++)
            {
                if (item.TryGetProperty(headers[i], out var val))
                    row[i] = val.ValueKind == JsonValueKind.String ? val.GetString() ?? "" : val.ToString();
                else
                    row[i] = "";
            }
            rows.Add(row);
        }

        // Compute widths
        var widths = new int[headers.Length];
        for (int i = 0; i < headers.Length; i++)
            widths[i] = headers[i].Length;
        foreach (var row in rows)
            for (int i = 0; i < headers.Length; i++)
                widths[i] = Math.Max(widths[i], Math.Min(row[i].Length, 40));

        // Print
        for (int i = 0; i < headers.Length; i++)
            Console.Write(headers[i].PadRight(widths[i] + 2));
        Console.WriteLine();
        for (int i = 0; i < headers.Length; i++)
            Console.Write(new string('-', widths[i]) + "  ");
        Console.WriteLine();
        foreach (var row in rows)
        {
            for (int i = 0; i < headers.Length; i++)
            {
                var v = row[i].Length > 40 ? row[i][..37] + "..." : row[i];
                Console.Write(v.PadRight(widths[i] + 2));
            }
            Console.WriteLine();
        }
        Console.WriteLine($"\n{rows.Count} result(s).");
    }

    static Dictionary<string, string> ParseKeyValues(string[] args)
    {
        var dict = new Dictionary<string, string>();
        foreach (var arg in args)
        {
            var eqIdx = arg.IndexOf('=');
            if (eqIdx > 0) dict[arg[..eqIdx]] = arg[(eqIdx + 1)..];
        }
        return dict;
    }

    static void PrintJson(string body)
    {
        try
        {
            var doc = JsonDocument.Parse(body);
            Console.WriteLine(JsonSerializer.Serialize(doc.RootElement, BmwJsonContext.Default.JsonElement));
        }
        catch { Console.WriteLine(body); }
    }

    static async Task PrintError(HttpResponseMessage resp)
    {
        var body = await resp.Content.ReadAsStringAsync();
        Console.Error.WriteLine($"Error {(int)resp.StatusCode}: {body}");
    }

    static void InitHttpClient()
    {
        LoadCookies();
        var handler = new HttpClientHandler { CookieContainer = _cookies, AllowAutoRedirect = false, UseCookies = true };
        _http = new HttpClient(handler);
        if (!string.IsNullOrEmpty(_config.Url))
            _http.BaseAddress = new Uri(_config.Url);
        if (!string.IsNullOrEmpty(_config.ApiKey))
            _http.DefaultRequestHeaders.Add("ApiKey", _config.ApiKey);
    }

    static void LoadConfig()
    {
        if (!File.Exists(ConfigPath)) return;
        var json = File.ReadAllText(ConfigPath);
        _config = JsonSerializer.Deserialize(json, BmwJsonContext.Default.BmwConfig) ?? new BmwConfig();
    }

    static void SaveConfig()
    {
        Directory.CreateDirectory(ConfigDir);
        File.WriteAllText(ConfigPath, JsonSerializer.Serialize(_config, BmwJsonContext.Default.BmwConfig));
    }

    static void SaveCookies()
    {
        if (string.IsNullOrEmpty(_config.Url)) return;
        Directory.CreateDirectory(ConfigDir);
        var uri = new Uri(_config.Url);
        var cookies = _cookies.GetCookies(uri);
        var lines = new List<string>();
        foreach (Cookie c in cookies)
            lines.Add($"{c.Name}\t{c.Value}\t{c.Domain}\t{c.Path}\t{c.Expires:O}\t{c.Secure}");
        File.WriteAllLines(CookiePath, lines);
    }

    static void LoadCookies()
    {
        _cookies = new CookieContainer();
        if (!File.Exists(CookiePath) || string.IsNullOrEmpty(_config.Url)) return;
        var uri = new Uri(_config.Url);
        foreach (var line in File.ReadAllLines(CookiePath))
        {
            var parts = line.Split('\t');
            if (parts.Length < 4) continue;
            var c = new Cookie(parts[0], parts[1], parts[3], parts[2]);
            if (parts.Length > 4 && DateTime.TryParse(parts[4], out var exp)) c.Expires = exp;
            if (parts.Length > 5 && bool.TryParse(parts[5], out var sec)) c.Secure = sec;
            _cookies.Add(uri, c);
        }
    }

    static string ReadPassword()
    {
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter) { Console.WriteLine(); break; }
            if (key.Key == ConsoleKey.Backspace && sb.Length > 0) { sb.Remove(sb.Length - 1, 1); Console.Write("\b \b"); }
            else if (!char.IsControl(key.KeyChar)) { sb.Append(key.KeyChar); Console.Write('*'); }
        }
        return sb.ToString();
    }

    static void PrintUsage()
    {
        Console.WriteLine("metal - BareMetalWeb CLI");
        Console.WriteLine();
        Console.WriteLine("Usage: metal <command> [args]");
        Console.WriteLine();
        Console.WriteLine("Run 'metal help' for available commands.");
    }

    static int Help(int exitCode, string? error = null)
    {
        if (error != null) Console.Error.WriteLine($"Error: {error}\n");
        Console.WriteLine("""
            metal - BareMetalWeb CLI

            Usage: metal <command> [args]

            Connection:
              connect <url> [api-key]     Set server URL and optional API key
              login                       Login via device code (opens browser)
              login --outofband           Login via device code (no browser)
              login <user> <pass>         Login with username/password directly
              config                      Show current configuration

            Entity Operations:
              types                       List available entity types
              list <type>                 List all entities of a type
              get <type> <id>             Get a single entity by ID
              create <type> k=v [k=v..]   Create a new entity
              update <type> <id> k=v ..   Update an entity (PATCH)
              delete <type> <id>          Delete an entity

            Query:
              query <type> [params]       Query with filters
                field=Name op=contains value=text
                q=searchtext sort=Field dir=desc skip=0 top=10
              first <type> [q=text]       Get first matching entity (detail view)

            Examples:
              metal connect https://mysite.azurewebsites.net abc123key
              metal types
              metal list to-do
              metal create to-do Title="Buy milk" Notes="From store"
              metal query to-do q=milk sort=Deadline dir=asc top=5
              metal get to-do abc123
              metal update to-do abc123 IsCompleted=true
              metal delete to-do abc123
            """);
        return exitCode;
    }
}
