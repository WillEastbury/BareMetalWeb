using System.Buffers;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;

namespace BareMetalWeb.CLI;

// ── Manual JSON helpers (replaces JsonSerializer + source-gen context) ────────

internal static class CliJson
{
    internal static string SerializeDict(Dictionary<string, string> dict)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        foreach (var (k, v) in dict)
            w.WriteString(k, v);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string SerializeSeedRequest(SeedRequest req)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        w.WriteBoolean("clearExisting", req.ClearExisting);
        w.WriteStartObject("entities");
        foreach (var (k, v) in req.Entities)
            w.WriteNumber(k, v);
        w.WriteEndObject();
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static JobStatusResponse? DeserializeJobStatus(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        return new JobStatusResponse
        {
            JobId = Str(r, "jobId"),
            OperationName = Str(r, "operationName"),
            Status = Str(r, "status"),
            PercentComplete = r.TryGetProperty("percentComplete", out var pc) ? pc.GetInt32() : 0,
            Description = StrOrNull(r, "description"),
            Error = StrOrNull(r, "error"),
            StatusUrl = StrOrNull(r, "statusUrl"),
        };
    }

    internal static MetaEntity[]? DeserializeMetaEntities(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Array) return null;
        var list = new MetaEntity[root.GetArrayLength()];
        int i = 0;
        foreach (var el in root.EnumerateArray())
        {
            list[i++] = new MetaEntity
            {
                Name = Str(el, "name"),
                Slug = Str(el, "slug"),
                Permissions = Str(el, "permissions"),
                ShowOnNav = el.TryGetProperty("showOnNav", out var sn) && sn.GetBoolean(),
                NavGroup = StrOrNull(el, "navGroup"),
                NavOrder = el.TryGetProperty("navOrder", out var no) ? no.GetInt32() : 0,
                ViewType = StrOrNull(el, "viewType"),
                ParentField = StrOrNull(el, "parentField"),
                Fields = DeserializeFields(el),
                Commands = DeserializeCommands(el),
            };
        }
        return list;
    }

    internal static BmwConfig DeserializeConfig(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        return new BmwConfig
        {
            Url = Str(r, "url"),
            ApiKey = Str(r, "apiKey"),
        };
    }

    internal static string SerializeConfig(BmwConfig cfg)
    {
        var buf = new ArrayBufferWriter<byte>(128);
        using var w = new Utf8JsonWriter(buf, new JsonWriterOptions { Indented = true });
        w.WriteStartObject();
        w.WriteString("url", cfg.Url);
        w.WriteString("apiKey", cfg.ApiKey);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string PrettyPrint(string body)
    {
        using var doc = JsonDocument.Parse(body);
        var buf = new ArrayBufferWriter<byte>(body.Length + 256);
        using var w = new Utf8JsonWriter(buf, new JsonWriterOptions { Indented = true });
        doc.RootElement.WriteTo(w);
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    private static MetaField[] DeserializeFields(JsonElement parent)
    {
        if (!parent.TryGetProperty("fields", out var arr) || arr.ValueKind != JsonValueKind.Array)
            return [];
        var list = new MetaField[arr.GetArrayLength()];
        int i = 0;
        foreach (var el in arr.EnumerateArray())
        {
            list[i++] = new MetaField
            {
                Name = Str(el, "name"),
                Label = Str(el, "label"),
                Type = Str(el, "type"),
                Order = el.TryGetProperty("order", out var o) ? o.GetInt32() : 0,
                Required = el.TryGetProperty("required", out var rq) && rq.GetBoolean(),
                List = el.TryGetProperty("list", out var li) && li.GetBoolean(),
                View = el.TryGetProperty("view", out var vi) && vi.GetBoolean(),
                Edit = el.TryGetProperty("edit", out var ed) && ed.GetBoolean(),
                Create = el.TryGetProperty("create", out var cr) && cr.GetBoolean(),
                ReadOnly = el.TryGetProperty("readOnly", out var ro) && ro.GetBoolean(),
                Lookup = DeserializeLookup(el),
            };
        }
        return list;
    }

    private static MetaLookup? DeserializeLookup(JsonElement parent)
    {
        if (!parent.TryGetProperty("lookup", out var el) || el.ValueKind != JsonValueKind.Object)
            return null;
        return new MetaLookup
        {
            TargetSlug = StrOrNull(el, "targetSlug"),
            TargetName = StrOrNull(el, "targetName"),
            ValueField = StrOrNull(el, "valueField"),
            DisplayField = StrOrNull(el, "displayField"),
            QueryField = StrOrNull(el, "queryField"),
            QueryOperator = StrOrNull(el, "queryOperator"),
            QueryValue = StrOrNull(el, "queryValue"),
            SortField = StrOrNull(el, "sortField"),
            SortDirection = StrOrNull(el, "sortDirection"),
        };
    }

    private static MetaCommand[] DeserializeCommands(JsonElement parent)
    {
        if (!parent.TryGetProperty("commands", out var arr) || arr.ValueKind != JsonValueKind.Array)
            return [];
        var list = new MetaCommand[arr.GetArrayLength()];
        int i = 0;
        foreach (var el in arr.EnumerateArray())
        {
            list[i++] = new MetaCommand
            {
                Name = Str(el, "name"),
                Label = Str(el, "label"),
                Icon = StrOrNull(el, "icon"),
                ConfirmMessage = StrOrNull(el, "confirmMessage"),
                Destructive = el.TryGetProperty("destructive", out var d) && d.GetBoolean(),
                Permission = StrOrNull(el, "permission"),
                Order = el.TryGetProperty("order", out var o) ? o.GetInt32() : 0,
            };
        }
        return list;
    }

    private static string Str(JsonElement el, string name)
        => el.TryGetProperty(name, out var v) ? v.GetString() ?? "" : "";

    private static string? StrOrNull(JsonElement el, string name)
        => el.TryGetProperty(name, out var v) ? v.GetString() : null;
}

internal sealed class BmwConfig
{
    public string Url { get; set; } = "";
    public string ApiKey { get; set; } = "";
}

internal sealed class MetaEntity
{
public string Name { get; set; } = "";
public string Slug { get; set; } = "";
public string Permissions { get; set; } = "";
public bool ShowOnNav { get; set; }
public string? NavGroup { get; set; }
public int NavOrder { get; set; }
public string? ViewType { get; set; }
public MetaField[] Fields { get; set; } = [];
public MetaCommand[] Commands { get; set; } = [];
public string? ParentField { get; set; }
}

internal sealed class MetaField
{
public string Name { get; set; } = "";
public string Label { get; set; } = "";
public string Type { get; set; } = "";
public int Order { get; set; }
public bool Required { get; set; }
public bool List { get; set; }
public bool View { get; set; }
public bool Edit { get; set; }
public bool Create { get; set; }
public bool ReadOnly { get; set; }
public MetaLookup? Lookup { get; set; }
}

internal sealed class MetaLookup
{
public string? TargetSlug { get; set; }
public string? TargetName { get; set; }
public string? ValueField { get; set; }
public string? DisplayField { get; set; }
public string? QueryField { get; set; }
public string? QueryOperator { get; set; }
public string? QueryValue { get; set; }
public string? SortField { get; set; }
public string? SortDirection { get; set; }
}

internal sealed class MetaCommand
{
public string Name { get; set; } = "";
public string Label { get; set; } = "";
public string? Icon { get; set; }
public string? ConfirmMessage { get; set; }
public bool Destructive { get; set; }
public string? Permission { get; set; }
public int Order { get; set; }
}

internal sealed class SeedRequest
{
public bool ClearExisting { get; set; }
public Dictionary<string, int> Entities { get; set; } = new();
}

internal sealed class JobStatusResponse
{
public string JobId { get; set; } = "";
public string OperationName { get; set; } = "";
public string Status { get; set; } = "";
public int PercentComplete { get; set; }
public string? Description { get; set; }
public string? Error { get; set; }
public string? StatusUrl { get; set; }
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
                "logout" => await Logout(),
                "types" => await ListTypes(),
                "schema" => await ShowSchema(rest),
                "list" => await ListEntities(rest),
                "get" => await GetEntity(rest),
                "create" => await CreateEntity(rest),
                "update" => await UpdateEntity(rest),
                "delete" => await DeleteEntity(rest),
                "query" => await QueryEntities(rest),
                "first" => await FirstEntity(rest),
                "lookup" => await LookupEntities(rest),
                "lookup-field" => await LookupField(rest),
                "aggregate" => await Aggregate(rest),
                "command" => await RunCommand(rest),
                "import" => await ImportEntities(rest),
                "export" => await ExportEntities(rest),
                "seed" => await SeedData(rest),
                "config" => ShowConfig(),
                "help" or "--help" or "-h" => Help(0),
                "--version" or "-v" or "version" => ShowVersion(),
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
        bool outOfBand = false;
        foreach (var a in args)
            if (a == "--outofband") { outOfBand = true; break; }
        var filteredList = new List<string>();
        foreach (var a in args)
            if (a != "--outofband") filteredList.Add(a);
        var filtered = filteredList.ToArray();

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
        // Fetch CSRF token first
        var getResp = await _http.GetAsync("/login");
        var csrfToken = "";
        if (getResp.IsSuccessStatusCode)
        {
            var html = await getResp.Content.ReadAsStringAsync();
            var match = System.Text.RegularExpressions.Regex.Match(html, @"name=""csrf_token""[^>]*value=""([^""]*)""");
            if (!match.Success)
                match = System.Text.RegularExpressions.Regex.Match(html, @"id=""csrf_token""[^>]*value=""([^""]*)""");
            // Also try extracting from cookie
            if (!match.Success && _config.Url != null)
            {
                var cookies = _cookies.GetCookies(new Uri(_config.Url));
                Cookie? csrfCookie = null;
                foreach (Cookie c in cookies)
                    if (c.Name == "csrf_token") { csrfCookie = c; break; }
                if (csrfCookie != null) csrfToken = csrfCookie.Value;
            }
            else if (match.Success)
                csrfToken = match.Groups[1].Value;
        }

        var fields = new List<KeyValuePair<string, string>>
        {
            new("email", user),
            new("password", pass)
        };
        if (!string.IsNullOrEmpty(csrfToken))
            fields.Add(new("csrf_token", csrfToken));

        var content = new FormUrlEncodedContent(fields);
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
                if (OperatingSystem.IsMacOS())
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
            var pollBody = CliJson.SerializeDict(new Dictionary<string, string> { ["device_code"] = deviceCode });
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

    // --- logout ---
    static async Task<int> Logout()
    {
        if (string.IsNullOrEmpty(_config.Url)) return Help(1, "Not connected. Run: metal connect <url>");
        try { await PostWithCsrf("/logout", null); } catch { /* best-effort */ }
        if (File.Exists(CookiePath)) File.Delete(CookiePath);
        _cookies = new CookieContainer();
        InitHttpClient();
        Console.WriteLine("Logged out. Session cleared.");
        return 0;
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

    // --- schema ---
    static async Task<int> ShowSchema(string[] args)
    {
        if (args.Length < 1) return Help(1, "Usage: metal schema <type>");
        var slug = args[0];
        var resp = await _http.GetAsync($"/meta/{slug}");
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;

        var name = root.TryGetProperty("name", out var n) ? n.GetString() : slug;
        Console.WriteLine($"Entity: {name} ({slug})");
        if (root.TryGetProperty("permissions", out var perm)) Console.WriteLine($"Permissions: {perm.GetString()}");
        if (root.TryGetProperty("viewType", out var vt)) Console.WriteLine($"View Type: {vt.GetString()}");
        Console.WriteLine();

        // Fields
        if (root.TryGetProperty("fields", out var fields) && fields.ValueKind == JsonValueKind.Array)
        {
            Console.WriteLine($"{"Field",-22} {"Label",-22} {"Type",-12} {"Req",-5} {"List",-5} {"View",-5} {"Edit",-5} Lookup");
            Console.WriteLine(new string('-', 100));
            foreach (var f in fields.EnumerateArray())
            {
                var fName = f.TryGetProperty("name", out var fn) ? fn.GetString() ?? "" : "";
                var fLabel = f.TryGetProperty("label", out var fl) ? fl.GetString() ?? "" : "";
                var fType = f.TryGetProperty("type", out var ft) ? ft.GetString() ?? "" : "";
                var fReq = f.TryGetProperty("required", out var fr) && fr.GetBoolean() ? "Y" : "";
                var fList = f.TryGetProperty("list", out var fli) && fli.GetBoolean() ? "Y" : "";
                var fView = f.TryGetProperty("view", out var fv) && fv.GetBoolean() ? "Y" : "";
                var fEdit = f.TryGetProperty("edit", out var fe) && fe.GetBoolean() ? "Y" : "";
                var lookup = "";
                if (f.TryGetProperty("lookup", out var lu) && lu.ValueKind == JsonValueKind.Object)
                {
                    var ts = lu.TryGetProperty("targetSlug", out var t) ? t.GetString() : "";
                    var df = lu.TryGetProperty("displayField", out var d) ? d.GetString() : "";
                    lookup = $"→ {ts} ({df})";
                }
                Console.WriteLine($"{fName,-22} {fLabel,-22} {fType,-12} {fReq,-5} {fList,-5} {fView,-5} {fEdit,-5} {lookup}");
            }
        }

        // Commands
        if (root.TryGetProperty("commands", out var cmds) && cmds.ValueKind == JsonValueKind.Array && cmds.GetArrayLength() > 0)
        {
            Console.WriteLine();
            Console.WriteLine("Commands:");
            foreach (var c in cmds.EnumerateArray())
            {
                var cName = c.TryGetProperty("name", out var cn) ? cn.GetString() ?? "" : "";
                var cLabel = c.TryGetProperty("label", out var cl) ? cl.GetString() ?? "" : "";
                var destr = c.TryGetProperty("destructive", out var cd) && cd.GetBoolean() ? " [DESTRUCTIVE]" : "";
                Console.WriteLine($"  {cName,-20} {cLabel}{destr}");
            }
        }
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
        using var _doc = JsonDocument.Parse(body); var items = UnwrapItems(_doc.RootElement);
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
        var json = CliJson.SerializeDict(obj);
        var resp = await PostWithCsrf($"/api/{slug}",
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
        var json = CliJson.SerializeDict(obj);
        var req = new HttpRequestMessage(HttpMethod.Patch, $"/api/{slug}/{id}")
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        var resp = await SendWithCsrf(req);
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
        var req = new HttpRequestMessage(HttpMethod.Delete, $"/api/{args[0]}/{args[1]}");
        var resp = await SendWithCsrf(req);
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
        using var _doc = JsonDocument.Parse(body); var items = UnwrapItems(_doc.RootElement);
        await PrintTable(slug, items);
        return 0;
    }

    // --- first ---
    static async Task<int> FirstEntity(string[] args)
    {
        if (args.Length < 1) return Help(1, "Usage: metal first <type> [q=text] [field=X op=eq value=Y] [sort=F] [dir=asc|desc]");
        var slug = args[0];
        bool hasSort = false;
        for (int i = 1; i < args.Length; i++)
            if (args[i].StartsWith("sort=", StringComparison.OrdinalIgnoreCase)) { hasSort = true; break; }
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
        using var _doc = JsonDocument.Parse(body); var items = UnwrapItems(_doc.RootElement);
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

    // --- lookup ---
    static async Task<int> LookupEntities(string[] args)
    {
        if (args.Length < 1) return Help(1, "Usage: metal lookup <type> [filter=field:value] [sort=Field] [dir=asc] [skip=0] [top=20] [search=text] [searchField=name]");
        var slug = args[0];
        var qs = BuildQueryString(args[1..]);
        var resp = await _http.GetAsync($"/api/_lookup/{slug}{qs}");
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        using var _doc = JsonDocument.Parse(body); var items = UnwrapItems(_doc.RootElement);
        await PrintTable(slug, items);
        return 0;
    }

    // --- lookup-field ---
    static async Task<int> LookupField(string[] args)
    {
        if (args.Length < 3) return Help(1, "Usage: metal lookup-field <type> <id> <field>");
        var resp = await _http.GetAsync($"/api/_lookup/{args[0]}/_field/{args[1]}/{args[2]}");
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        try
        {
            var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("value", out var val))
            {
                Console.WriteLine(val.ValueKind == JsonValueKind.String ? val.GetString() : val.ToString());
                return 0;
            }
        }
        catch { /* not JSON, print raw */ }
        Console.WriteLine(body.Trim('"'));
        return 0;
    }

    // --- aggregate ---
    static async Task<int> Aggregate(string[] args)
    {
        if (args.Length < 2) return Help(1, "Usage: metal aggregate <type> <fn> [field=X] [filter=field:value]");
        var slug = args[0]; var fn = args[1];
        var qs = BuildQueryString(args[2..]);
        var sep = qs.Length > 0 ? "&" : "?";
        var url = $"/api/_lookup/{slug}/_aggregate?fn={Uri.EscapeDataString(fn)}{(qs.Length > 0 ? "&" + qs[1..] : "")}";
        var resp = await _http.GetAsync(url);
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        Console.WriteLine(body);
        return 0;
    }

    // --- command ---
    static async Task<int> RunCommand(string[] args)
    {
        if (args.Length < 3) return Help(1, "Usage: metal command <type> <id> <command> [key=value...]");
        var slug = args[0]; var id = args[1]; var command = args[2];
        var payload = args.Length > 3 ? ParseKeyValues(args[3..]) : new Dictionary<string, string>();
        var json = CliJson.SerializeDict(payload);
        var resp = await PostWithCsrf($"/api/{slug}/{id}/_command/{command}",
            new StringContent(json, Encoding.UTF8, "application/json"));
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        if (!string.IsNullOrWhiteSpace(body))
            PrintJson(body);
        else
            Console.WriteLine("Command executed.");
        return 0;
    }

    // --- import ---
    static async Task<int> ImportEntities(string[] args)
    {
        if (args.Length < 2) return Help(1, "Usage: metal import <type> <file.json>");
        var slug = args[0]; var file = args[1];
        if (!File.Exists(file)) { Console.Error.WriteLine($"File not found: {file}"); return 1; }
        var content = await File.ReadAllTextAsync(file);
        var resp = await PostWithCsrf($"/api/{slug}/import",
            new StringContent(content, Encoding.UTF8, "application/json"));
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();
        if (!string.IsNullOrWhiteSpace(body))
            PrintJson(body);
        else
            Console.WriteLine("Import complete.");
        return 0;
    }

    // --- export ---
    static async Task<int> ExportEntities(string[] args)
    {
        if (args.Length < 1) return Help(1, "Usage: metal export <type> [--format=csv|json] [--output=file]");
        var slug = args[0];
        var format = "json";
        string? outputFile = null;
        foreach (var a in args[1..])
        {
            if (a.StartsWith("--format=", StringComparison.OrdinalIgnoreCase))
                format = a[9..].ToLowerInvariant();
            else if (a.StartsWith("--output=", StringComparison.OrdinalIgnoreCase))
                outputFile = a[9..];
        }

        var req = new HttpRequestMessage(HttpMethod.Get, $"/api/{slug}");
        if (format == "csv")
            req.Headers.Add("Accept", "text/csv");
        var resp = await _http.SendAsync(req);
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return 1; }
        var body = await resp.Content.ReadAsStringAsync();

        if (outputFile != null)
        {
            await File.WriteAllTextAsync(outputFile, body);
            Console.WriteLine($"Exported to {outputFile}");
        }
        else
        {
            Console.WriteLine(body);
        }
        return 0;
    }

    // --- seed ---
    static async Task<int> SeedData(string[] args)
    {
        if (string.IsNullOrEmpty(_config.Url))
            return Help(1, "Not connected. Run: metal connect <url>");

        bool clearExisting = false;
        var entityCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var arg in args)
        {
            if (arg is "--clear" or "--clear-existing")
            {
                clearExisting = true;
                continue;
            }
            var eqIdx = arg.IndexOf('=');
            if (eqIdx > 0 && int.TryParse(arg[(eqIdx + 1)..], out var count))
            {
                if (count <= 0) return Help(1, $"Count for '{arg[..eqIdx]}' must be a positive integer.");
                entityCounts[arg[..eqIdx]] = count;
                continue;
            }
            return Help(1, $"Unrecognised argument: {arg}\nUsage: metal seed [--clear] [type=count ...]");
        }

        // If no entity types specified, fetch all and use a default count of 10 each
        if (entityCounts.Count == 0)
        {
            var meta = await FetchMeta();
            if (meta == null) return 1;
            foreach (var e in meta)
                entityCounts[e.Slug] = 10;
            if (entityCounts.Count == 0)
            {
                Console.Error.WriteLine("No entity types found on the server.");
                return 1;
            }
            Console.WriteLine($"No entity types specified — using all {entityCounts.Count} types with 10 records each.");
        }

        var request = new SeedRequest { ClearExisting = clearExisting, Entities = entityCounts };
        var json = CliJson.SerializeSeedRequest(request);

        Console.WriteLine($"Seeding {entityCounts.Count} entity type(s){(clearExisting ? " (clearing existing data first)" : "")}...");

        var resp = await PostWithCsrf("/api/admin/sample-data",
            new StringContent(json, Encoding.UTF8, "application/json"));

        if (resp.StatusCode == HttpStatusCode.Forbidden)
        {
            Console.Error.WriteLine("403 Forbidden - ensure you are logged in as an admin: metal login");
            return 1;
        }
        if (resp.StatusCode != HttpStatusCode.Accepted && !resp.IsSuccessStatusCode)
        {
            await PrintError(resp);
            return 1;
        }

        var body = await resp.Content.ReadAsStringAsync();
        var jobResp = CliJson.DeserializeJobStatus(body);
        if (jobResp == null || string.IsNullOrEmpty(jobResp.JobId))
        {
            Console.Error.WriteLine("Unexpected response from server - could not get job ID.");
            return 1;
        }

        Console.WriteLine($"Job queued: {jobResp.JobId}  Polling for completion...");

        var statusUrl = $"/api/jobs/{jobResp.JobId}";
        int lastPercent = -1;
        while (true)
        {
            await Task.Delay(2000);
            var pollResp = await _http.GetAsync(statusUrl);
            if (pollResp.StatusCode == HttpStatusCode.NotFound)
            {
                Console.Error.WriteLine("\nJob not found - it may have been pruned.");
                return 1;
            }
            if (!pollResp.IsSuccessStatusCode && pollResp.StatusCode != HttpStatusCode.Accepted)
            {
                await PrintError(pollResp);
                return 1;
            }
            var pollBody = await pollResp.Content.ReadAsStringAsync();
            var status = CliJson.DeserializeJobStatus(pollBody);
            if (status == null) break;

            if (status.PercentComplete != lastPercent)
            {
                lastPercent = status.PercentComplete;
                var bar = BuildProgressBar(status.PercentComplete, 30);
                // Truncate description to a fixed width so \r overwrites cleanly
                var desc = status.Description ?? string.Empty;
                if (desc.Length > 50) desc = desc[..47] + "...";
                Console.Write($"\r  {bar} {status.PercentComplete,3}%  {desc,-50}");
            }

            if (string.Equals(status.Status, "succeeded", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine();
                Console.WriteLine($"Seed complete. {status.Description}");
                return 0;
            }
            if (string.Equals(status.Status, "failed", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine();
                Console.Error.WriteLine($"Seed failed: {status.Error ?? status.Description}");
                return 1;
            }
        }

        Console.WriteLine();
        return 0;
    }

    static string BuildProgressBar(int percent, int width)
    {
        var filled = (percent * width + 50) / 100;
        return "[" + new string('#', filled) + new string('-', width - filled) + "]";
    }

    // --- version ---
    static int ShowVersion()
    {
        var version = typeof(Program).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? typeof(Program).Assembly.GetName().Version?.ToString()
            ?? "unknown";
        Console.WriteLine($"metal version {version}");
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
        var resp = await _http.GetAsync("/meta/objects");
        if (!resp.IsSuccessStatusCode) { await PrintError(resp); return null; }
        var body = await resp.Content.ReadAsStringAsync();
        _meta = CliJson.DeserializeMetaEntities(body);
        return _meta;
    }

    /// Gets the CSRF token from cookies for mutating requests.
    static string? GetCsrfToken()
    {
        if (string.IsNullOrEmpty(_config.Url)) return null;
        var cookies = _cookies.GetCookies(new Uri(_config.Url));
        foreach (Cookie c in cookies)
            if (c.Name == "csrf_token") return c.Value;
        return null;
    }

    /// Sends a request with CSRF headers attached.
    static async Task<HttpResponseMessage> SendWithCsrf(HttpRequestMessage req)
    {
        var csrf = GetCsrfToken();
        if (!string.IsNullOrEmpty(csrf))
            req.Headers.TryAddWithoutValidation("X-CSRF-Token", csrf);
        req.Headers.TryAddWithoutValidation("X-Requested-With", "BareMetalWeb");
        return await _http.SendAsync(req);
    }

    /// Shortcut: POST with CSRF.
    static async Task<HttpResponseMessage> PostWithCsrf(string url, HttpContent? content)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
        return await SendWithCsrf(req);
    }

    /// Unwraps paginated envelope {items: [], total: N} or {data: [], count: N} → array, or returns as-is.
    static JsonElement UnwrapItems(JsonElement el)
    {
        if (el.ValueKind == JsonValueKind.Object)
        {
            if (el.TryGetProperty("items", out var items)) return items;
            if (el.TryGetProperty("data", out var data)) return data;
        }
        return el;
    }

    static string BuildQueryString(string[] args)
    {
        var qs = new StringBuilder();
        foreach (var arg in args)
        {
            var eqIdx = arg.IndexOf('=');
            if (eqIdx <= 0) continue;
            var k = arg[..eqIdx]; var v = arg[(eqIdx + 1)..];
            qs.Append(qs.Length == 0 ? '?' : '&');
            qs.Append(Uri.EscapeDataString(k)).Append('=').Append(Uri.EscapeDataString(v));
        }
        return qs.ToString();
    }

    static async Task PrintTable(string slug, JsonElement items)
    {
        if (items.ValueKind != JsonValueKind.Array) { Console.WriteLine(items.ToString()); return; }
        var meta = await FetchMeta();
        MetaEntity? entity = null;
        if (meta != null)
        {
            foreach (var e in meta)
            {
                if (string.Equals(e.Slug, slug, StringComparison.OrdinalIgnoreCase))
                {
                    entity = e;
                    break;
                }
            }
        }
        string[]? listFields = null;
        if (entity != null)
        {
            var fieldList = new List<MetaField>();
            foreach (var f in entity.Fields)
                if (f.List) fieldList.Add(f);
            fieldList.Sort((a, b) => a.Order.CompareTo(b.Order));
            var names = new List<string>();
            foreach (var f in fieldList)
                names.Add(f.Name);
            listFields = names.ToArray();
        }

        // Collect all rows to compute column widths
        var rows = new List<string[]>();
        string[] headers;
        if (listFields != null && listFields.Length > 0)
        {
            var headerList = new List<string> { "Id" };
            foreach (var f in listFields) headerList.Add(f);
            headers = headerList.ToArray();
        }
        else
        {
            // Fallback: use keys from first item
            JsonElement first = default;
            bool hasFirst = false;
            foreach (var elem in items.EnumerateArray())
            {
                first = elem;
                hasFirst = true;
                break;
            }
            if (hasFirst && first.ValueKind == JsonValueKind.Object)
            {
                var propNames = new List<string>();
                int count = 0;
                foreach (var p in first.EnumerateObject())
                {
                    if (count >= 6) break;
                    propNames.Add(p.Name);
                    count++;
                }
                headers = propNames.ToArray();
            }
            else
            {
                headers = new[] { "Value" };
            }
        }

        foreach (var item in items.EnumerateArray())
        {
            var row = new string[headers.Length];
            for (int i = 0; i < headers.Length; i++)
            {
                if (item.TryGetProperty(headers[i], out var val))
                    row[i] = val.ValueKind == JsonValueKind.String ? val.GetString() ?? "" : val.ToString();
                else if (TryGetPropertyInsensitive(item, headers[i], out var val2))
                    row[i] = val2.ValueKind == JsonValueKind.String ? val2.GetString() ?? "" : val2.ToString();
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

    static bool TryGetPropertyInsensitive(JsonElement element, string name, out JsonElement value)
    {
        foreach (var prop in element.EnumerateObject())
        {
            if (string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                value = prop.Value;
                return true;
            }
        }
        value = default;
        return false;
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
            Console.WriteLine(CliJson.PrettyPrint(body));
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
        _config = CliJson.DeserializeConfig(json);
    }

    static void SaveConfig()
    {
        Directory.CreateDirectory(ConfigDir);
        File.WriteAllText(ConfigPath, CliJson.SerializeConfig(_config));
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
              logout                      Clear session and log out
              config                      Show current configuration
              --version, -v               Show CLI version

            Entity Operations:
              types                       List available entity types
              schema <type>               Show full entity schema (fields, lookups, commands)
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

            Lookup API:
              lookup <type> [filters]     Query via lookup API (lightweight)
                filter=field:value sort=Field dir=asc skip=0 top=20
              lookup-field <type> <id> <field>  Get single field value
              aggregate <type> <fn> [field=X]   Aggregate (count/sum/avg/min/max)

            Commands:
              command <type> <id> <cmd>   Execute a remote command on an entity

            Import / Export:
              import <type> <file.json>   Bulk import entities from JSON file
              export <type> [options]     Export entities
                --format=csv|json  --output=file.csv

            Dev / Admin:
              seed [--clear] [type=count ...]
                                          Seed sample data for dev environment setup.
                                          If no types given, seeds all types with 10 records each.
                --clear                   Clear existing records before seeding

            Examples:
              metal connect https://mysite.azurewebsites.net abc123key
              metal login
              metal types
              metal schema orders
              metal list to-do
              metal create to-do Title="Buy milk" Notes="From store"
              metal query to-do q=milk sort=Deadline dir=asc top=5
              metal get to-do abc123
              metal update to-do abc123 IsCompleted=true
              metal delete to-do abc123
              metal lookup customers search=acme top=5
              metal lookup-field customers abc123 Name
              metal aggregate orders count
              metal aggregate orders sum field=Total
              metal command orders abc123 Approve
              metal import products data.json
              metal export products --format=csv --output=products.csv
              metal seed
              metal seed --clear to-do=20 customers=5
              metal logout
            """);
        return exitCode;
    }
}
