using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.DataBrowser;

internal static class Program
{
    private static string _dataRoot = "";
    private static bool _writeMode = false;
    private static LocalFolderBinaryDataProvider _provider = null!;
    private static IndexStore _indexStore = null!;

    static async Task<int> Main(string[] args)
    {
        var positional = new List<string>();
        var cmdArgs = new List<string>();
        bool seenCommand = false;

        foreach (var arg in args)
        {
            if (arg == "--write" || arg == "-w")
            {
                _writeMode = true;
                continue;
            }
            if (!seenCommand && string.IsNullOrEmpty(_dataRoot) && !arg.StartsWith("--"))
            {
                _dataRoot = arg;
                continue;
            }
            seenCommand = true;
            cmdArgs.Add(arg);
        }

        if (string.IsNullOrEmpty(_dataRoot))
            _dataRoot = TryFindDefaultDataRoot();

        if (string.IsNullOrEmpty(_dataRoot) || !Directory.Exists(_dataRoot))
        {
            Console.Error.WriteLine("BareMetalWeb Data Browser");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Usage: bmwdb <dataRoot> [--write] [command [args...]]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("  dataRoot  Path to the BareMetalWeb data directory");
            Console.Error.WriteLine("  --write   Enable write operations (server must be down)");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Run 'bmwdb <dataRoot>' with no command for interactive mode.");
            Console.Error.WriteLine("Run 'bmwdb <dataRoot> help' to list all commands.");
            return 1;
        }

        _provider = new LocalFolderBinaryDataProvider(_dataRoot);
        _indexStore = new IndexStore(_provider);

        // Register all known entity types so DataScaffold.Entities is populated.
        DataStoreProvider.PrimaryProvider = _provider;
        var store = new DataObjectStore();
        store.RegisterProvider(_provider);
        DataStoreProvider.Current = store;
        DataEntityRegistry.RegisterAllEntities();

        WriteBanner();

        if (cmdArgs.Count > 0)
        {
            try
            {
                return await Dispatch(cmdArgs.ToArray());
            }
            catch (Exception ex)
            {
                Red($"Error: {ex.GetType().Name}: {ex.Message}");
                return 1;
            }
        }

        return await RunRepl();
    }

    // ── Banner ────────────────────────────────────────────────────────────────

    static void WriteBanner()
    {
        Cyan("BareMetalWeb Data Browser  [bmwdb]");
        Console.WriteLine($"  Data root : {_dataRoot}");
        Console.WriteLine($"  Mode      : {(_writeMode ? "READ/WRITE  *** server must be down for writes ***" : "READ-ONLY  (safe while server is running)")}");
        Console.WriteLine();
    }

    // ── REPL ──────────────────────────────────────────────────────────────────

    static async Task<int> RunRepl()
    {
        Console.WriteLine("Type 'help' for available commands, 'exit' to quit.");
        Console.WriteLine();

        while (true)
        {
            Console.Write("bmwdb> ");
            var line = Console.ReadLine();
            if (line == null)
                break;

            line = line.Trim();
            if (string.IsNullOrEmpty(line))
                continue;

            if (line.Equals("exit", StringComparison.OrdinalIgnoreCase) ||
                line.Equals("quit", StringComparison.OrdinalIgnoreCase))
                break;

            var tokens = SplitTokens(line);
            if (tokens.Length == 0)
                continue;

            try
            {
                await Dispatch(tokens);
            }
            catch (Exception ex)
            {
                Red($"Error: {ex.GetType().Name}: {ex.Message}");
            }

            Console.WriteLine();
        }

        return 0;
    }

    // ── Dispatcher ────────────────────────────────────────────────────────────

    static async Task<int> Dispatch(string[] tokens)
    {
        if (tokens.Length == 0)
            return 0;

        var cmd = tokens[0].ToLowerInvariant();
        var rest = tokens[1..];

        return cmd switch
        {
            "help" or "--help" or "-h" => Help(),
            "entities" or "list-entities" => ListEntities(),
            "indexes" or "list-indexes" => ListIndexes(rest),
            "index-view" or "iv" => IndexView(rest),
            "index-wal" or "wal" => IndexWal(rest),
            "index-stats" or "is" => IndexStats(rest),
            "index-rebuild" or "ir" => IndexRebuild(rest),
            "index-rebuild-all" or "ira" => IndexRebuildAll(),
            "records" or "rs" => await Records(rest),
            "record-get" or "rg" => await RecordGet(rest),
            "record-edit" or "re" => await RecordEdit(rest),
            "record-delete" or "rd" => await RecordDelete(rest),
            "seqid" => SeqId(rest),
            "compact" => Compact(rest),
            _ => UnknownCommand(cmd)
        };
    }

    // ── help ──────────────────────────────────────────────────────────────────

    static int Help()
    {
        Console.WriteLine("""
            BareMetalWeb Data Browser — Commands
            =====================================

            Entity / Index discovery:
              entities                          List entity types found in the data directory
              indexes [entity]                  List tracked indexes (optionally filtered by entity)

            Index inspection (read-only, safe while server is running):
              index-view  <entity> <field>      Merged index state (snapshot + WAL)
              index-wal   <entity> <field>      Raw WAL log entries from the paged file
              index-stats <entity> <field>      Header stats: snapshot/log page counts + sequence

            Index maintenance (WRITE mode only — server must be down):
              index-rebuild     <entity> <field>   Compact WAL log into snapshot
              index-rebuild-all                    Rebuild all registered indexes

            Record browsing (read-only, safe while server is running):
              records     <entity> [--top N]    List record IDs + key fields
              record-get  <entity> <id>         Full record detail

            Record editing (WRITE mode only — server must be down):
              record-edit   <entity> <id> f=v…  Edit field values on a record
              record-delete <entity> <id>        Delete a record

            Utilities:
              seqid   <entity>                  Show current sequential ID counter
              compact <entity>                  Compact the clustered object store (WRITE mode)

              help                              This help text
              exit / quit                       Leave the interactive shell
            """);
        return 0;
    }

    static int UnknownCommand(string cmd)
    {
        Red($"Unknown command: '{cmd}'.  Type 'help' for available commands.");
        return 1;
    }

    // ── entities ──────────────────────────────────────────────────────────────

    static int ListEntities()
    {
        // Discover entities from two sources:
        // 1. DataScaffold-registered types (known C# entity classes)
        // 2. Subdirectories in the Paged folder (entities with stored data)
        var registered = DataScaffold.Entities
            .ToDictionary(e => e.Name, StringComparer.OrdinalIgnoreCase);

        var onDisk = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pagedRoot = Path.Combine(_dataRoot, "Paged");
        if (Directory.Exists(pagedRoot))
            foreach (var dir in Directory.EnumerateDirectories(pagedRoot))
                onDisk.Add(Path.GetFileName(dir));

        // Also pick up from index registry
        foreach (var (entity, _) in IndexStore.ListTrackedIndexes(_provider))
            onDisk.Add(entity);

        var all = registered.Keys.Union(onDisk, StringComparer.OrdinalIgnoreCase)
            .OrderBy(n => n).ToList();

        if (all.Count == 0)
        {
            Console.WriteLine("No entities found.");
            return 0;
        }

        var headers = new[] { "Entity", "Slug", "Fields", "OnDisk", "Registered" };
        var rows = all.Select(name =>
        {
            registered.TryGetValue(name, out var meta);
            return new[]
            {
                name,
                meta?.Slug ?? "-",
                meta?.Fields.Count.ToString() ?? "-",
                onDisk.Contains(name) ? "yes" : "no",
                meta != null ? "yes" : "no"
            };
        }).ToList();

        PrintTable(headers, rows);
        Console.WriteLine($"\n{all.Count} entity type(s).");
        return 0;
    }

    // ── indexes ───────────────────────────────────────────────────────────────

    static int ListIndexes(string[] args)
    {
        var filterEntity = args.Length > 0 && !args[0].StartsWith("--") ? args[0] : null;

        var entries = IndexStore.ListTrackedIndexes(_provider)
            .Where(e => filterEntity == null || string.Equals(e.EntityName, filterEntity, StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.EntityName).ThenBy(e => e.FieldName)
            .ToList();

        if (entries.Count == 0)
        {
            Console.WriteLine(filterEntity != null
                ? $"No indexes tracked for '{filterEntity}'."
                : "No indexes found in registry.");
            return 0;
        }

        var headers = new[] { "Entity", "Field", "Snapshot pages", "Log pages", "Sequence" };
        var rows = entries.Select(e =>
        {
            var (snap, log, seq) = _indexStore.ReadIndexStats(e.EntityName, e.FieldName);
            return new[] { e.EntityName, e.FieldName, snap.ToString(), log.ToString(), seq.ToString() };
        }).ToList();

        PrintTable(headers, rows);
        Console.WriteLine($"\n{entries.Count} index(es).");
        return 0;
    }

    // ── index-view ────────────────────────────────────────────────────────────

    static int IndexView(string[] args)
    {
        if (args.Length < 2)
            return ArgError("Usage: index-view <entity> <field>");

        var entity = args[0];
        var field = args[1];

        var index = _indexStore.ReadIndex(entity, field);
        if (index.Count == 0)
        {
            Console.WriteLine("Index is empty (or does not exist).");
            return 0;
        }

        var headers = new[] { "Key", "IDs" };
        var rows = index.OrderBy(kv => kv.Key)
            .Select(kv => new[] { kv.Key, string.Join(", ", kv.Value.Take(10)) +
                (kv.Value.Count > 10 ? $"  …+{kv.Value.Count - 10}" : "") })
            .ToList();

        PrintTable(headers, rows);
        Console.WriteLine($"\n{index.Count} key(s),  {index.Values.Sum(v => v.Count)} total ID(s).");
        return 0;
    }

    // ── index-wal ─────────────────────────────────────────────────────────────

    static int IndexWal(string[] args)
    {
        if (args.Length < 2)
            return ArgError("Usage: index-wal <entity> <field>");

        var entity = args[0];
        var field = args[1];
        bool raw = args.Contains("--raw", StringComparer.OrdinalIgnoreCase);

        var entries = _indexStore.ReadRawLogEntries(entity, field);
        if (entries.Count == 0)
        {
            Console.WriteLine("WAL log is empty (or index does not exist).");
            return 0;
        }

        var headers = new[] { "Timestamp (UTC)", "Op", "Key", "ID", "Expires (UTC)" };
        var rows = entries.Select(e =>
        {
            var ts = new DateTime(e.Ticks, DateTimeKind.Utc).ToString("yyyy-MM-dd HH:mm:ss.fff");
            var exp = e.ExpiresAtUtcTicks.HasValue && e.ExpiresAtUtcTicks.Value > 0
                ? new DateTime(e.ExpiresAtUtcTicks.Value, DateTimeKind.Utc).ToString("yyyy-MM-dd HH:mm:ss")
                : "-";
            return new[] { ts, e.Op.ToString(), e.Key, e.Id, exp };
        }).ToList();

        PrintTable(headers, rows);
        Console.WriteLine($"\n{entries.Count} WAL log entry(ies).");
        return 0;
    }

    // ── index-stats ───────────────────────────────────────────────────────────

    static int IndexStats(string[] args)
    {
        if (args.Length < 2)
            return ArgError("Usage: index-stats <entity> <field>");

        var entity = args[0];
        var field = args[1];
        var (snap, log, seq) = _indexStore.ReadIndexStats(entity, field);

        Console.WriteLine($"  Entity          : {entity}");
        Console.WriteLine($"  Field           : {field}");
        Console.WriteLine($"  Snapshot pages  : {snap}");
        Console.WriteLine($"  Log (WAL) pages : {log}");
        Console.WriteLine($"  Header sequence : {seq}");
        if (snap + log > 0)
        {
            var pct = (double)log / (snap + log) * 100;
            Console.WriteLine($"  WAL ratio       : {pct:F1}%  ({(log > snap / 2 ? "consider rebuild" : "ok")})");
        }
        return 0;
    }

    // ── index-rebuild ─────────────────────────────────────────────────────────

    static int IndexRebuild(string[] args)
    {
        if (args.Length < 2)
            return ArgError("Usage: index-rebuild <entity> <field>");
        RequireWriteMode();

        var entity = args[0];
        var field = args[1];
        var (_, logBefore, _) = _indexStore.ReadIndexStats(entity, field);
        _indexStore.BuildSnapshot(entity, field);
        var (snapAfter, logAfter, _) = _indexStore.ReadIndexStats(entity, field);
        Console.WriteLine($"  Rebuilt {entity}.{field}:  log pages {logBefore} → {logAfter},  snapshot pages → {snapAfter}.");
        return 0;
    }

    static int IndexRebuildAll()
    {
        RequireWriteMode();

        var indexes = IndexStore.ListTrackedIndexes(_provider).ToList();
        if (indexes.Count == 0)
        {
            Console.WriteLine("No indexes tracked.");
            return 0;
        }

        foreach (var (entity, field) in indexes)
        {
            try
            {
                var (_, logBefore, _) = _indexStore.ReadIndexStats(entity, field);
                _indexStore.BuildSnapshot(entity, field);
                var (snapAfter, logAfter, _) = _indexStore.ReadIndexStats(entity, field);
                Console.WriteLine($"  {entity}.{field}:  log {logBefore} → {logAfter},  snap → {snapAfter}");
            }
            catch (Exception ex)
            {
                Red($"  Failed {entity}.{field}: {ex.Message}");
            }
        }
        Console.WriteLine($"\nRebuilt {indexes.Count} index(es).");
        return 0;
    }

    // ── records ───────────────────────────────────────────────────────────────

    static async Task<int> Records(string[] args)
    {
        if (args.Length < 1)
            return ArgError("Usage: records <entity> [--top N]");

        var entity = args[0];
        var top = 50;
        for (int i = 1; i < args.Length; i++)
            if ((args[i] == "--top" || args[i] == "-n") && i + 1 < args.Length && int.TryParse(args[i + 1], out var n))
                top = n;

        var meta = FindEntityMetadata(entity);
        if (meta != null)
        {
            var query = new QueryDefinition { Top = top };
            var results = await meta.Handlers.QueryAsync(query, CancellationToken.None);
            var list = results.ToList();
            if (list.Count == 0)
            {
                Console.WriteLine("No records found.");
                return 0;
            }

            var listFields = meta.Fields.Where(f => f.List).OrderBy(f => f.Order).Take(5).ToList();
            var colNames = new[] { "Id" }.Concat(listFields.Select(f => f.Name)).ToArray();

            var rows = list.Select(obj =>
            {
                var cells = new string[colNames.Length];
                cells[0] = obj.Id;
                for (int i = 0; i < listFields.Count; i++)
                {
                    var val = listFields[i].GetValueFn(obj);
                    cells[i + 1] = FormatValue(val);
                }
                return cells;
            }).ToList();

            PrintTable(colNames, rows);
            Console.WriteLine($"\n{list.Count} record(s) (top={top}).");
        }
        else
        {
            // Unknown entity — show IDs from clustered index
            var index = _indexStore.ReadLatestValueIndex(entity, "_clustered", normalizeKey: false);
            if (index.Count == 0)
            {
                Console.WriteLine($"No records found for '{entity}'.");
                return 0;
            }

            var headers = new[] { "Id", "Clustered location" };
            var rows = index.OrderBy(kv => kv.Key)
                .Take(top)
                .Select(kv => new[] { kv.Key, kv.Value })
                .ToList();

            PrintTable(headers, rows);
            Console.WriteLine($"\n{Math.Min(index.Count, top)} of {index.Count} record(s) shown.");
        }

        return 0;
    }

    // ── record-get ────────────────────────────────────────────────────────────

    static async Task<int> RecordGet(string[] args)
    {
        if (args.Length < 2)
            return ArgError("Usage: record-get <entity> <id>");

        var entity = args[0];
        var id = args[1];
        var meta = FindEntityMetadata(entity);

        if (meta == null)
        {
            Yellow($"Entity '{entity}' is not registered. Showing raw index data only.");
            if (_indexStore.TryGetLatestValue(entity, "_clustered", id, out var loc, normalizeKey: false))
                Console.WriteLine($"  Clustered location: {loc}");
            else
                Console.WriteLine($"  Record '{id}' not found in clustered index.");
            return 0;
        }

        var obj = await meta.Handlers.LoadAsync(id, CancellationToken.None);
        if (obj == null)
        {
            Console.WriteLine($"  Record '{id}' not found.");
            return 0;
        }

        Console.WriteLine($"  Entity : {meta.Name}");
        Console.WriteLine($"  Id     : {obj.Id}");
        Console.WriteLine($"  ETag   : {obj.ETag}");
        Console.WriteLine($"  Created: {obj.CreatedOnUtc:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine($"  Updated: {obj.UpdatedOnUtc:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine();

        var allFields = meta.Fields.OrderBy(f => f.Order).ToList();
        var maxLabel = allFields.Count > 0 ? allFields.Max(f => f.Label.Length) : 10;
        maxLabel = Math.Max(maxLabel, 10);

        foreach (var field in allFields)
        {
            var val = field.GetValueFn(obj);
            Console.WriteLine($"  {field.Label.PadRight(maxLabel)}  {FormatValue(val)}");
        }
        return 0;
    }

    // ── record-edit ───────────────────────────────────────────────────────────

    static async Task<int> RecordEdit(string[] args)
    {
        if (args.Length < 3)
            return ArgError("Usage: record-edit <entity> <id> field=value [field=value...]");
        RequireWriteMode();

        var entity = args[0];
        var id = args[1];
        var meta = FindEntityMetadata(entity);

        if (meta == null)
            return ArgError($"Entity '{entity}' is not registered. Cannot edit unknown entities.");

        var obj = await meta.Handlers.LoadAsync(id, CancellationToken.None);
        if (obj == null)
        {
            Console.WriteLine($"  Record '{id}' not found.");
            return 1;
        }

        var pairs = ParseKeyValues(args[2..]);
        if (pairs.Count == 0)
            return ArgError("No field=value pairs provided.");

        foreach (var (key, value) in pairs)
        {
            var field = meta.Fields.FirstOrDefault(f =>
                string.Equals(f.Name, key, StringComparison.OrdinalIgnoreCase));

            if (field == null)
            {
                Yellow($"  Field '{key}' not found on {entity}, skipping.");
                continue;
            }

            if (field.ReadOnly)
            {
                Yellow($"  Field '{key}' is read-only, skipping.");
                continue;
            }

            try
            {
                var converted = ConvertValue(value, field.Property.PropertyType);
                field.SetValueFn(obj, converted);
                Console.WriteLine($"  Set {field.Name} = {FormatValue(converted)}");
            }
            catch (Exception ex)
            {
                Red($"  Cannot set '{key}': {ex.Message}");
            }
        }

        await meta.Handlers.SaveAsync(obj, CancellationToken.None);
        Console.WriteLine($"  Saved {entity}/{id}.");
        return 0;
    }

    // ── record-delete ─────────────────────────────────────────────────────────

    static async Task<int> RecordDelete(string[] args)
    {
        if (args.Length < 2)
            return ArgError("Usage: record-delete <entity> <id>");
        RequireWriteMode();

        var entity = args[0];
        var id = args[1];
        var meta = FindEntityMetadata(entity);

        if (meta == null)
            return ArgError($"Entity '{entity}' is not registered. Cannot delete from unknown entities.");

        Console.Write($"  Delete {entity}/{id}? [y/N] ");
        var confirm = Console.ReadLine()?.Trim();
        if (!string.Equals(confirm, "y", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("  Cancelled.");
            return 0;
        }

        await meta.Handlers.DeleteAsync(id, CancellationToken.None);
        Console.WriteLine($"  Deleted {entity}/{id}.");
        return 0;
    }

    // ── seqid ─────────────────────────────────────────────────────────────────

    static int SeqId(string[] args)
    {
        if (args.Length < 1)
            return ArgError("Usage: seqid <entity>");

        var entity = args[0];
        var seqFile = Path.Combine(_dataRoot, entity, "_seqid.dat");

        if (!File.Exists(seqFile))
        {
            Console.WriteLine($"  No sequential ID file found for '{entity}'.");
            return 0;
        }

        var buf = new byte[8];
        using var fs = new FileStream(seqFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (fs.Length < 8)
        {
            Console.WriteLine($"  Sequential ID for '{entity}': 0 (file too small, probably 0)");
            return 0;
        }
        fs.ReadExactly(buf, 0, 8);
        var current = System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(buf);
        Console.WriteLine($"  Sequential ID for '{entity}': {current}");
        return 0;
    }

    // ── compact ───────────────────────────────────────────────────────────────

    static int Compact(string[] args)
    {
        if (args.Length < 1)
            return ArgError("Usage: compact <entity>");
        RequireWriteMode();

        var entity = args[0];
        var meta = FindEntityMetadata(entity);

        if (meta == null)
            return ArgError($"Entity '{entity}' is not registered. Cannot compact unknown entities.");

        _provider.CompactClusteredEntity(meta.Type);
        Console.WriteLine($"  Compacted clustered store for '{entity}'.");
        return 0;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static DataEntityMetadata? FindEntityMetadata(string entityNameOrSlug)
    {
        return DataScaffold.Entities.FirstOrDefault(e =>
            string.Equals(e.Name, entityNameOrSlug, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(e.Slug, entityNameOrSlug, StringComparison.OrdinalIgnoreCase));
    }

    static void RequireWriteMode()
    {
        if (!_writeMode)
            throw new InvalidOperationException(
                "This operation requires write mode. Run with --write (and ensure the server is down).");
    }

    static int ArgError(string msg)
    {
        Red(msg);
        return 1;
    }

    static string FormatValue(object? val)
    {
        if (val == null)
            return "(null)";
        if (val is DateTime dt)
            return dt.Kind == DateTimeKind.Utc
                ? dt.ToString("yyyy-MM-dd HH:mm:ss") + " UTC"
                : dt.ToString("yyyy-MM-dd HH:mm:ss");
        if (val is bool b)
            return b ? "true" : "false";
        if (val is System.Collections.IEnumerable enumerable && val is not string)
        {
            var items = new List<string>();
            foreach (var item in enumerable)
                items.Add(item?.ToString() ?? "");
            if (items.Count == 0)
                return "[]";
            var joined = "[" + string.Join(", ", items.Take(5)) + (items.Count > 5 ? $", …+{items.Count - 5}" : "") + "]";
            return joined.Length > 80 ? joined[..77] + "…" : joined;
        }
        var s = val.ToString() ?? "";
        return s.Length > 80 ? s[..77] + "…" : s;
    }

    static object? ConvertValue(string value, Type targetType)
    {
        var underlying = Nullable.GetUnderlyingType(targetType) ?? targetType;

        if (value.Equals("null", StringComparison.OrdinalIgnoreCase) &&
            (targetType.IsClass || Nullable.GetUnderlyingType(targetType) != null))
            return null;

        if (underlying == typeof(string))
            return value;
        if (underlying == typeof(bool))
            return value.Equals("true", StringComparison.OrdinalIgnoreCase) || value == "1";
        if (underlying == typeof(int))
            return int.Parse(value);
        if (underlying == typeof(long))
            return long.Parse(value);
        if (underlying == typeof(double))
            return double.Parse(value);
        if (underlying == typeof(decimal))
            return decimal.Parse(value);
        if (underlying == typeof(Guid))
            return Guid.Parse(value);
        if (underlying == typeof(DateTime))
            return DateTime.Parse(value);
        if (underlying.IsEnum)
            return Enum.Parse(underlying, value, ignoreCase: true);

        return Convert.ChangeType(value, underlying);
    }

    static Dictionary<string, string> ParseKeyValues(string[] args)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var arg in args)
        {
            var idx = arg.IndexOf('=');
            if (idx > 0)
                dict[arg[..idx]] = arg[(idx + 1)..];
        }
        return dict;
    }

    static string TryFindDefaultDataRoot()
    {
        // Look for appsettings.json next to the executable and in common locations.
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "Data"),
            Path.Combine(Directory.GetCurrentDirectory(), "Data"),
        };
        foreach (var c in candidates)
            if (Directory.Exists(c))
                return c;
        return "";
    }

    static string[] SplitTokens(string line)
    {
        var tokens = new List<string>();
        var sb = new System.Text.StringBuilder();
        bool inQuote = false;
        foreach (var ch in line)
        {
            if (ch == '"')
            {
                inQuote = !inQuote;
            }
            else if (ch == ' ' && !inQuote)
            {
                if (sb.Length > 0)
                {
                    tokens.Add(sb.ToString());
                    sb.Clear();
                }
            }
            else
            {
                sb.Append(ch);
            }
        }
        if (sb.Length > 0)
            tokens.Add(sb.ToString());
        return tokens.ToArray();
    }

    // ── Table formatting ──────────────────────────────────────────────────────

    static void PrintTable(string[] headers, List<string[]> rows)
    {
        const int MaxColWidth = 42;
        var widths = new int[headers.Length];
        for (int i = 0; i < headers.Length; i++)
            widths[i] = headers[i].Length;

        foreach (var row in rows)
            for (int i = 0; i < Math.Min(row.Length, widths.Length); i++)
                widths[i] = Math.Max(widths[i], Math.Min(row[i]?.Length ?? 0, MaxColWidth));

        // Header
        Console.ForegroundColor = ConsoleColor.Cyan;
        for (int i = 0; i < headers.Length; i++)
            Console.Write(headers[i].PadRight(widths[i] + 2));
        Console.ResetColor();
        Console.WriteLine();

        for (int i = 0; i < headers.Length; i++)
            Console.Write(new string('-', widths[i]) + "  ");
        Console.WriteLine();

        foreach (var row in rows)
        {
            for (int i = 0; i < headers.Length; i++)
            {
                var cell = i < row.Length ? (row[i] ?? "") : "";
                if (cell.Length > MaxColWidth)
                    cell = cell[..(MaxColWidth - 1)] + "…";
                Console.Write(cell.PadRight(widths[i] + 2));
            }
            Console.WriteLine();
        }
    }

    // ── Color helpers ─────────────────────────────────────────────────────────

    static void Cyan(string msg) { Console.ForegroundColor = ConsoleColor.Cyan; Console.WriteLine(msg); Console.ResetColor(); }
    static void Yellow(string msg) { Console.ForegroundColor = ConsoleColor.Yellow; Console.WriteLine(msg); Console.ResetColor(); }
    static void Red(string msg) { Console.ForegroundColor = ConsoleColor.Red; Console.Error.WriteLine(msg); Console.ResetColor(); }
}
