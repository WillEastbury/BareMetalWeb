using System.Text;
using BareMetalWeb.Core.Host;

namespace BareMetalWeb.Host;

/// <summary>
/// Builds a deterministic protocol descriptor from registered BMW routes.
/// The descriptor is the single shared contract between server and all clients.
/// Downloaded at bootstrap via GET /bmw/protocol.
///
/// Architecture: BMW metadata → protocol descriptor → JS SDK / CLI SDK → binary transport → handlers.
/// </summary>
public sealed class BmwProtocolDescriptor
{
    /// <summary>Route descriptor for a single opcode-addressable route.</summary>
    public readonly struct RouteDescriptor
    {
        public readonly string Name;
        public readonly int Opcode;
        public readonly string Method;
        public readonly int MethodOrdinal;
        public readonly int RouteOrdinal;
        public readonly string Path;
        public readonly string? Entity;
        public readonly string[] ParameterNames;
        public readonly bool HasPayload;
        public readonly string? Permission;

        public RouteDescriptor(string name, int opcode, string method, int methodOrdinal,
            int routeOrdinal, string path, string? entity, string[] parameterNames,
            bool hasPayload, string? permission)
        {
            Name = name;
            Opcode = opcode;
            Method = method;
            MethodOrdinal = methodOrdinal;
            RouteOrdinal = routeOrdinal;
            Path = path;
            Entity = entity;
            ParameterNames = parameterNames;
            HasPayload = hasPayload;
            Permission = permission;
        }
    }

    /// <summary>Entity descriptor grouping all routes for a single entity type.</summary>
    public readonly struct EntityDescriptor
    {
        public readonly string Slug;
        public readonly int[] Opcodes; // opcodes for each verb

        public EntityDescriptor(string slug, int[] opcodes)
        {
            Slug = slug;
            Opcodes = opcodes;
        }
    }

    // ── Lookup tables ──────────────────────────────────────────────────────
    private readonly RouteDescriptor[] _routes;
    private readonly Dictionary<string, RouteDescriptor> _byName;
    private readonly Dictionary<int, RouteDescriptor> _byOpcode;
    private readonly Dictionary<string, EntityDescriptor> _entities;
    private string? _cachedJson;
    private string? _cachedSdk;
    private string? _cachedCli;

    public IReadOnlyList<RouteDescriptor> Routes => _routes;
    public IReadOnlyDictionary<string, RouteDescriptor> RoutesByName => _byName;
    public IReadOnlyDictionary<int, RouteDescriptor> RoutesByOpcode => _byOpcode;
    public IReadOnlyDictionary<string, EntityDescriptor> Entities => _entities;

    private BmwProtocolDescriptor(RouteDescriptor[] routes,
        Dictionary<string, RouteDescriptor> byName,
        Dictionary<int, RouteDescriptor> byOpcode,
        Dictionary<string, EntityDescriptor> entities)
    {
        _routes = routes;
        _byName = byName;
        _byOpcode = byOpcode;
        _entities = entities;
    }

    /// <summary>
    /// Build a protocol descriptor from the server's registered routes.
    /// Enumerates all routes, computes deterministic opcodes, and groups by entity.
    /// </summary>
    public static BmwProtocolDescriptor Build(
        Dictionary<string, RouteHandlerData> routes,
        Dictionary<string, CompiledRoute> compiledRoutes)
    {
        var descriptors = new List<RouteDescriptor>();
        var byName = new Dictionary<string, RouteDescriptor>(StringComparer.Ordinal);
        var byOpcode = new Dictionary<int, RouteDescriptor>();
        var entityOpcodes = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);

        foreach (var kvp in routes)
        {
            var data = kvp.Value;
            if (data.RouteId == 0 || data.Handler == null)
                continue;

            int routeOrdinal = data.RouteId;
            if (routeOrdinal >= BmwBinaryTransport.MaxRoutes)
                continue;

            int methodOrdinal = BmwBinaryTransport.ParseMethodOrdinal(kvp.Key);
            if (methodOrdinal < 0)
                continue;

            // Parse verb and path
            string routeKeyStr = kvp.Key;
            int spaceIdx = routeKeyStr.IndexOf(' ');
            string verb = spaceIdx > 0 ? routeKeyStr[..spaceIdx] : routeKeyStr;
            string path = spaceIdx > 0 ? routeKeyStr[(spaceIdx + 1)..] : "/";

            // Compute deterministic opcode
            int opcode = (methodOrdinal << BmwBinaryTransport.RouteBits) | routeOrdinal;

            // Extract parameter names from compiled route
            string[] paramNames = Array.Empty<string>();
            if (compiledRoutes.TryGetValue(kvp.Key, out var compiled) && compiled.ParameterCount > 0)
            {
                paramNames = new string[compiled.Segments.Length];
                int idx = 0;
                for (int i = 0; i < compiled.Segments.Length; i++)
                {
                    if (compiled.Segments[i].Kind != RouteSegmentKind.Literal)
                        paramNames[idx++] = compiled.Segments[i].Value;
                }
                if (idx < paramNames.Length)
                    Array.Resize(ref paramNames, idx);
            }

            // Extract entity slug from /api/{slug} paths
            string? entity = ExtractEntitySlug(path);

            // Generate SDK-friendly name: e.g. "getUsers", "createOrder"
            string sdkName = GenerateSdkName(verb, path, entity);

            // Extract permission from PageInfo
            string? permission = data.PageInfo?.PageMetaData?.PermissionsNeeded;

            bool hasPayload = BmwBinaryTransport.IsWriteMethod(methodOrdinal);

            var desc = new RouteDescriptor(sdkName, opcode, verb, methodOrdinal,
                routeOrdinal, path, entity, paramNames, hasPayload, permission);

            descriptors.Add(desc);
            byName[sdkName] = desc;
            byOpcode[opcode] = desc;

            // Group by entity
            if (entity != null)
            {
                if (!entityOpcodes.TryGetValue(entity, out var list))
                {
                    list = new List<int>();
                    entityOpcodes[entity] = list;
                }
                list.Add(opcode);
            }
        }

        // Build entity descriptors
        var entities = new Dictionary<string, EntityDescriptor>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in entityOpcodes)
        {
            entities[kvp.Key] = new EntityDescriptor(kvp.Key, kvp.Value.ToArray());
        }

        return new BmwProtocolDescriptor(descriptors.ToArray(), byName, byOpcode, entities);
    }

    /// <summary>Serialize the descriptor to JSON for the /bmw/protocol endpoint.</summary>
    public string ToJson()
    {
        if (_cachedJson != null) return _cachedJson;

        var sb = new StringBuilder(8192);
        sb.Append("{\"protocol\":\"BMW1.0\",\"transport\":{\"frameSize\":");
        sb.Append(BmwBinaryTransport.FrameSize);
        sb.Append(",\"methodBits\":");
        sb.Append(BmwBinaryTransport.MethodBits);
        sb.Append(",\"routeBits\":");
        sb.Append(BmwBinaryTransport.RouteBits);
        sb.Append(",\"maxRoutes\":");
        sb.Append(BmwBinaryTransport.MaxRoutes);
        sb.Append(",\"payloadLengthBytes\":");
        sb.Append(BmwBinaryTransport.PayloadLengthSize);
        sb.Append(",\"methods\":[");
        AppendMethod(sb, "GET", BmwBinaryTransport.MethodGet, true);
        AppendMethod(sb, "HEAD", BmwBinaryTransport.MethodHead, false);
        AppendMethod(sb, "DELETE", BmwBinaryTransport.MethodDelete, false);
        AppendMethod(sb, "POST", BmwBinaryTransport.MethodPost, false);
        AppendMethod(sb, "PUT", BmwBinaryTransport.MethodPut, false);
        AppendMethod(sb, "PATCH", BmwBinaryTransport.MethodPatch, false);
        sb.Append("]},\"routes\":[");

        for (int i = 0; i < _routes.Length; i++)
        {
            if (i > 0) sb.Append(',');
            AppendRoute(sb, _routes[i]);
        }

        sb.Append("],\"entities\":{");
        bool firstEntity = true;
        foreach (var kvp in _entities)
        {
            if (!firstEntity) sb.Append(',');
            firstEntity = false;
            sb.Append('"');
            sb.Append(EscapeJson(kvp.Key));
            sb.Append("\":{\"slug\":\"");
            sb.Append(EscapeJson(kvp.Value.Slug));
            sb.Append("\",\"opcodes\":[");
            for (int i = 0; i < kvp.Value.Opcodes.Length; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(kvp.Value.Opcodes[i]);
            }
            sb.Append("]}");
        }

        sb.Append("},\"stats\":{\"totalRoutes\":");
        sb.Append(_routes.Length);
        sb.Append(",\"entities\":");
        sb.Append(_entities.Count);
        sb.Append(",\"opcodes\":");
        sb.Append(_byOpcode.Count);
        sb.Append("}}");

        _cachedJson = sb.ToString();
        return _cachedJson;
    }

    /// <summary>
    /// Generate an ECMAScript module (ESM) SDK from the protocol descriptor.
    /// Produces a BMWClient class with WebSocket binary transport, generated
    /// route methods, and entity wrapper classes. Loadable via:
    ///   import { BMWClient } from "/bmw/sdk.js";
    /// No bundlers, transpilers, or build tools required.
    /// </summary>
    public string GenerateJsSdk()
    {
        if (_cachedSdk != null) return _cachedSdk;

        var sb = new StringBuilder(8192);
        sb.Append("// Auto-generated BMW ESM SDK — do not edit\n");
        sb.Append("// Protocol: BMW1.0\n");
        sb.Append("// Usage: import { BMWClient } from \"/bmw/sdk.js\";\n\n");

        // Embedded protocol descriptor
        sb.Append("const descriptor = ");
        sb.Append(ToJson());
        sb.Append(";\n\n");

        // Binary frame helpers (module-level, shared by all instances)
        sb.Append("const ROUTE_BITS = ");
        sb.Append(BmwBinaryTransport.RouteBits);
        sb.Append(";\n");
        sb.Append("const FRAME_SIZE = ");
        sb.Append(BmwBinaryTransport.FrameSize);
        sb.Append(";\n");
        sb.Append("const PAYLOAD_HDR = ");
        sb.Append(BmwBinaryTransport.PayloadLengthSize);
        sb.Append(";\n\n");

        sb.Append("function encodeFrame(opcode, entityId) {\n");
        sb.Append("  const b = new Uint8Array(FRAME_SIZE);\n");
        sb.Append("  const v = new DataView(b.buffer);\n");
        sb.Append("  v.setUint16(0, opcode << 2);\n");
        sb.Append("  v.setUint32(2, entityId, true);\n");
        sb.Append("  return b;\n");
        sb.Append("}\n\n");

        sb.Append("function encodePayload(frame, data) {\n");
        sb.Append("  const json = JSON.stringify(data);\n");
        sb.Append("  const enc = new TextEncoder().encode(json);\n");
        sb.Append("  const len = enc.length;\n");
        sb.Append("  const buf = new Uint8Array(FRAME_SIZE + PAYLOAD_HDR + len);\n");
        sb.Append("  buf.set(frame);\n");
        sb.Append("  buf[6] = len & 0xFF;\n");
        sb.Append("  buf[7] = (len >> 8) & 0xFF;\n");
        sb.Append("  buf[8] = (len >> 16) & 0xFF;\n");
        sb.Append("  buf.set(enc, FRAME_SIZE + PAYLOAD_HDR);\n");
        sb.Append("  return buf;\n");
        sb.Append("}\n\n");

        sb.Append("function decodeResponse(buf) {\n");
        sb.Append("  if (buf.byteLength <= FRAME_SIZE) return null;\n");
        sb.Append("  return JSON.parse(new TextDecoder().decode(\n");
        sb.Append("    new Uint8Array(buf, FRAME_SIZE + PAYLOAD_HDR)));\n");
        sb.Append("}\n\n");

        // BMWClient class
        sb.Append("export class BMWClient {\n");
        sb.Append("  #ws = null;\n");
        sb.Append("  #pending = new Map();\n");
        sb.Append("  #nextId = 1;\n");
        sb.Append("  #connected = false;\n\n");

        sb.Append("  constructor(protocol) {\n");
        sb.Append("    this.protocol = protocol || descriptor;\n");
        sb.Append("    this.routes = {};\n");
        sb.Append("    for (const r of this.protocol.routes) {\n");
        sb.Append("      this.routes[r.name] = r.opcode;\n");
        sb.Append("    }\n");
        sb.Append("  }\n\n");

        sb.Append("  get connected() { return this.#connected; }\n\n");

        // connect() — opens WebSocket, sets up response correlation
        sb.Append("  connect(url) {\n");
        sb.Append("    return new Promise((resolve, reject) => {\n");
        sb.Append("      const wsUrl = url ||\n");
        sb.Append("        ((typeof location !== 'undefined')\n");
        sb.Append("          ? `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/bmw/ws`\n");
        sb.Append("          : 'ws://localhost/bmw/ws');\n");
        sb.Append("      this.#ws = new WebSocket(wsUrl);\n");
        sb.Append("      this.#ws.binaryType = 'arraybuffer';\n");
        sb.Append("      this.#ws.onopen = () => { this.#connected = true; resolve(this); };\n");
        sb.Append("      this.#ws.onerror = (e) => reject(e);\n");
        sb.Append("      this.#ws.onclose = () => {\n");
        sb.Append("        this.#connected = false;\n");
        sb.Append("        for (const [, cb] of this.#pending) cb(null, new Error('Connection closed'));\n");
        sb.Append("        this.#pending.clear();\n");
        sb.Append("      };\n");
        sb.Append("      this.#ws.onmessage = (e) => {\n");
        sb.Append("        const v = new DataView(e.data);\n");
        sb.Append("        const id = v.getUint32(2, true);\n");
        sb.Append("        const cb = this.#pending.get(id);\n");
        sb.Append("        if (cb) { this.#pending.delete(id); cb(e.data); }\n");
        sb.Append("      };\n");
        sb.Append("    });\n");
        sb.Append("  }\n\n");

        // send() — encode + dispatch a binary frame, return Promise
        sb.Append("  send(opcode, entityId, data) {\n");
        sb.Append("    return new Promise((resolve, reject) => {\n");
        sb.Append("      if (!this.#ws || this.#ws.readyState !== 1)\n");
        sb.Append("        return reject(new Error('Not connected'));\n");
        sb.Append("      const reqId = entityId || (this.#nextId++);\n");
        sb.Append("      this.#pending.set(reqId, (buf, err) => {\n");
        sb.Append("        if (err) return reject(err);\n");
        sb.Append("        resolve(decodeResponse(buf));\n");
        sb.Append("      });\n");
        sb.Append("      const frame = encodeFrame(opcode, reqId);\n");
        sb.Append("      if (data !== undefined) {\n");
        sb.Append("        this.#ws.send(encodePayload(frame, data));\n");
        sb.Append("      } else {\n");
        sb.Append("        this.#ws.send(frame);\n");
        sb.Append("      }\n");
        sb.Append("    });\n");
        sb.Append("  }\n\n");

        // close()
        sb.Append("  close() {\n");
        sb.Append("    if (this.#ws) { this.#ws.close(); this.#ws = null; }\n");
        sb.Append("  }\n");
        sb.Append("}\n\n");

        // Generated prototype methods for each route
        sb.Append("// ── Generated route methods ──────────────────────────────────────\n\n");
        foreach (var route in _routes)
        {
            sb.Append("BMWClient.prototype.");
            sb.Append(route.Name);

            if (route.HasPayload)
            {
                if (route.ParameterNames.Length > 0)
                {
                    sb.Append(" = function(id, data) {\n");
                    sb.Append("  return this.send(");
                    sb.Append(route.Opcode);
                    sb.Append(", id, data);\n};\n\n");
                }
                else
                {
                    sb.Append(" = function(data) {\n");
                    sb.Append("  return this.send(");
                    sb.Append(route.Opcode);
                    sb.Append(", 0, data);\n};\n\n");
                }
            }
            else
            {
                if (route.ParameterNames.Length > 0)
                {
                    sb.Append(" = function(id) {\n");
                    sb.Append("  return this.send(");
                    sb.Append(route.Opcode);
                    sb.Append(", id);\n};\n\n");
                }
                else
                {
                    sb.Append(" = function() {\n");
                    sb.Append("  return this.send(");
                    sb.Append(route.Opcode);
                    sb.Append(", 0);\n};\n\n");
                }
            }
        }

        // Entity wrapper classes
        sb.Append("// ── Entity classes ───────────────────────────────────────────────\n\n");
        foreach (var entity in _entities)
        {
            string className = Capitalize(entity.Key);
            sb.Append("export class ");
            sb.Append(className);
            sb.Append(" {\n");
            sb.Append("  constructor(data) {\n");
            sb.Append("    if (data) Object.assign(this, data);\n");
            sb.Append("  }\n");
            sb.Append("}\n\n");
        }

        // Named exports
        sb.Append("export { descriptor, encodeFrame, decodeResponse };\n");

        _cachedSdk = sb.ToString();
        return _cachedSdk;
    }

    /// <summary>
    /// Generate a Node.js CLI client script from the protocol descriptor.
    /// Uses WebSocket binary transport with the same opcode mappings as the browser SDK.
    /// Executable via: node bmw-cli.js &lt;entity&gt; &lt;action&gt; [id] [payload.json]
    /// </summary>
    public string GenerateCliReference()
    {
        if (_cachedCli != null) return _cachedCli;

        var sb = new StringBuilder(4096);
        sb.Append("#!/usr/bin/env node\n");
        sb.Append("// Auto-generated BMW CLI client — do not edit\n");
        sb.Append("// Protocol: BMW1.0\n");
        sb.Append("// Usage: node bmw-cli.js <entity> <action> [id] [payload.json]\n\n");

        sb.Append("import { readFileSync } from 'fs';\n");
        sb.Append("import { WebSocket } from 'ws';\n\n");

        // Embed the opcode table as a flat lookup
        sb.Append("const commands = {\n");
        foreach (var entity in _entities)
        {
            foreach (int opcode in entity.Value.Opcodes)
            {
                if (!_byOpcode.TryGetValue(opcode, out var route)) continue;
                string action = route.Method switch
                {
                    "GET" when route.ParameterNames.Length > 0 => "get",
                    "GET" => "list",
                    "POST" => "create",
                    "PUT" => "update",
                    "PATCH" => "patch",
                    "DELETE" => "delete",
                    "HEAD" => "head",
                    _ => route.Method.ToLowerInvariant()
                };
                sb.Append("  '");
                sb.Append(entity.Key);
                sb.Append(':');
                sb.Append(action);
                sb.Append("': { opcode: ");
                sb.Append(opcode);
                sb.Append(", hasId: ");
                sb.Append(route.ParameterNames.Length > 0 ? "true" : "false");
                sb.Append(", hasPayload: ");
                sb.Append(route.HasPayload ? "true" : "false");
                sb.Append(" },\n");
            }
        }
        sb.Append("};\n\n");

        // Frame encoding (same wire format as browser SDK)
        sb.Append("function encodeFrame(opcode, entityId) {\n");
        sb.Append("  const b = Buffer.alloc(6);\n");
        sb.Append("  b.writeUInt16BE(opcode << 2, 0);\n");
        sb.Append("  b.writeUInt32LE(entityId, 2);\n");
        sb.Append("  return b;\n");
        sb.Append("}\n\n");

        sb.Append("function encodePayload(frame, payload) {\n");
        sb.Append("  const json = Buffer.from(JSON.stringify(payload));\n");
        sb.Append("  const len = json.length;\n");
        sb.Append("  const buf = Buffer.alloc(frame.length + 3 + len);\n");
        sb.Append("  frame.copy(buf);\n");
        sb.Append("  buf[6] = len & 0xFF;\n");
        sb.Append("  buf[7] = (len >> 8) & 0xFF;\n");
        sb.Append("  buf[8] = (len >> 16) & 0xFF;\n");
        sb.Append("  json.copy(buf, 9);\n");
        sb.Append("  return buf;\n");
        sb.Append("}\n\n");

        // Main CLI entry
        sb.Append("const [,, entity, action, ...rest] = process.argv;\n");
        sb.Append("const host = process.env.BMW_HOST || 'ws://localhost:5000/bmw/ws';\n\n");

        sb.Append("if (!entity || !action) {\n");
        sb.Append("  console.log('BMW CLI — Protocol BMW1.0');\n");
        sb.Append("  console.log('Usage: bmw <entity> <action> [id] [payload.json]\\n');\n");
        sb.Append("  console.log('Commands:');\n");
        sb.Append("  for (const k of Object.keys(commands)) {\n");
        sb.Append("    const [e, a] = k.split(':');\n");
        sb.Append("    const c = commands[k];\n");
        sb.Append("    let args = '';\n");
        sb.Append("    if (c.hasId) args += ' <id>';\n");
        sb.Append("    if (c.hasPayload) args += ' <payload.json>';\n");
        sb.Append("    console.log(`  bmw ${e} ${a}${args}  (opcode=${c.opcode})`);\n");
        sb.Append("  }\n");
        sb.Append("  process.exit(0);\n");
        sb.Append("}\n\n");

        sb.Append("const cmd = commands[`${entity}:${action}`];\n");
        sb.Append("if (!cmd) {\n");
        sb.Append("  console.error(`Unknown command: ${entity} ${action}`);\n");
        sb.Append("  process.exit(1);\n");
        sb.Append("}\n\n");

        sb.Append("let id = 0, payload;\n");
        sb.Append("if (cmd.hasId && rest.length > 0) id = parseInt(rest.shift(), 10);\n");
        sb.Append("if (cmd.hasPayload && rest.length > 0) {\n");
        sb.Append("  const file = rest.shift();\n");
        sb.Append("  payload = JSON.parse(file === '-' ? readFileSync(0, 'utf8') : readFileSync(file, 'utf8'));\n");
        sb.Append("}\n\n");

        sb.Append("const ws = new WebSocket(host);\n");
        sb.Append("ws.binaryType = 'arraybuffer';\n");
        sb.Append("ws.on('open', () => {\n");
        sb.Append("  const frame = encodeFrame(cmd.opcode, id);\n");
        sb.Append("  ws.send(payload ? encodePayload(frame, payload) : frame);\n");
        sb.Append("});\n");
        sb.Append("ws.on('message', (buf) => {\n");
        sb.Append("  if (buf.byteLength > 9) {\n");
        sb.Append("    const data = Buffer.from(buf).subarray(9).toString('utf8');\n");
        sb.Append("    try { console.log(JSON.stringify(JSON.parse(data), null, 2)); }\n");
        sb.Append("    catch { console.log(data); }\n");
        sb.Append("  } else { console.log('OK'); }\n");
        sb.Append("  ws.close();\n");
        sb.Append("});\n");
        sb.Append("ws.on('error', (e) => { console.error(e.message); process.exit(1); });\n");

        _cachedCli = sb.ToString();
        return _cachedCli;
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static string? ExtractEntitySlug(string path)
    {
        // Match /api/{slug} or /api/{slug}/{id} patterns
        if (!path.StartsWith("/api/", StringComparison.Ordinal) || path.Length <= 5)
            return null;

        var rest = path.AsSpan(5);
        int slash = rest.IndexOf('/');
        string slug = slash >= 0 ? rest[..slash].ToString() : rest.ToString();

        // Skip internal prefixes
        if (slug.StartsWith("_", StringComparison.Ordinal))
            return null;

        return slug;
    }

    internal static string GenerateSdkName(string verb, string path, string? entity)
    {
        if (entity == null)
        {
            // Non-entity routes: verbify the last path segment
            int lastSlash = path.LastIndexOf('/');
            string segment = lastSlash >= 0 ? path[(lastSlash + 1)..] : path;
            // Strip parameter placeholders
            segment = segment.Replace("{", "").Replace("}", "");
            if (string.IsNullOrEmpty(segment)) segment = "root";
            return ToCamelCase(verb.ToLowerInvariant() + "_" + segment);
        }

        // Entity routes: verb + entity name (singularized for id-bearing routes)
        string action = verb switch
        {
            "GET" when path.Contains("{id") => "get",
            "GET" => "list",
            "POST" => "create",
            "PUT" => "update",
            "PATCH" => "patch",
            "DELETE" => "delete",
            "HEAD" => "head",
            _ => verb.ToLowerInvariant()
        };

        return action + Capitalize(entity);
    }

    private static string Capitalize(string s)
        => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];

    internal static string ToCamelCase(string s)
    {
        if (s.Length == 0) return s;
        var sb = new StringBuilder(s.Length);
        bool upper = false;
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '_' || c == '-')
            {
                upper = true;
                continue;
            }
            sb.Append(upper ? char.ToUpperInvariant(c) : (i == 0 ? char.ToLowerInvariant(c) : c));
            upper = false;
        }
        return sb.ToString();
    }

    private static void AppendMethod(StringBuilder sb, string name, int ordinal, bool first)
    {
        if (!first) sb.Append(',');
        sb.Append("{\"name\":\"");
        sb.Append(name);
        sb.Append("\",\"ordinal\":");
        sb.Append(ordinal);
        sb.Append(",\"hasPayload\":");
        sb.Append(BmwBinaryTransport.IsWriteMethod(ordinal) ? "true" : "false");
        sb.Append('}');
    }

    private void AppendRoute(StringBuilder sb, RouteDescriptor r)
    {
        sb.Append("{\"name\":\"");
        sb.Append(EscapeJson(r.Name));
        sb.Append("\",\"opcode\":");
        sb.Append(r.Opcode);
        sb.Append(",\"method\":\"");
        sb.Append(r.Method);
        sb.Append("\",\"methodOrdinal\":");
        sb.Append(r.MethodOrdinal);
        sb.Append(",\"routeOrdinal\":");
        sb.Append(r.RouteOrdinal);
        sb.Append(",\"path\":\"");
        sb.Append(EscapeJson(r.Path));
        sb.Append('"');
        if (r.Entity != null)
        {
            sb.Append(",\"entity\":\"");
            sb.Append(EscapeJson(r.Entity));
            sb.Append('"');
        }
        if (r.ParameterNames.Length > 0)
        {
            sb.Append(",\"params\":[");
            for (int i = 0; i < r.ParameterNames.Length; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append('"');
                sb.Append(EscapeJson(r.ParameterNames[i]));
                sb.Append('"');
            }
            sb.Append(']');
        }
        if (r.HasPayload)
            sb.Append(",\"hasPayload\":true");
        if (r.Permission != null)
        {
            sb.Append(",\"permission\":\"");
            sb.Append(EscapeJson(r.Permission));
            sb.Append('"');
        }
        sb.Append('}');
    }

    private static string EscapeJson(string s) =>
        s.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
