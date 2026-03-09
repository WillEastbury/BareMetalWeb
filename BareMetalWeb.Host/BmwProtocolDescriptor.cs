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
    /// Generate a JavaScript SDK module string from the protocol descriptor.
    /// Creates a virtual SDK where each entity method maps to binary transport opcodes.
    /// </summary>
    public string GenerateJsSdk()
    {
        var sb = new StringBuilder(4096);
        sb.Append("// Auto-generated BMW SDK — do not edit\n");
        sb.Append("// Protocol: BMW1.0 | Generated: ");
        sb.Append(DateTime.UtcNow.ToString("O"));
        sb.Append('\n');
        sb.Append("const BmwSdk=(()=>{\n'use strict';\n");
        sb.Append("const _d=");
        sb.Append(ToJson());
        sb.Append(";\n");
        sb.Append("const _opcodes=new Map();\n");
        sb.Append("for(const r of _d.routes)_opcodes.set(r.name,r);\n\n");

        // Frame encode/decode helpers
        sb.Append("function encodeFrame(method,route,entityId){\n");
        sb.Append("const b=new Uint8Array(6);\n");
        sb.Append("const op=(method<<");
        sb.Append(BmwBinaryTransport.RouteBits);
        sb.Append(")|route;\n");
        sb.Append("const v=new DataView(b.buffer);\n");
        sb.Append("v.setUint16(0,op<<2);\n");
        sb.Append("v.setUint32(2,entityId,true);\nreturn b;\n}\n\n");

        sb.Append("function encodePayload(frame,data){\n");
        sb.Append("const json=JSON.stringify(data);\n");
        sb.Append("const enc=new TextEncoder().encode(json);\n");
        sb.Append("const len=enc.length;\n");
        sb.Append("const buf=new Uint8Array(frame.length+3+len);\n");
        sb.Append("buf.set(frame);\n");
        sb.Append("buf[6]=len&0xFF;buf[7]=(len>>8)&0xFF;buf[8]=(len>>16)&0xFF;\n");
        sb.Append("buf.set(enc,9);\nreturn buf;\n}\n\n");

        // WebSocket connection management
        sb.Append("let _ws=null,_pending=new Map(),_nextId=1;\n");
        sb.Append("function connect(url){\n");
        sb.Append("return new Promise((resolve,reject)=>{\n");
        sb.Append("_ws=new WebSocket(url);\n");
        sb.Append("_ws.binaryType='arraybuffer';\n");
        sb.Append("_ws.onopen=()=>resolve(_ws);\n");
        sb.Append("_ws.onerror=e=>reject(e);\n");
        sb.Append("_ws.onmessage=e=>{\n");
        sb.Append("const v=new DataView(e.data);\n");
        sb.Append("const id=v.getUint32(2,true);\n");
        sb.Append("const cb=_pending.get(id);\n");
        sb.Append("if(cb){_pending.delete(id);cb(e.data);}\n");
        sb.Append("};\n});\n}\n\n");

        // send() — fire a binary frame and resolve with response
        sb.Append("function send(method,route,entityId,data){\n");
        sb.Append("return new Promise((resolve,reject)=>{\n");
        sb.Append("if(!_ws||_ws.readyState!==1)return reject(new Error('Not connected'));\n");
        sb.Append("const reqId=entityId||(_nextId++);\n");
        sb.Append("_pending.set(reqId,buf=>{\n");
        sb.Append("if(buf.byteLength>6){const dec=new TextDecoder();\n");
        sb.Append("resolve(JSON.parse(dec.decode(new Uint8Array(buf,9))));\n");
        sb.Append("}else resolve(null);\n});\n");
        sb.Append("const frame=encodeFrame(method,route,reqId);\n");
        sb.Append("if(data!==undefined){_ws.send(encodePayload(frame,data));}\n");
        sb.Append("else{_ws.send(frame);}\n");
        sb.Append("});\n}\n\n");

        // Generate entity-specific SDK methods
        foreach (var entity in _entities)
        {
            string slug = entity.Key;
            string jsName = ToCamelCase(slug);
            sb.Append("// ── ");
            sb.Append(slug);
            sb.Append(" ──\n");
            sb.Append("const ");
            sb.Append(jsName);
            sb.Append("={\n");

            foreach (int opcode in entity.Value.Opcodes)
            {
                if (!_byOpcode.TryGetValue(opcode, out var route)) continue;
                int methodOrd = BmwBinaryTransport.GetMethod(opcode);
                int routeOrd = BmwBinaryTransport.GetRoute(opcode);

                sb.Append("  ");
                sb.Append(route.Name);
                sb.Append(':');

                if (route.HasPayload)
                {
                    // Write methods: fn(data) or fn(id, data)
                    if (route.ParameterNames.Length > 0)
                    {
                        sb.Append("(id,data)=>send(");
                        sb.Append(methodOrd);
                        sb.Append(',');
                        sb.Append(routeOrd);
                        sb.Append(",id,data)");
                    }
                    else
                    {
                        sb.Append("(data)=>send(");
                        sb.Append(methodOrd);
                        sb.Append(',');
                        sb.Append(routeOrd);
                        sb.Append(",0,data)");
                    }
                }
                else
                {
                    // Read methods: fn(id) or fn()
                    if (route.ParameterNames.Length > 0)
                    {
                        sb.Append("(id)=>send(");
                        sb.Append(methodOrd);
                        sb.Append(',');
                        sb.Append(routeOrd);
                        sb.Append(",id)");
                    }
                    else
                    {
                        sb.Append("()=>send(");
                        sb.Append(methodOrd);
                        sb.Append(',');
                        sb.Append(routeOrd);
                        sb.Append(",0)");
                    }
                }
                sb.Append(",\n");
            }
            sb.Append("};\n\n");
        }

        // Public API
        sb.Append("return{connect,send,descriptor:_d,opcodes:_opcodes");
        foreach (var entity in _entities)
        {
            sb.Append(',');
            sb.Append(ToCamelCase(entity.Key));
        }
        sb.Append("};\n})();\n");

        return sb.ToString();
    }

    /// <summary>
    /// Generate CLI command mappings from the protocol descriptor.
    /// Returns a help-text style listing of available CLI commands.
    /// </summary>
    public string GenerateCliReference()
    {
        var sb = new StringBuilder(2048);
        sb.Append("# BMW CLI Reference\n# Protocol: BMW1.0\n#\n");
        sb.Append("# Usage: bmw <entity> <action> [id] [payload.json]\n#\n");

        foreach (var entity in _entities)
        {
            sb.Append("\n# ── ");
            sb.Append(entity.Key);
            sb.Append(" ──\n");

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

                sb.Append("bmw ");
                sb.Append(entity.Key);
                sb.Append(' ');
                sb.Append(action);
                if (route.ParameterNames.Length > 0)
                    sb.Append(" <id>");
                if (route.HasPayload)
                    sb.Append(" <payload.json>");
                sb.Append("   # opcode=");
                sb.Append(opcode);
                sb.Append('\n');
            }
        }

        return sb.ToString();
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
