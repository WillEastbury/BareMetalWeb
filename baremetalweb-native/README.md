# BareMetalWeb Native

A native C port of BareMetalWeb with a pluggable module architecture.

## Architecture

```
┌─────────────────────────────────────────────┐
│                  main.c                      │
│          Event Loop (epoll/kqueue/WSAPoll)   │
├─────────────────────┬───────────────────────┤
│   mod_http (port 8080)  │  mod_wal (port 8001) │
│   ─ HTTP/1.1 parser     │  ─ WAL engine        │
│   ─ Route dispatch       │  ─ TCP wire protocol │
│   ─ Template engine      │  ─ Slot-based store  │
│   ─ Static file server   │  ─ Compaction        │
└─────────────────────┴───────────────────────┘
```

## Modules

### HTTP Server (`mod_http`)
- Non-blocking TCP on configurable port (default 8080)
- HTTP/1.1 request parsing with keep-alive
- Route table: exact match + prefix match
- Template engine with `{{token}}` substitution (HTML-escaped by default, `{{{raw}}}` for unescaped)
- Static file serving with path traversal protection
- MIME type detection

### WAL Engine (`mod_wal`)
- PicoWAL-compatible Write-Ahead Log
- Binary wire protocol: APPEND (0x01), READ (0x02), NOOP (0x00)
- Slot-based storage (32 × 512B slots)
- Delta header format: `[key_hash:u32][value_len:u16][op:u8][reserved:u8]`
- Background compaction (keeps latest per key)
- Exposed as internal service + optional TCP listener (port 8001)
- HTTP endpoints: `POST /wal/append`, `GET /wal/read?key=<key>`

## Building

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

### Windows (MSVC)
```cmd
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022"
cmake --build . --config Release
```

## Running

```bash
./baremetalweb
# HTTP on :8080, WAL TCP on :8001
```

Place static files in `./wwwroot/`.

## Module Interface

Modules implement:
- `init(config, services)` - Configure and register services
- `start(event_loop)` - Bind sockets, start listening  
- `stop()` - Close connections
- `shutdown()` - Free resources

Modules communicate via a service registry (e.g., WAL registers `"wal.engine"`, HTTP registers `"http.router"`).

## Configuration

Ports and paths are set via `bmw_config_t` entries in `main.c`. To change defaults, edit the config arrays or add a config file parser.
