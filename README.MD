//////////////////////////////
// Welcome to BareMetalWeb !// 
//////////////////////////////
// this is intentionally not MVC
// this is intentionally single-handler, NOT middleware-based or minimal-api-based
// this is intentionally NOT using any frameworks beyond bare-metal ASP.NET Core
// we are using kestrel and asp.net core only for handling ssl and the http protocol
// everything else is built from scratch and is RAW and BARE METAL
// routing is data-driven and explicit
// lifecycle is explicit
// magic is banned, this approach is about CONTROL and UNDERSTANDING over convenience
// and it is about MINIMALISM and PERFORMANCE over features
// this is a LEAN and MEAN web server example
// this will be lightning fast and efficient
// think asp.net classic era ashx handlers and httpmodules but in modern .net 7+ form
// and with a focus on clarity and simplicity over cleverness and complexity

// interesting bits: 
// “routes are NOT immutable after startup” - if you want to add routes on the fly - knock yourself out - just call appinfo.BuildAppInfoMenuOptions() to update the header menu afterwards

// “logging is buffered to disk asynchronously” - so logging does not block request handling, EXCEPT for exception logging - which during app shutdown is strictly best effort on flush to console - but we do write a clean shutdown record so you can see no data loss in logs even if the app is killed hard - and we do flush the buffer on graceful shutdown so you can see a clean shutdown record in the logs as well.
also the logs are written per-day-per-hour-per-minute log files to keep them manageable and easy to find relevant logs for a given time period, and to avoid giant log files that are hard to work with, and we close those with a record on cycle too. 

// “html rendering is done via simple template replacement” - no razor, no cshtml, no complex view engines, just simple and fast on the fly streaming replacement inside basic text templates with {{replacetoken}}, foreach blocks with {{Loop%%loopKey}}...{{EndLoop}}, and for blocks with {{For%%i|from|to|increment}}...{{EndFor}}

// “no dependency injection, no service containers” - everything is explicit and straightforward - we do use interfaces for key components to allow easy swapping if needed, so nothing is technically stopping you from injecting different interfaces we just don't use that pattern for both speed of skipping the DI container and simplicity and readability.
// “no middleware pipeline” - just a single request handler that does everything - no complex middleware chains to understand or manage, register a route with pagedata and a handler via a delegate and boom away you go.

// We have a simple request throttling system to protect against abuse and overload - maybe a simple token bucket algorithm that tracks request counts per IP and shortcuts the handler to 429, the values are configurable. 

// We have a super-fast binary serializer for session data and other data storage needs - it's a custom format that is designed to be as fast as possible to serialize and deserialize, and to be compact on disk and in memory - it's not human-readable but it's lightning fast and efficient for our needs.

// We also have a pluggable data abstraction storage framework and repository pattern that allows you to easily swap out different storage implementations - we have a simple file-based binary implementation for user accounts and sessions, but you could easily swap in a database-backed implementation if you wanted to - the interfaces are designed to be flexible and easy to work with, and the file-based implementation is designed to be simple and easy to understand as well.

//Static file / content streaming with caching headers
// - configured in appsettings.json (StaticFiles)
// - serves files from a fixed folder (default: wwwroot/static) via a fixed prefix (default: /static)
// - streams file bytes directly from disk (no MVC, no middleware)
// - supports cache headers (Cache-Control, ETag, Last-Modified) with configurable max-age
// - supports MIME type mapping via StaticFiles:MimeTypes (defaults provided, override/add as needed)
// - unknown MIME types are blocked by default (AllowUnknownMime=false) unless you opt in
// - example: request /static/site.css -> reads wwwroot/static/site.css
//
// appsettings.json snippet:
// "StaticFiles": {
//   "Enabled": true,
//   "RequestPathPrefix": "/static",
//   "RootDirectory": "wwwroot/static",
//   "EnableCaching": true,
//   "CacheSeconds": 86400,
//   "AddETag": true,
//   "AddLastModified": true,
//   "AllowUnknownMime": false,
//   "DefaultMimeType": "application/octet-stream",
//   "MimeTypes": { ".webmanifest": "application/manifest+json", ".wasm": "application/wasm" }
// }

// 4.7 a rudimentary service proxy / router
// Configure Proxy:Route and Proxy:TargetBaseUrl in appsettings*.json
// Requests to the route are forwarded to the target (headers/body preserved), excluding the auth session cookie

// 4.8 Paged file store with optimistic concurrency
// A page-addressable storage engine with deterministic write ordering, no locks for normal page writes,
// and optional optimistic concurrency control. Uses extent-based partitioning with single-writer queues.
//
// Key features:
// - Single-writer queue per extent (~64MB partitions) for deterministic FIFO write order
// - No locks on hot path - extent writers serialize writes naturally
// - Optimistic concurrency via version/LSN tracking and If-Match headers
// - Bounded queues with backpressure (returns 429/503 when full)
// - Durable sync flush per write for strong crash semantics
// - In-memory metadata cache for fast reads
// - HTTP API: GET, HEAD, POST, PUT /pages endpoints
//
// Configuration in appsettings.json:
// "PageStore": {
//   "Enabled": false,
//   "PageSize": 4096,
//   "ExtentSizeBytes": 67108864,    // 64 MB extents
//   "QueueCapacity": 1000,           // Bounded queue per extent
//   "RequiredPermission": "Public"   // or "Authenticated", "admin", etc.
// }
//
// API endpoints when enabled:
// POST   /pages           → create new page, returns { pageId, version } with ETag
// GET    /pages/{id}      → read page data with ETag: "{version}" header
// HEAD   /pages/{id}      → metadata only (ETag without body)
// PUT    /pages/{id}      → update page, supports If-Match for optimistic concurrency
//                           returns 412 Precondition Failed on version mismatch
//
// Benefits:
// - No locks on hot path - extent writers serialize naturally
// - Highly scalable write throughput via extent parallelism
// - Simple optimistic control prevents lost updates  
// - Durable sync flush per write gives strong crash semantics
//

