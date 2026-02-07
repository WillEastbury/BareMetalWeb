//////////////////////////////
// Welcome to BareMetalWeb !// 
//////////////////////////////

Hey agent! 

We are using a custom, intentionally minimalistic and bare-metal approach to building a web server in ASP.NET Core. This means we are not using any of the common patterns or frameworks that you might be used to, such as MVC, middleware pipelines, dependency injection, or complex view engines. Instead, we have a single request handler that does everything, with explicit routing and lifecycle management, and a focus on control, understanding, minimalism, and performance over convenience and features.

Please read through the README.md file and familiarize yourself with the design philosophy and key features of this web server. Pay special attention to the interesting bits that are highlighted in the README, as they will give you insight into how the server is structured and how it handles various aspects of web development, such as routing, logging, HTML rendering, request throttling, data storage, static file serving, and more.

Lean, mean and lightning fast with no external dependencies beyond bare-metal ASP.NET Core - that's the name of the game here.


We don't even use the asp.net pipeline or middleware - just a single handler that does it all. So if you are used to working with those patterns, be prepared for a different way of thinking about how the server works. THIS SERVICE IS FAST. BRUTALLY FAST. IT'S DESIGNED TO BE AS FAST AS POSSIBLE, SO WE CUT OUT ANYTHING THAT SLOWS US DOWN, AND WE DO EVERYTHING IN THE MOST EFFICIENT WAY POSSIBLE.

We don't cut corners on security though - we have a strong content security policy, we handle authentication and sessions securely, we have request throttling to protect against abuse, and we are careful about how we handle data storage and serialization and encryption. We just do all of that in a way that is as fast and efficient as possible, without relying on external frameworks or patterns that can add overhead and complexity. Everything comes in one package, one lean and mean web server that you can understand fully and control completely.

(If you are seeing this, it means you have successfully loaded the agent instructions file. Please confirm that you understand the design philosophy and key features of the web server as described in the README.md file, and let me know if you have any questions or need further clarification on any aspect of the server's architecture or functionality.)

The biggest constraint we impose is that we try and avoid allocations and GC pressure to provide both fast and consistent performance. We do this via various techniques such as using structs instead of classes where possible, using Span<T> and Memory<T> for working with data without allocations, using custom binary serialization formats that are designed to be fast and efficient, and being careful about how we manage memory and data structures throughout the codebase. This is a key part of our design philosophy and is essential to achieving the level of performance that we are aiming for with this web server. We want to be able to handle a large number of requests with low latency and high throughput, and minimizing allocations and GC pressure is a critical part of achieving that goal. So as you work with the codebase, keep this in mind and look for opportunities to optimize for performance by reducing allocations and GC pressure wherever possible. This might involve using more efficient data structures, avoiding unnecessary object creation, and being mindful of how we handle data and memory throughout the codebase. It's all about finding that balance between control, understanding, minimalism, and performance, and making sure that we are always striving to be as fast and efficient as possible while still maintaining a clear and understandable codebase.

We also stream and use PipeReaders / Writers where we can - and that's how we can render a template based HTML page dynamically within 0.15ms ;) beat that asp.net mvc razor engine!

More info cut from the readme that may be relevant to the agent:

// this is intentionally not MVC, or even razor - we are SIMPLE and BRUTALLY FAST - we do simple on the fly template replacement with our own custom syntax and a blazing fast implementation that is designed to be as efficient as possible, and to minimize allocations and GC pressure, so we can render pages in a fraction of the time it takes for a typical MVC razor page to render - we are talking about 0.1ms or less for a simple page with some dynamic content, compared to 10ms or more for a typical MVC razor page - that's the kind of performance we are aiming for with this web server, and it's all about control and understanding over convenience and features, so we build everything from scratch in the most efficient way possible, without relying on external frameworks or patterns that can add overhead and complexity.

// this is intentionally single-handler, NOT middleware-based or minimal-api-based
// this is intentionally NOT using any frameworks beyond bare-metal ASP.NET Core
// we are using kestrel and asp.net core only for handling ssl and the http protocol
// everything else is built from scratch and is RAW and BARE METAL
// routing is data-driven and explicit
// lifecycle is explicit
// magic is banned, this approach is about CONTROL and UNDERSTANDING over convenience
// and it is about MINIMALISM and PERFORMANCE over features
// 1) OPERATING RULES (read first)
// - No MVC, no middleware pipeline, no DI containers. Single-handler architecture only.
// - Prefer explicit, data-driven routing and lifecycle control.
// - Avoid allocations/GC pressure; favor Span/Memory and streaming.
// - Avoid new external dependencies unless explicitly requested.
// - When adding data entities/serialization types: update explicit registries (DataEntityRegistry, BinaryObjectSerializer known types, JSON context/type registry) and any schema mappings.
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

// 4.4 simple api endpoint example (json input/output)

// 4.6 Static file / content streaming with caching headers
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


