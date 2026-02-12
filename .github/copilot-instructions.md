# BareMetalWeb Copilot instructions

## Architecture and flow
- Single-handler, no MVC, no middleware pipeline, and no DI containers. Routing and lifecycle are explicit and data-driven.
- Kestrel/ASP.NET Core are used only for HTTP/SSL; everything else is built from scratch for minimalism and performance.
- Routes are mutable after startup; call `appinfo.BuildAppInfoMenuOptions()` if you add routes dynamically so the header menu updates.

## Rendering
- HTML rendering uses lightweight template replacement (not Razor). Tokens are `{{replacetoken}}`.
- Loop syntax: `{{Loop%%loopKey}}...{{EndLoop}}` for foreach blocks and `{{For%%i|from|to|increment}}...{{EndFor}}` for for blocks.
- Rendering favors streaming with `PipeReader`/`PipeWriter` to minimize allocations and GC pressure.

## Data and storage
- Session/data storage uses a custom binary serializer designed for speed and compactness.
- Data storage is pluggable via the repository abstraction; the default implementation is file-based binary, but storage can be swapped.

## Performance and security conventions
- Avoid allocations/GC pressure; prefer `Span<T>`, `Memory<T>`, and streaming patterns.
- Strong CSP, secure auth/session handling, and request throttling are built in; keep changes aligned with these constraints.

## Static files and proxy
- Static files are served by the custom handler (no middleware) with caching/ETag/Last-Modified support configured in `appsettings.json` under `StaticFiles`.
- Proxy routing is enabled via `Proxy:Route` and `Proxy:TargetBaseUrl` in `appsettings*.json` and forwards requests excluding the auth session cookie.
