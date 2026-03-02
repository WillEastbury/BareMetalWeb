# Reverse Proxy

BareMetalWeb includes a built-in reverse proxy that can forward requests to upstream targets with load balancing, retries, sticky sessions, and circuit-breaker health tracking.

## Configuration

Proxy routes are configured in `appsettings.json` under the `Proxy` section:

```json
{
  "Proxy": {
    "Routes": [
      {
        "Route": "/api/backend",
        "Verb": "ALL",
        "MatchMode": "StartsWith",
        "TargetBaseUrl": "https://upstream.example.com",
        "LoadBalance": "RoundRobin"
      }
    ]
  }
}
```

### Route Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Route` | string | `/proxy` | URL pattern to match |
| `Verb` | string | `ALL` | HTTP verb filter (`GET`, `POST`, `ALL`, etc.) |
| `MatchMode` | string | `Equals` | `Equals`, `StartsWith`, or `Regex` |
| `TargetBaseUrl` | string | — | Single upstream target URL |
| `Targets` | string[] | `[]` | Multiple upstream target URLs (equal weight) |
| `TargetConfigs` | object[] | `[]` | Targets with explicit weights (see below) |
| `LoadBalance` | string | `RoundRobin` | `RoundRobin` (weighted) or `Failover` |

### Weighted Targets

```json
"TargetConfigs": [
  { "Uri": "https://primary.example.com", "Weight": 3 },
  { "Uri": "https://secondary.example.com", "Weight": 1 }
]
```

### Path Manipulation

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `PathPrefixToStrip` | string | — | Remove this prefix before forwarding |
| `PathPrefixToAdd` | string | — | Add this prefix before forwarding |
| `RewritePath` | string | — | Replace the entire path |
| `IncludeQuery` | bool | `true` | Forward query string parameters |

### Headers

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `AddHeaders` | dict | `{}` | Headers to add to upstream requests |
| `RemoveHeaders` | string[] | `[]` | Headers to strip from upstream requests |
| `TraceIdHeader` | string | `X-Trace-ID` | Header for distributed trace correlation |

### Sticky Sessions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `StickySessionsEnabled` | bool | `false` | Enable session affinity |
| `StickySessionMode` | string | `Cookie` | `Cookie` or `IpHash` |
| `StickySessionKeyName` | string | `X-Proxy-Session` | Cookie/header name for session key |
| `StickySessionTtlSeconds` | int | `3600` | Cookie TTL |

### Lease-Owner Affinity

When running behind a load balancer (e.g. Azure App Service with ARR), you can pin proxied requests to the cluster lease owner. The proxy computes a SHA-256 hash of the lease owner's `InstanceId` and injects it as an `ARRAffinity` cookie on each outgoing request.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `LeaseAffinityCookieEnabled` | bool | `false` | Inject ARRAffinity cookie based on lease owner |
| `LeaseAffinityCookieName` | string | `ARRAffinity` | Cookie name (both `{name}` and `{name}SameSite` are set) |

**Example:**

```json
{
  "Proxy": {
    "Routes": [{
      "Route": "/api/backend",
      "MatchMode": "StartsWith",
      "TargetBaseUrl": "https://myapp.azurewebsites.net",
      "LeaseAffinityCookieEnabled": true,
      "LeaseAffinityCookieName": "ARRAffinity"
    }]
  }
}
```

The cookie value is `SHA256(InstanceId)` as lowercase hex. Both `ARRAffinity` and `ARRAffinitySameSite` cookies are set so the Azure load balancer routes the request to the instance that owns the cluster write lease.

### Retries

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `RetryIdempotentRequests` | bool | `true` | Retry GET/HEAD/OPTIONS/TRACE on 502/503/504 |
| `RetryAllMethodsHeader` | string | `X-Proxy-Retry-All` | Header to opt-in retry for non-idempotent methods |
| `MaxRetries` | int | `1` | Maximum retry attempts |
| `MaxRetryBodyBytes` | int | `1048576` | Max body size to buffer for retries (1 MB) |
| `RetryBaseDelayMs` | int | `100` | Base delay between retries |
| `RetryMaxDelayMs` | int | `2000` | Maximum retry delay |
| `RetryUseJitter` | bool | `true` | Randomize retry delay |

### Circuit Breaker

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `FailureWindowSeconds` | int | `60` | Sliding window for failure tracking |
| `FailurePercentageThreshold` | double | `50` | Failure rate to trip the breaker (%) |
| `MinimumRequestsInWindow` | int | `10` | Minimum requests before tripping |
| `OfflineSeconds` | int | `60` | How long a tripped target stays offline |

### Other

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `UseStatus499ForClientAbort` | bool | `true` | Return 499 when client disconnects |
| `EnableVerboseLog` | bool | `false` | Log each proxy attempt and result |

## Status Endpoint

When proxy routes are configured, a status endpoint is registered:

```
GET /proxy/status
```

Returns JSON with the health and traffic stats for each proxy route and target.
