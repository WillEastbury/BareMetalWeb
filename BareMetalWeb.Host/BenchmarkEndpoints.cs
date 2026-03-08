using System.Runtime.CompilerServices;
using BareMetalWeb.Core;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Ultra-minimal benchmark endpoints for performance diagnostics.
/// <list type="bullet">
///   <item><c>/_null</c>  — raw Kestrel ceiling: bypasses entire BMW pipeline.</item>
///   <item><c>/_router</c> — Kestrel + EntityPrefixRouter resolution only.</item>
/// </list>
/// Enabled by <c>BMW_ENABLE_BENCH_ENDPOINTS=1</c> environment variable.
/// </summary>
internal static class BenchmarkEndpoints
{
    /// <summary>
    /// Static readonly so the JIT can fold the branch and eliminate dead code
    /// when the env var is not set (production default).
    /// </summary>
    internal static readonly bool Enabled =
        string.Equals(
            Environment.GetEnvironmentVariable("BMW_ENABLE_BENCH_ENDPOINTS"),
            "1",
            StringComparison.Ordinal);

    private static readonly byte[] OkBody = "OK"u8.ToArray();

    private static EntityPrefixRouter? _benchRouter;
    private static readonly object _routerLock = new();

    /// <summary>
    /// Fast-path check. Call at the very top of RequestHandler — before
    /// BmwContext creation, stopwatch, rate limiter, CORS, or any middleware.
    /// Returns true (and writes the response) if the path matched a bench endpoint.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static bool TryHandle(BmwContext context)
    {
        var path = context.Request.Path;

        // Length gate: /_null = 6, /_router = 8.  Anything shorter or null → skip.
        if (path.Length < 6)
            return false;

        if (path.Length == 6 && path[1] == 'n')
        {
            if (string.Equals(path, "/_null", StringComparison.Ordinal))
            {
                WriteOk(context);
                return true;
            }
        }
        else if (path.Length == 8 && path[1] == 'r')
        {
            if (string.Equals(path, "/_router", StringComparison.Ordinal))
            {
                HandleRouter(context);
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// /_null — absolute minimum: write two pre-computed bytes, nothing else.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteOk(BmwContext context)
    {
        context.StatusCode = 200;
        context.ContentType = "text/plain";
        context.ContentLength = 2;
        var span = context.ResponseBody.GetSpan(2);
        OkBody.CopyTo(span);
        context.ResponseBody.Advance(2);
    }

    /// <summary>
    /// /_router — exercise EntityPrefixRouter.TryResolve on a real entity slug,
    /// then write the same two-byte response. No WAL, no rendering, no auth.
    /// </summary>
    private static void HandleRouter(BmwContext context)
    {
        var router = EnsureRouter();
        router.TryResolve("customer"u8, out _, out _);
        WriteOk(context);
    }

    /// <summary>
    /// Lazily build an EntityPrefixRouter from DataScaffold entities.
    /// Double-checked lock: first request pays the build cost, subsequent
    /// requests get a volatile read of the already-built instance.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static EntityPrefixRouter EnsureRouter()
    {
        var r = Volatile.Read(ref _benchRouter);
        if (r is not null) return r;

        lock (_routerLock)
        {
            r = Volatile.Read(ref _benchRouter);
            if (r is not null) return r;

            var router = new EntityPrefixRouter();
            var entities = DataScaffold.Entities;

            if (entities is { Count: > 0 })
            {
                var slugs = new List<string>(entities.Count);
                for (int i = 0; i < entities.Count; i++)
                {
                    var slug = entities[i].Slug;
                    if (!string.IsNullOrEmpty(slug))
                        slugs.Add(slug);
                }

                if (slugs.Count > 0)
                {
                    router.Build(slugs);
                    Volatile.Write(ref _benchRouter, router);
                    return router;
                }
            }

            // Fallback when no entities are scaffolded yet
            router.Build(new[] { "customer", "order", "invoice", "product" });
            Volatile.Write(ref _benchRouter, router);
            return router;
        }
    }
}
