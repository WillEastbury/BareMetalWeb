using System.Collections.Generic;
using BenchmarkDotNet.Attributes;

namespace BareMetalWeb.Benchmarks;

[MemoryDiagnoser]
[ShortRunJob]
public class RouteMatchingBenchmarks
{
    private static readonly Dictionary<string, string> _routes = new()
    {
        ["GET /"] = "home",
        ["GET /login"] = "login",
        ["GET /admin/data/Customer"] = "list",
        ["GET /api/Customer/abc-123"] = "get",
    };

    [Benchmark(Baseline = true)]
    public bool ExactMatch()
    {
        return BareMetalWeb.Host.RouteMatching.TryMatch("/admin/data/Customer", "/admin/data/Customer", out _);
    }

    [Benchmark]
    public bool ParameterMatch()
    {
        return BareMetalWeb.Host.RouteMatching.TryMatch("/admin/data/Customer/abc-123", "/admin/data/{type}/{id}", out _);
    }

    [Benchmark]
    public bool CatchAllMatch()
    {
        return BareMetalWeb.Host.RouteMatching.TryMatch("/static/css/themes/dark/main.css", "/static/{*rest}", out _);
    }

    [Benchmark]
    public bool RegexMatch()
    {
        return BareMetalWeb.Host.RouteMatching.TryMatch("/api/v2/data", "regex:^/api/v\\d+/data$", out _);
    }

    [Benchmark]
    public bool NoMatch()
    {
        return BareMetalWeb.Host.RouteMatching.TryMatch("/nonexistent/path", "/admin/data/{type}", out _);
    }
}
