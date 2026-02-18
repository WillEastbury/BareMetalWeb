using System;
using System.Collections.Generic;
using System.Text;
using BareMetalWeb.Rendering;
using BenchmarkDotNet.Attributes;

namespace BareMetalWeb.Benchmarks;

[MemoryDiagnoser]
[ShortRunJob]
public class OutputCacheBenchmarks
{
    private OutputCache _cache = null!;
    private readonly byte[] _payload = Encoding.UTF8.GetBytes(new string('x', 4096));

    [GlobalSetup]
    public void Setup()
    {
        _cache = new OutputCache();
        _cache.Store("warm-key", _payload, TimeSpan.FromMinutes(5));
    }

    [Benchmark]
    public bool CacheHit()
    {
        return _cache.TryGet("warm-key", out _);
    }

    [Benchmark]
    public bool CacheMiss()
    {
        return _cache.TryGet("missing-key", out _);
    }

    [Benchmark]
    public void CacheStore()
    {
        _cache.Store("bench-key", _payload, TimeSpan.FromMinutes(5));
    }
}
