using System.Collections.Concurrent;
using System.Threading;

namespace BareMetalWeb.Data;

public static class IdSequenceProvider
{
    private static readonly ConcurrentDictionary<string, long> _counters = new(StringComparer.OrdinalIgnoreCase);

    public static string NextId(string entityName)
    {
        var next = _counters.AddOrUpdate(entityName, 1, (_, current) => current + 1);
        return next.ToString();
    }

    public static void SeedIfHigher(string entityName, long value)
    {
        _counters.AddOrUpdate(entityName, value, (_, current) => Math.Max(current, value));
    }
}
