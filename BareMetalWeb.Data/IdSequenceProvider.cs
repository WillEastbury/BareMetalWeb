using System.Collections.Concurrent;
using System.Threading;

namespace BareMetalWeb.Data;

public static class IdSequenceProvider
{
    private static readonly ConcurrentDictionary<string, uint> _counters = new(StringComparer.OrdinalIgnoreCase);

    public static uint NextKey(string entityName)
    {
        return _counters.AddOrUpdate(entityName, 1u, (_, current) => current + 1);
    }

    public static void SeedIfHigher(string entityName, uint value)
    {
        _counters.AddOrUpdate(entityName, value, (_, current) => Math.Max(current, value));
    }
}
