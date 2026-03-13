using System.Collections.Generic;
using System.Globalization;

namespace BareMetalWeb.Rendering;

public static class FormOptions
{
    private static readonly Lazy<IReadOnlyList<string>> CurrencyCodes = new(() =>
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var culture in CultureInfo.GetCultures(CultureTypes.SpecificCultures))
        {
            try
            {
                var region = new RegionInfo(culture.Name);
                if (!string.IsNullOrWhiteSpace(region.ISOCurrencySymbol))
                    set.Add(region.ISOCurrencySymbol);
            }
            catch
            {
                // Ignore invalid cultures
            }
        }
        var list = new List<string>(set);
        list.Sort(StringComparer.Ordinal);
        return list;
    });

    private static readonly Lazy<IReadOnlyList<KeyValuePair<string, string>>> CountryCodes = new(() =>
    {
        var set = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var culture in CultureInfo.GetCultures(CultureTypes.SpecificCultures))
        {
            try
            {
                var region = new RegionInfo(culture.Name);
                if (!set.ContainsKey(region.TwoLetterISORegionName))
                    set.Add(region.TwoLetterISORegionName, region.EnglishName);
            }
            catch
            {
                // Ignore invalid cultures
            }
        }
        var list = new List<KeyValuePair<string, string>>(set);
        list.Sort((a, b) => string.Compare(a.Value, b.Value, StringComparison.Ordinal));
        return list;
    });

    public static IReadOnlyList<string> GetCurrencyOptions() => CurrencyCodes.Value;

    public static IReadOnlyList<KeyValuePair<string, string>> GetCountryOptions() => CountryCodes.Value;
}
