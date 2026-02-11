using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

public static class DataStoreProvider
{
    public static IDataObjectStore Current { get; set; } = new DataObjectStore();
    public static IDataProvider? PrimaryProvider { get; set; }
}
