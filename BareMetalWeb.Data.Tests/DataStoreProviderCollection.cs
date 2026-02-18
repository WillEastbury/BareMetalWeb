using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Test collection to ensure tests that modify DataStoreProvider.Current
/// don't run in parallel with each other.
/// </summary>
[CollectionDefinition("DataStoreProvider")]
public class DataStoreProviderCollection
{
    // This class is just a marker for the collection definition
    // xUnit will use this to group tests and run them sequentially
}
