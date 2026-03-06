using Xunit;

namespace BareMetalWeb.Host.Tests;

[CollectionDefinition("SharedState", DisableParallelization = true)]
public class SharedStateCollection { }

[CollectionDefinition("StaticAssetCache", DisableParallelization = true)]
public class StaticAssetCacheCollection { }
