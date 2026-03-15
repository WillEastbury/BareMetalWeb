using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class BitNetEngineTests
{
    [Fact]
    public void IsLoaded_BeforeLoad_ReturnsFalse()
    {
        using var engine = new BitNetEngine();

        Assert.False(engine.IsLoaded);
    }

    [Fact]
    public async Task GenerateAsync_NotLoaded_ReturnsNotLoadedMessage()
    {
        using var engine = new BitNetEngine();

        var result = await engine.GenerateAsync("test prompt".AsMemory());

        Assert.Contains("not loaded", result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetMetrics_NotLoaded_ReturnsNull()
    {
        using var engine = new BitNetEngine();

        Assert.Null(engine.GetMetrics());
    }
}
