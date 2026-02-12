using BareMetalWeb.Rendering;

namespace BareMetalWeb.Core.Tests;

public class TemplateLoopTests
{
    [Fact]
    public void Constructor_ValidParameters_CreatesInstance()
    {
        // Arrange
        var key = "testLoop";
        var items = new List<IReadOnlyDictionary<string, string>>
        {
            new Dictionary<string, string> { ["name"] = "Item1", ["value"] = "1" },
            new Dictionary<string, string> { ["name"] = "Item2", ["value"] = "2" }
        };

        // Act
        var loop = new TemplateLoop(key, items);

        // Assert
        Assert.Equal(key, loop.Key);
        Assert.Equal(2, loop.Items.Count);
        Assert.Equal("Item1", loop.Items[0]["name"]);
        Assert.Equal("2", loop.Items[1]["value"]);
    }

    [Fact]
    public void Constructor_EmptyItems_CreatesInstance()
    {
        // Arrange
        var key = "emptyLoop";
        var items = new List<IReadOnlyDictionary<string, string>>();

        // Act
        var loop = new TemplateLoop(key, items);

        // Assert
        Assert.Equal(key, loop.Key);
        Assert.Empty(loop.Items);
    }
}
