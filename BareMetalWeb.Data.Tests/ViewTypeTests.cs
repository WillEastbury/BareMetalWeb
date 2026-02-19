using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class ViewTypeTests
{
    [Fact]
    public void ViewType_HasTimelineOption()
    {
        // Arrange & Act
        var timelineValue = ViewType.Timeline;
        
        // Assert
        Assert.Equal(3, (int)timelineValue);
    }
    
    [Fact]
    public void ViewType_AllValuesAreUnique()
    {
        // Arrange
        var values = new[]
        {
            (int)ViewType.Table,
            (int)ViewType.TreeView,
            (int)ViewType.OrgChart,
            (int)ViewType.Timeline
        };
        
        // Act
        var uniqueValues = new HashSet<int>(values);
        
        // Assert
        Assert.Equal(values.Length, uniqueValues.Count);
    }
}
