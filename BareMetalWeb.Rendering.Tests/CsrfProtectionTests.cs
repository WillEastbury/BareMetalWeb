using BareMetalWeb.Rendering;

namespace BareMetalWeb.Rendering.Tests;

public class CsrfProtectionTests
{
    [Fact]
    public void GenerateToken_ReturnsNonEmptyString()
    {
        // Act
        var token1 = InvokeGenerateToken();
        var token2 = InvokeGenerateToken();

        // Assert
        Assert.NotNull(token1);
        Assert.NotEmpty(token1);
        Assert.NotNull(token2);
        Assert.NotEmpty(token2);
        Assert.NotEqual(token1, token2); // Tokens should be unique
    }

    [Fact]
    public void FixedTimeEquals_IdenticalStrings_ReturnsTrue()
    {
        // Arrange
        var str = "test_token_12345";

        // Act
        var result = InvokeFixedTimeEquals(str, str);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void FixedTimeEquals_DifferentStrings_ReturnsFalse()
    {
        // Arrange
        var str1 = "test_token_12345";
        var str2 = "test_token_67890";

        // Act
        var result = InvokeFixedTimeEquals(str1, str2);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void FixedTimeEquals_DifferentLengthStrings_ReturnsFalse()
    {
        // Arrange
        var str1 = "test_token_12345";
        var str2 = "test_token";

        // Act
        var result = InvokeFixedTimeEquals(str1, str2);

        // Assert
        Assert.False(result);
    }

    // Helper methods to invoke private methods via reflection
    private static string InvokeGenerateToken()
    {
        var method = typeof(CsrfProtection).GetMethod("GenerateToken",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        return (string)method!.Invoke(null, null)!;
    }

    private static bool InvokeFixedTimeEquals(string left, string right)
    {
        var method = typeof(CsrfProtection).GetMethod("FixedTimeEquals",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        return (bool)method!.Invoke(null, new object[] { left, right })!;
    }
}
