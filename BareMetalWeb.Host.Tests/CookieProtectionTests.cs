using System;
using System.IO;
using Xunit;

namespace BareMetalWeb.Host.Tests;

[Collection("CookieProtection")]
public class CookieProtectionTests : IDisposable
{
    private readonly string _tempDirectory;

    public CookieProtectionTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(_tempDirectory);
        CookieProtection.ConfigureKeyRoot(_tempDirectory);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDirectory))
            Directory.Delete(_tempDirectory, true);
    }

    [Fact]
    public void Protect_ValidValue_ReturnsProtectedString()
    {
        // Arrange
        var value = "test-session-id-12345";

        // Act
        var protected1 = CookieProtection.Protect(value);

        // Assert
        Assert.NotNull(protected1);
        Assert.NotEmpty(protected1);
        Assert.Contains(".", protected1); // Should contain separator
    }

    [Fact]
    public void Protect_NullValue_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => CookieProtection.Protect(null!));
    }

    [Fact]
    public void Unprotect_ValidProtectedValue_ReturnsOriginalValue()
    {
        // Arrange
        var original = "test-session-id-12345";
        var protected1 = CookieProtection.Protect(original);

        // Act
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(original, unprotected);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void Unprotect_NullOrEmptyValue_ReturnsNull(string value)
    {
        // Act
        var result = CookieProtection.Unprotect(value);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Unprotect_InvalidFormat_ReturnsNull()
    {
        // Arrange - No separator
        var invalidValue = "invalidformatwithoutseparator";

        // Act
        var result = CookieProtection.Unprotect(invalidValue);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Unprotect_InvalidBase64_ReturnsNull()
    {
        // Arrange - Invalid base64 characters
        var invalidValue = "invalid!!!.base64!!!";

        // Act
        var result = CookieProtection.Unprotect(invalidValue);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Unprotect_TamperedData_ReturnsNull()
    {
        // Arrange
        var original = "test-session-id";
        var protected1 = CookieProtection.Protect(original);
        
        // Tamper with the protected value by changing one character
        var parts = protected1.Split('.');
        var tampered = parts[0].Substring(0, parts[0].Length - 1) + "X." + parts[1];

        // Act
        var result = CookieProtection.Unprotect(tampered);

        // Assert
        Assert.Null(result); // Should fail HMAC verification
    }

    [Fact]
    public void Unprotect_TamperedMac_ReturnsNull()
    {
        // Arrange
        var original = "test-session-id";
        var protected1 = CookieProtection.Protect(original);
        
        // Tamper with the MAC by completely replacing it with a different base64 string
        var parts = protected1.Split('.');
        // Use a completely different MAC value (all zeros, same length as SHA256 = 32 bytes)
        var fakeMac = Convert.ToBase64String(new byte[32]).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var tampered = parts[0] + "." + fakeMac;

        // Act
        var result = CookieProtection.Unprotect(tampered);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Protect_SameValue_GeneratesDifferentProtectedValues()
    {
        // Arrange
        var value = "test-session-id";

        // Act
        var protected1 = CookieProtection.Protect(value);
        var protected2 = CookieProtection.Protect(value);

        // Assert
        Assert.NotEqual(protected1, protected2); // Due to random nonce in encryption
    }

    [Fact]
    public void Protect_DifferentValues_GeneratesDifferentProtectedValues()
    {
        // Act
        var protected1 = CookieProtection.Protect("value1");
        var protected2 = CookieProtection.Protect("value2");

        // Assert
        Assert.NotEqual(protected1, protected2);
    }

    [Fact]
    public void Unprotect_MultipleProtectedValues_AllValid()
    {
        // Arrange
        var value1 = "session-1";
        var value2 = "session-2";
        var protected1 = CookieProtection.Protect(value1);
        var protected2 = CookieProtection.Protect(value2);

        // Act
        var unprotected1 = CookieProtection.Unprotect(protected1);
        var unprotected2 = CookieProtection.Unprotect(protected2);

        // Assert
        Assert.Equal(value1, unprotected1);
        Assert.Equal(value2, unprotected2);
    }

    [Fact]
    public void Protect_EmptyString_WorksCorrectly()
    {
        // Arrange
        var value = "";

        // Act
        var protected1 = CookieProtection.Protect(value);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(value, unprotected);
    }

    [Fact]
    public void Protect_LongValue_WorksCorrectly()
    {
        // Arrange
        var value = new string('a', 1000);

        // Act
        var protected1 = CookieProtection.Protect(value);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(value, unprotected);
    }

    [Fact]
    public void Protect_SpecialCharacters_WorksCorrectly()
    {
        // Arrange
        var value = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`";

        // Act
        var protected1 = CookieProtection.Protect(value);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(value, unprotected);
    }

    [Fact]
    public void Protect_UnicodeCharacters_WorksCorrectly()
    {
        // Arrange
        var value = "Hello 世界 🔐";

        // Act
        var protected1 = CookieProtection.Protect(value);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(value, unprotected);
    }

    [Fact]
    public void Protect_Guid_WorksCorrectly()
    {
        // Arrange
        var value = Guid.NewGuid().ToString();

        // Act
        var protected1 = CookieProtection.Protect(value);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(value, unprotected);
    }

    [Fact]
    public void ConfigureKeyRoot_ValidFolder_Works()
    {
        // Arrange
        var newFolder = Path.Combine(_tempDirectory, "cookiekeys");
        Directory.CreateDirectory(newFolder);

        // Act
        CookieProtection.ConfigureKeyRoot(newFolder);
        
        // Just verify it doesn't throw - the static nature makes it hard to verify more
        // Assert
        Assert.True(Directory.Exists(newFolder));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void ConfigureKeyRoot_InvalidFolder_ThrowsArgumentException(string folder)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => CookieProtection.ConfigureKeyRoot(folder));
        Assert.Equal("rootFolder", exception.ParamName);
    }

    [Fact]
    public void Protect_WorksAfterInitialization()
    {
        // Arrange - Just ensure it works after keys are set up
        var value = "test";

        // Act
        var protected1 = CookieProtection.Protect(value);

        // Assert - Key files exist somewhere (could be _tempDirectory or AppContext.BaseDirectory)
        Assert.NotNull(protected1);
    }

    [Fact]
    public void Protect_OnlyDotInValue_WorksCorrectly()
    {
        // Arrange - Test edge case where value contains only dots
        var value = "...";

        // Act
        var protected1 = CookieProtection.Protect(value);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(value, unprotected);
    }

    [Fact]
    public void Unprotect_ValueWithMultipleDots_HandlesCorrectly()
    {
        // Arrange - Create a valid protected value first
        var original = "test-value";
        var protected1 = CookieProtection.Protect(original);
        
        // Add extra dots to create invalid format
        var invalidValue = protected1 + ".extra.parts";

        // Act
        var result = CookieProtection.Unprotect(invalidValue);

        // Assert — malformed token (extra dot-separated parts) must be rejected
        Assert.Null(result);
    }

    [Fact]
    public void Protect_Whitespace_WorksCorrectly()
    {
        // Arrange
        var value = "  leading and trailing  ";

        // Act
        var protected1 = CookieProtection.Protect(value);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(value, unprotected);
    }

    [Fact]
    public void Protect_NewlineCharacters_WorksCorrectly()
    {
        // Arrange
        var value = "Line1\nLine2\rLine3\r\nLine4";

        // Act
        var protected1 = CookieProtection.Protect(value);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(value, unprotected);
    }
}
