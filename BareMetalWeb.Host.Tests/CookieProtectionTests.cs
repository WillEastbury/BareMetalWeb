using Xunit;
using BareMetalWeb.Host;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Tests for CookieProtection - critical security component for cookie encryption/decryption.
/// Note: CookieProtection uses static initialization, so these tests share state.
/// Tests focus on the protect/unprotect functionality rather than key management.
/// </summary>
public class CookieProtectionTests
{
    [Fact]
    public void Protect_ValidValue_ReturnsProtectedString()
    {
        // Arrange
        var value = "session-id-12345";

        // Act
        var protected1 = CookieProtection.Protect(value);

        // Assert
        Assert.NotNull(protected1);
        Assert.NotEmpty(protected1);
        Assert.NotEqual(value, protected1);
        // Should contain a dot separator (encrypted.mac)
        Assert.Contains(".", protected1);
    }

    [Fact]
    public void Protect_NullValue_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => CookieProtection.Protect(null!));
    }

    [Fact]
    public void Protect_SameValue_ProducesDifferentOutputs()
    {
        // Arrange
        var value = "session-id-12345";

        // Act
        var protected1 = CookieProtection.Protect(value);
        var protected2 = CookieProtection.Protect(value);

        // Assert - Different nonces mean different outputs
        Assert.NotEqual(protected1, protected2);
    }

    [Fact]
    public void Unprotect_ValidProtectedValue_ReturnsOriginalValue()
    {
        // Arrange
        var originalValue = "session-id-12345";
        var protectedValue = CookieProtection.Protect(originalValue);

        // Act
        var unprotected = CookieProtection.Unprotect(protectedValue);

        // Assert
        Assert.Equal(originalValue, unprotected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Unprotect_NullOrEmptyValue_ReturnsNull(string? value)
    {
        // Act
        var result = CookieProtection.Unprotect(value!);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Unprotect_InvalidFormat_ReturnsNull()
    {
        // Arrange - Missing dot separator
        var invalidFormat = "nodotseparator";

        // Act
        var result = CookieProtection.Unprotect(invalidFormat);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Unprotect_InvalidBase64_ReturnsNull()
    {
        // Arrange - Invalid base64 characters
        var invalidBase64 = "invalid!!!.base64!!!";

        // Act
        var result = CookieProtection.Unprotect(invalidBase64);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Unprotect_TamperedEncryptedPart_ReturnsNull()
    {
        // Arrange
        var originalValue = "session-id-12345";
        var protectedValue = CookieProtection.Protect(originalValue);
        var parts = protectedValue.Split('.');
        
        // Tamper with encrypted part (change last character)
        var tamperedEncrypted = parts[0].Substring(0, parts[0].Length - 1) + "X";
        var tamperedValue = $"{tamperedEncrypted}.{parts[1]}";

        // Act
        var result = CookieProtection.Unprotect(tamperedValue);

        // Assert - HMAC verification should fail
        Assert.Null(result);
    }

    [Fact]
    public void Unprotect_TamperedMacPart_ReturnsNull()
    {
        // Arrange
        var originalValue = "session-id-12345";
        var protectedValue = CookieProtection.Protect(originalValue);
        var parts = protectedValue.Split('.');
        
        // Tamper with MAC part (change last character)
        var tamperedMac = parts[1].Substring(0, parts[1].Length - 1) + "X";
        var tamperedValue = $"{parts[0]}.{tamperedMac}";

        // Act
        var result = CookieProtection.Unprotect(tamperedValue);

        // Assert - HMAC verification should fail
        Assert.Null(result);
    }

    [Fact]
    public void Unprotect_WrongNumberOfParts_ReturnsNull()
    {
        // Arrange
        var tooManyParts = "part1.part2.part3";
        var onePart = "onlyonepart";

        // Act
        var result1 = CookieProtection.Unprotect(tooManyParts);
        var result2 = CookieProtection.Unprotect(onePart);

        // Assert
        Assert.Null(result1);
        Assert.Null(result2);
    }

    [Fact]
    public void RoundTrip_EmptyString_WorksCorrectly()
    {
        // Arrange
        var emptyValue = "";

        // Act
        var protected1 = CookieProtection.Protect(emptyValue);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(emptyValue, unprotected);
    }

    [Fact]
    public void RoundTrip_LongString_WorksCorrectly()
    {
        // Arrange
        var longValue = new string('x', 10000);

        // Act
        var protected1 = CookieProtection.Protect(longValue);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(longValue, unprotected);
    }

    [Fact]
    public void RoundTrip_SpecialCharacters_WorksCorrectly()
    {
        // Arrange
        var specialChars = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`";

        // Act
        var protected1 = CookieProtection.Protect(specialChars);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(specialChars, unprotected);
    }

    [Fact]
    public void RoundTrip_UnicodeCharacters_WorksCorrectly()
    {
        // Arrange
        var unicode = "Hello 世界! 🌍 Здравствуй мир!";

        // Act
        var protected1 = CookieProtection.Protect(unicode);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(unicode, unprotected);
    }

    [Fact]
    public void RoundTrip_WhitespaceString_WorksCorrectly()
    {
        // Arrange
        var whitespace = "   \t\n\r   ";

        // Act
        var protected1 = CookieProtection.Protect(whitespace);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(whitespace, unprotected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ConfigureKeyRoot_NullOrEmptyPath_ThrowsArgumentException(string? path)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => CookieProtection.ConfigureKeyRoot(path!));
    }

    [Fact]
    public void Protect_UsesUrlSafeBase64_NoStandardBase64Characters()
    {
        // Arrange
        var value = "session-id-12345";

        // Act
        var protected1 = CookieProtection.Protect(value);

        // Assert - Should not contain standard base64 characters that are URL-unsafe
        Assert.DoesNotContain("+", protected1.Split('.')[0]);
        Assert.DoesNotContain("/", protected1.Split('.')[0]);
        Assert.DoesNotContain("=", protected1.Split('.')[0]); // Padding removed
        Assert.DoesNotContain("+", protected1.Split('.')[1]);
        Assert.DoesNotContain("/", protected1.Split('.')[1]);
        Assert.DoesNotContain("=", protected1.Split('.')[1]); // Padding removed
    }

    [Fact]
    public void Unprotect_HandlesUrlSafeBase64_WithDashAndUnderscore()
    {
        // Arrange
        var value = "test-value-that-produces-url-safe-chars";

        // Act
        var protected1 = CookieProtection.Protect(value);
        var unprotected = CookieProtection.Unprotect(protected1);

        // Assert
        Assert.Equal(value, unprotected);
        // Protected value may contain URL-safe chars (- and _)
        Assert.True(protected1.Contains('-') || protected1.Contains('_') || 
                   (!protected1.Contains('+') && !protected1.Contains('/')));
    }
}
