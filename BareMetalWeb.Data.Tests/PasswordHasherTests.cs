using Xunit;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for PasswordHasher - critical security component for password hashing.
/// </summary>
public class PasswordHasherTests
{
    [Fact]
    public void CreateHash_ValidPassword_ReturnsHashSaltIterations()
    {
        // Arrange
        var password = "MySecurePassword123!";

        // Act
        var (hash, salt, iterations) = PasswordHasher.CreateHash(password);

        // Assert
        Assert.NotNull(hash);
        Assert.NotEmpty(hash);
        Assert.NotNull(salt);
        Assert.NotEmpty(salt);
        Assert.Equal(100_000, iterations);
    }

    [Fact]
    public void CreateHash_CustomIterations_UsesProvidedIterations()
    {
        // Arrange
        var password = "MySecurePassword123!";
        var customIterations = 50_000;

        // Act
        var (hash, salt, iterations) = PasswordHasher.CreateHash(password, customIterations);

        // Assert
        Assert.Equal(customIterations, iterations);
    }

    [Fact]
    public void CreateHash_SamePassword_ProducesDifferentSalts()
    {
        // Arrange
        var password = "MySecurePassword123!";

        // Act
        var (hash1, salt1, _) = PasswordHasher.CreateHash(password);
        var (hash2, salt2, _) = PasswordHasher.CreateHash(password);

        // Assert - Different salts mean different hashes
        Assert.NotEqual(salt1, salt2);
        Assert.NotEqual(hash1, hash2);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void CreateHash_NullOrEmptyPassword_ThrowsArgumentException(string? password)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => PasswordHasher.CreateHash(password!));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    public void CreateHash_InvalidIterations_ThrowsArgumentOutOfRangeException(int iterations)
    {
        // Arrange
        var password = "MySecurePassword123!";

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => PasswordHasher.CreateHash(password, iterations));
    }

    [Fact]
    public void Verify_CorrectPassword_ReturnsTrue()
    {
        // Arrange
        var password = "MySecurePassword123!";
        var (hash, salt, iterations) = PasswordHasher.CreateHash(password);

        // Act
        var result = PasswordHasher.Verify(password, hash, salt, iterations);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Verify_IncorrectPassword_ReturnsFalse()
    {
        // Arrange
        var password = "MySecurePassword123!";
        var wrongPassword = "WrongPassword456!";
        var (hash, salt, iterations) = PasswordHasher.CreateHash(password);

        // Act
        var result = PasswordHasher.Verify(wrongPassword, hash, salt, iterations);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Verify_ModifiedHash_ReturnsFalse()
    {
        // Arrange
        var password = "MySecurePassword123!";
        var (hash, salt, iterations) = PasswordHasher.CreateHash(password);
        var tamperedHash = hash.Substring(0, hash.Length - 1) + "X"; // Modify last character

        // Act
        var result = PasswordHasher.Verify(password, tamperedHash, salt, iterations);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Verify_ModifiedSalt_ReturnsFalse()
    {
        // Arrange
        var password = "MySecurePassword123!";
        var (hash, salt, iterations) = PasswordHasher.CreateHash(password);
        var tamperedSalt = salt.Substring(0, salt.Length - 1) + "X"; // Modify last character

        // Act
        var result = PasswordHasher.Verify(password, hash, tamperedSalt, iterations);

        // Assert
        Assert.False(result);
    }

    [Theory]
    [InlineData(null, "validhash", "validsalt", 100000)]
    [InlineData("", "validhash", "validsalt", 100000)]
    [InlineData("   ", "validhash", "validsalt", 100000)]
    [InlineData("password", null, "validsalt", 100000)]
    [InlineData("password", "", "validsalt", 100000)]
    [InlineData("password", "   ", "validsalt", 100000)]
    [InlineData("password", "validhash", null, 100000)]
    [InlineData("password", "validhash", "", 100000)]
    [InlineData("password", "validhash", "   ", 100000)]
    public void Verify_NullOrEmptyInputs_ReturnsFalse(string? password, string? hash, string? salt, int iterations)
    {
        // Act
        var result = PasswordHasher.Verify(password!, hash!, salt!, iterations);

        // Assert
        Assert.False(result);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    public void Verify_InvalidIterations_ReturnsFalse(int iterations)
    {
        // Arrange
        var password = "MySecurePassword123!";
        var (hash, salt, _) = PasswordHasher.CreateHash(password);

        // Act
        var result = PasswordHasher.Verify(password, hash, salt, iterations);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Verify_InvalidBase64Hash_ReturnsFalse()
    {
        // Arrange
        var password = "MySecurePassword123!";
        var (_, salt, iterations) = PasswordHasher.CreateHash(password);
        var invalidHash = "not-valid-base64!!!";

        // Act
        var result = PasswordHasher.Verify(password, invalidHash, salt, iterations);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Verify_InvalidBase64Salt_ReturnsFalse()
    {
        // Arrange
        var password = "MySecurePassword123!";
        var (hash, _, iterations) = PasswordHasher.CreateHash(password);
        var invalidSalt = "not-valid-base64!!!";

        // Act
        var result = PasswordHasher.Verify(password, hash, invalidSalt, iterations);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Verify_WrongIterations_ReturnsFalse()
    {
        // Arrange
        var password = "MySecurePassword123!";
        var (hash, salt, iterations) = PasswordHasher.CreateHash(password);
        var wrongIterations = iterations + 1000;

        // Act
        var result = PasswordHasher.Verify(password, hash, salt, wrongIterations);

        // Assert
        Assert.False(result);
    }
}
