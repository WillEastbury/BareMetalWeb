using System;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class PasswordHasherTests
{
    [Fact]
    public void CreateHash_ValidPassword_ReturnsHashSaltAndIterations()
    {
        // Arrange
        var password = "SecurePassword123!";

        // Act
        var result = PasswordHasher.CreateHash(password);

        // Assert
        Assert.NotNull(result.Hash);
        Assert.NotNull(result.Salt);
        Assert.NotEmpty(result.Hash);
        Assert.NotEmpty(result.Salt);
        Assert.Equal(100_000, result.Iterations); // Default iterations
    }

    [Fact]
    public void CreateHash_CustomIterations_ReturnsCorrectIterations()
    {
        // Arrange
        var password = "SecurePassword123!";
        var iterations = 50_000;

        // Act
        var result = PasswordHasher.CreateHash(password, iterations);

        // Assert
        Assert.Equal(iterations, result.Iterations);
    }

    [Fact]
    public void CreateHash_SamePassword_GeneratesDifferentHashesAndSalts()
    {
        // Arrange
        var password = "SecurePassword123!";

        // Act
        var result1 = PasswordHasher.CreateHash(password);
        var result2 = PasswordHasher.CreateHash(password);

        // Assert
        Assert.NotEqual(result1.Hash, result2.Hash);
        Assert.NotEqual(result1.Salt, result2.Salt);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("   ")]
    public void CreateHash_EmptyOrWhitespacePassword_ThrowsArgumentException(string password)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => PasswordHasher.CreateHash(password));
        Assert.Equal("password", exception.ParamName);
    }

    [Fact]
    public void CreateHash_NullPassword_ThrowsArgumentException()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => PasswordHasher.CreateHash(null!));
        Assert.Equal("password", exception.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    public void CreateHash_InvalidIterations_ThrowsArgumentOutOfRangeException(int iterations)
    {
        // Arrange
        var password = "SecurePassword123!";

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => PasswordHasher.CreateHash(password, iterations));
        Assert.Equal("iterations", exception.ParamName);
    }

    [Fact]
    public void Verify_CorrectPassword_ReturnsTrue()
    {
        // Arrange
        var password = "SecurePassword123!";
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
        var password = "SecurePassword123!";
        var wrongPassword = "WrongPassword456!";
        var (hash, salt, iterations) = PasswordHasher.CreateHash(password);

        // Act
        var result = PasswordHasher.Verify(wrongPassword, hash, salt, iterations);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Verify_WrongSalt_ReturnsFalse()
    {
        // Arrange
        var password = "SecurePassword123!";
        var (hash, _, iterations) = PasswordHasher.CreateHash(password);
        var (_, wrongSalt, _) = PasswordHasher.CreateHash("OtherPassword");

        // Act
        var result = PasswordHasher.Verify(password, hash, wrongSalt, iterations);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Verify_WrongIterations_ReturnsFalse()
    {
        // Arrange
        var password = "SecurePassword123!";
        var (hash, salt, _) = PasswordHasher.CreateHash(password, 100_000);

        // Act
        var result = PasswordHasher.Verify(password, hash, salt, 50_000);

        // Assert
        Assert.False(result);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void Verify_InvalidPassword_ReturnsFalse(string? password)
    {
        // Arrange
        var (hash, salt, iterations) = PasswordHasher.CreateHash("ValidPassword");

        // Act
        var result = PasswordHasher.Verify(password!, hash, salt, iterations);

        // Assert
        Assert.False(result);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void Verify_InvalidHash_ReturnsFalse(string? invalidHash)
    {
        // Arrange
        var (_, salt, iterations) = PasswordHasher.CreateHash("ValidPassword");

        // Act
        var result = PasswordHasher.Verify("ValidPassword", invalidHash!, salt, iterations);

        // Assert
        Assert.False(result);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void Verify_InvalidSalt_ReturnsFalse(string invalidSalt)
    {
        // Arrange
        var (hash, _, iterations) = PasswordHasher.CreateHash("ValidPassword");

        // Act
        var result = PasswordHasher.Verify("ValidPassword", hash, invalidSalt, iterations);

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
        var (hash, salt, _) = PasswordHasher.CreateHash("ValidPassword");

        // Act
        var result = PasswordHasher.Verify("ValidPassword", hash, salt, iterations);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Verify_InvalidBase64Hash_ReturnsFalse()
    {
        // Arrange
        var (_, salt, iterations) = PasswordHasher.CreateHash("ValidPassword");
        var invalidHash = "not-valid-base64!!!";

        // Act
        var result = PasswordHasher.Verify("ValidPassword", invalidHash, salt, iterations);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Verify_InvalidBase64Salt_ReturnsFalse()
    {
        // Arrange
        var (hash, _, iterations) = PasswordHasher.CreateHash("ValidPassword");
        var invalidSalt = "not-valid-base64!!!";

        // Act
        var result = PasswordHasher.Verify("ValidPassword", hash, invalidSalt, iterations);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void CreateHash_LongPassword_WorksCorrectly()
    {
        // Arrange
        var password = new string('a', 1000); // Very long password

        // Act
        var result = PasswordHasher.CreateHash(password);

        // Assert
        Assert.NotNull(result.Hash);
        Assert.NotNull(result.Salt);
        Assert.True(PasswordHasher.Verify(password, result.Hash, result.Salt, result.Iterations));
    }

    [Fact]
    public void CreateHash_SpecialCharacters_WorksCorrectly()
    {
        // Arrange
        var password = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`";

        // Act
        var result = PasswordHasher.CreateHash(password);

        // Assert
        Assert.True(PasswordHasher.Verify(password, result.Hash, result.Salt, result.Iterations));
    }

    [Fact]
    public void CreateHash_UnicodeCharacters_WorksCorrectly()
    {
        // Arrange
        var password = "密码Test🔐パスワード";

        // Act
        var result = PasswordHasher.CreateHash(password);

        // Assert
        Assert.True(PasswordHasher.Verify(password, result.Hash, result.Salt, result.Iterations));
    }
}
