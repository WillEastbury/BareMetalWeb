using System.Text;
using Xunit;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for SynchronousEncryption - critical security component for data encryption.
/// </summary>
public class SynchronousEncryptionTests : IDisposable
{
    private readonly string _testKeyFolder;

    public SynchronousEncryptionTests()
    {
        // Create a temporary folder for test keys
        _testKeyFolder = Path.Combine(Path.GetTempPath(), $"EncryptionTests_{Guid.NewGuid()}");
        Directory.CreateDirectory(_testKeyFolder);
    }

    public void Dispose()
    {
        // Clean up test keys
        if (Directory.Exists(_testKeyFolder))
        {
            Directory.Delete(_testKeyFolder, true);
        }
    }

    [Fact]
    public void CreateDefault_ValidRootFolder_CreatesEncryption()
    {
        // Act
        var encryption = SynchronousEncryption.CreateDefault(_testKeyFolder);

        // Assert
        Assert.NotNull(encryption);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void CreateDefault_NullOrEmptyRootFolder_ThrowsArgumentException(string? rootFolder)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => SynchronousEncryption.CreateDefault(rootFolder!));
    }

    [Fact]
    public void CreateFromKeyFile_ValidPath_CreatesEncryption()
    {
        // Arrange
        var keyPath = Path.Combine(_testKeyFolder, "test.key");

        // Act
        var encryption = SynchronousEncryption.CreateFromKeyFile(keyPath);

        // Assert
        Assert.NotNull(encryption);
        Assert.True(File.Exists(keyPath));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void CreateFromKeyFile_NullOrEmptyPath_ThrowsArgumentException(string? keyPath)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => SynchronousEncryption.CreateFromKeyFile(keyPath!));
    }

    [Fact]
    public void EnsureKeyFile_NewFile_CreatesKeyFile()
    {
        // Arrange
        var keyPath = Path.Combine(_testKeyFolder, "new.key");

        // Act
        SynchronousEncryption.EnsureKeyFile(keyPath);

        // Assert
        Assert.True(File.Exists(keyPath));
        var content = File.ReadAllText(keyPath);
        Assert.NotEmpty(content);
    }

    [Fact]
    public void EnsureKeyFile_ExistingFile_DoesNotOverwrite()
    {
        // Arrange
        var keyPath = Path.Combine(_testKeyFolder, "existing.key");
        var originalContent = "original-key-content";
        File.WriteAllText(keyPath, originalContent);

        // Act
        SynchronousEncryption.EnsureKeyFile(keyPath);

        // Assert
        var content = File.ReadAllText(keyPath);
        Assert.Equal(originalContent, content);
    }

    [Fact]
    public void Encrypt_ValidPlaintext_ReturnsEncryptedData()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

        // Act
        var encrypted = encryption.Encrypt(plaintext);

        // Assert
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
        Assert.NotEqual(plaintext, encrypted);
        // Encrypted data should be longer (includes version, nonce, tag)
        Assert.True(encrypted.Length > plaintext.Length);
    }

    [Fact]
    public void Encrypt_NullPlaintext_ThrowsArgumentNullException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => encryption.Encrypt(null!));
    }

    [Fact]
    public void Encrypt_SamePlaintext_ProducesDifferentCiphertext()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

        // Act
        var encrypted1 = encryption.Encrypt(plaintext);
        var encrypted2 = encryption.Encrypt(plaintext);

        // Assert - Different nonces mean different ciphertext
        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public void Decrypt_ValidEncryptedData_ReturnsOriginalPlaintext()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var originalPlaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var encrypted = encryption.Encrypt(originalPlaintext);

        // Act
        var decrypted = encryption.Decrypt(encrypted);

        // Assert
        Assert.Equal(originalPlaintext, decrypted);
    }

    [Fact]
    public void Decrypt_NullPayload_ThrowsArgumentNullException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => encryption.Decrypt(null!));
    }

    [Fact]
    public void Decrypt_TooShortPayload_ThrowsArgumentException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var tooShort = new byte[10]; // Too short to contain version + nonce + tag

        // Act & Assert
        Assert.Throws<ArgumentException>(() => encryption.Decrypt(tooShort));
    }

    [Fact]
    public void Decrypt_InvalidVersion_ThrowsInvalidOperationException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var encrypted = encryption.Encrypt(plaintext);
        
        // Tamper with version byte
        encrypted[0] = 99;

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => encryption.Decrypt(encrypted));
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_ThrowsCryptographicException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var encrypted = encryption.Encrypt(plaintext);
        
        // Tamper with ciphertext (last byte)
        encrypted[^1] ^= 0xFF;

        // Act & Assert
        Assert.ThrowsAny<Exception>(() => encryption.Decrypt(encrypted));
    }

    [Fact]
    public void EncryptToBase64_ValidString_ReturnsBase64String()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var plaintext = "Hello, World!";

        // Act
        var encrypted = encryption.EncryptToBase64(plaintext);

        // Assert
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
        // Should be valid base64
        Assert.NotNull(Convert.FromBase64String(encrypted));
    }

    [Fact]
    public void EncryptToBase64_NullString_ThrowsArgumentNullException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => encryption.EncryptToBase64(null!));
    }

    [Fact]
    public void DecryptFromBase64_ValidEncryptedString_ReturnsOriginalString()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var originalText = "Hello, World!";
        var encrypted = encryption.EncryptToBase64(originalText);

        // Act
        var decrypted = encryption.DecryptFromBase64(encrypted);

        // Assert
        Assert.Equal(originalText, decrypted);
    }

    [Fact]
    public void DecryptFromBase64_NullString_ThrowsArgumentNullException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => encryption.DecryptFromBase64(null!));
    }

    [Fact]
    public void DecryptFromBase64_InvalidBase64_ThrowsFormatException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var invalidBase64 = "not-valid-base64!!!";

        // Act & Assert
        Assert.Throws<FormatException>(() => encryption.DecryptFromBase64(invalidBase64));
    }

    [Fact]
    public void Encrypt_WithAssociatedData_IncludesInAuthentication()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var plaintext = Encoding.UTF8.GetBytes("Secret Message");
        var associatedData = Encoding.UTF8.GetBytes("Context Info");

        // Act
        var encrypted = encryption.Encrypt(plaintext, associatedData);
        var decrypted = encryption.Decrypt(encrypted, associatedData);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Decrypt_WithWrongAssociatedData_Fails()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var plaintext = Encoding.UTF8.GetBytes("Secret Message");
        var correctAssociatedData = Encoding.UTF8.GetBytes("Context Info");
        var wrongAssociatedData = Encoding.UTF8.GetBytes("Wrong Context");
        var encrypted = encryption.Encrypt(plaintext, correctAssociatedData);

        // Act & Assert - Wrong associated data should fail authentication
        Assert.ThrowsAny<Exception>(() => encryption.Decrypt(encrypted, wrongAssociatedData));
    }

    [Fact]
    public void Decrypt_WithMissingAssociatedData_Fails()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var plaintext = Encoding.UTF8.GetBytes("Secret Message");
        var associatedData = Encoding.UTF8.GetBytes("Context Info");
        var encrypted = encryption.Encrypt(plaintext, associatedData);

        // Act & Assert - Missing associated data should fail authentication
        Assert.ThrowsAny<Exception>(() => encryption.Decrypt(encrypted, null));
    }

    [Fact]
    public void RoundTrip_EmptyData_WorksCorrectly()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var emptyData = Array.Empty<byte>();

        // Act
        var encrypted = encryption.Encrypt(emptyData);
        var decrypted = encryption.Decrypt(encrypted);

        // Assert
        Assert.Empty(decrypted);
    }

    [Fact]
    public void RoundTrip_LargeData_WorksCorrectly()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var largeData = new byte[10000];
        Random.Shared.NextBytes(largeData);

        // Act
        var encrypted = encryption.Encrypt(largeData);
        var decrypted = encryption.Decrypt(encrypted);

        // Assert
        Assert.Equal(largeData, decrypted);
    }

    [Fact]
    public void RoundTrip_UnicodeString_WorksCorrectly()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateFromKeyFile(Path.Combine(_testKeyFolder, "test.key"));
        var unicodeText = "Hello 世界! 🌍 Здравствуй мир!";

        // Act
        var encrypted = encryption.EncryptToBase64(unicodeText);
        var decrypted = encryption.DecryptFromBase64(encrypted);

        // Assert
        Assert.Equal(unicodeText, decrypted);
    }
}
