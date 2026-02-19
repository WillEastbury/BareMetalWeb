using System;
using System.IO;
using System.Text;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class SynchronousEncryptionTests : IDisposable
{
    private readonly string _tempDirectory;

    public SynchronousEncryptionTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(_tempDirectory);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDirectory))
            Directory.Delete(_tempDirectory, true);
    }

    [Fact]
    public void CreateDefault_ValidRootFolder_CreatesEncryptionInstance()
    {
        // Act
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);

        // Assert
        Assert.NotNull(encryption);
    }

    [Fact]
    public void CreateDefault_CreatesKeyFile()
    {
        // Act
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);

        // Assert
        var keyPath = Path.Combine(_tempDirectory, ".keys", "encryption.key");
        Assert.True(File.Exists(keyPath));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void CreateDefault_InvalidRootFolder_ThrowsArgumentException(string? rootFolder)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => SynchronousEncryption.CreateDefault(rootFolder!));
        Assert.Equal("rootFolder", exception.ParamName);
    }

    [Fact]
    public void CreateFromKeyFile_ValidKeyFile_CreatesEncryptionInstance()
    {
        // Arrange
        var keyPath = Path.Combine(_tempDirectory, "test.key");
        SynchronousEncryption.EnsureKeyFile(keyPath);

        // Act
        var encryption = SynchronousEncryption.CreateFromKeyFile(keyPath);

        // Assert
        Assert.NotNull(encryption);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void CreateFromKeyFile_InvalidPath_ThrowsArgumentException(string keyFilePath)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => SynchronousEncryption.CreateFromKeyFile(keyFilePath));
        Assert.Equal("keyFilePath", exception.ParamName);
    }

    [Fact]
    public void EnsureKeyFile_NonExistentFile_CreatesNewKeyFile()
    {
        // Arrange
        var keyPath = Path.Combine(_tempDirectory, "new.key");

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
        var keyPath = Path.Combine(_tempDirectory, "existing.key");
        SynchronousEncryption.EnsureKeyFile(keyPath);
        var originalContent = File.ReadAllText(keyPath);

        // Act
        SynchronousEncryption.EnsureKeyFile(keyPath);

        // Assert
        var newContent = File.ReadAllText(keyPath);
        Assert.Equal(originalContent, newContent);
    }

    [Fact]
    public void EnsureKeyFile_CreatesParentDirectory()
    {
        // Arrange
        var keyPath = Path.Combine(_tempDirectory, "subdir", "another", "test.key");

        // Act
        SynchronousEncryption.EnsureKeyFile(keyPath);

        // Assert
        Assert.True(File.Exists(keyPath));
    }

    [Fact]
    public void Encrypt_ValidPlaintext_ReturnsEncryptedBytes()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

        // Act
        var encrypted = encryption.Encrypt(plaintext);

        // Assert
        Assert.NotNull(encrypted);
        Assert.True(encrypted.Length > plaintext.Length); // Encrypted data includes nonce, tag, version
    }

    [Fact]
    public void Encrypt_NullPlaintext_ThrowsArgumentNullException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => encryption.Encrypt(null!));
    }

    [Fact]
    public void Decrypt_ValidEncryptedData_ReturnsOriginalPlaintext()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var encrypted = encryption.Encrypt(plaintext);

        // Act
        var decrypted = encryption.Decrypt(encrypted);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Decrypt_NullPayload_ThrowsArgumentNullException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => encryption.Decrypt(null!));
    }

    [Fact]
    public void Decrypt_TooShortPayload_ThrowsArgumentException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var shortPayload = new byte[5]; // Too short to contain version + nonce + tag

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => encryption.Decrypt(shortPayload));
        Assert.Equal("payload", exception.ParamName);
    }

    [Fact]
    public void Decrypt_InvalidVersion_ThrowsInvalidOperationException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");
        var encrypted = encryption.Encrypt(plaintext);
        encrypted[0] = 99; // Invalid version

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => encryption.Decrypt(encrypted));
    }

    [Fact]
    public void Encrypt_SamePlaintext_GeneratesDifferentCiphertext()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = Encoding.UTF8.GetBytes("Hello, World!");

        // Act
        var encrypted1 = encryption.Encrypt(plaintext);
        var encrypted2 = encryption.Encrypt(plaintext);

        // Assert
        Assert.NotEqual(encrypted1, encrypted2); // Due to random nonce
    }

    [Fact]
    public void EncryptDecrypt_WithAssociatedData_WorksCorrectly()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = Encoding.UTF8.GetBytes("Secret Message");
        var associatedData = Encoding.UTF8.GetBytes("Context Info");

        // Act
        var encrypted = encryption.Encrypt(plaintext, associatedData);
        var decrypted = encryption.Decrypt(encrypted, associatedData);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Decrypt_WithWrongAssociatedData_ThrowsException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = Encoding.UTF8.GetBytes("Secret Message");
        var correctAD = Encoding.UTF8.GetBytes("Context Info");
        var wrongAD = Encoding.UTF8.GetBytes("Wrong Context");
        var encrypted = encryption.Encrypt(plaintext, correctAD);

        // Act & Assert
        Assert.ThrowsAny<Exception>(() => encryption.Decrypt(encrypted, wrongAD));
    }

    [Fact]
    public void Decrypt_WithoutAssociatedDataWhenExpected_ThrowsException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = Encoding.UTF8.GetBytes("Secret Message");
        var associatedData = Encoding.UTF8.GetBytes("Context Info");
        var encrypted = encryption.Encrypt(plaintext, associatedData);

        // Act & Assert
        Assert.ThrowsAny<Exception>(() => encryption.Decrypt(encrypted, null));
    }

    [Fact]
    public void EncryptToBase64_ValidString_ReturnsBase64()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = "Hello, World!";

        // Act
        var encrypted = encryption.EncryptToBase64(plaintext);

        // Assert
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
        // Should be valid Base64
        Assert.NotNull(Convert.FromBase64String(encrypted));
    }

    [Fact]
    public void EncryptToBase64_NullString_ThrowsArgumentNullException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => encryption.EncryptToBase64(null!));
    }

    [Fact]
    public void DecryptFromBase64_ValidEncryptedString_ReturnsOriginal()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = "Hello, World!";
        var encrypted = encryption.EncryptToBase64(plaintext);

        // Act
        var decrypted = encryption.DecryptFromBase64(encrypted);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void DecryptFromBase64_NullString_ThrowsArgumentNullException()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => encryption.DecryptFromBase64(null!));
    }

    [Fact]
    public void EncryptToBase64_UnicodeString_WorksCorrectly()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = "Hello 世界 🌍 مرحبا";

        // Act
        var encrypted = encryption.EncryptToBase64(plaintext);
        var decrypted = encryption.DecryptFromBase64(encrypted);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptToBase64_EmptyString_WorksCorrectly()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = "";

        // Act
        var encrypted = encryption.EncryptToBase64(plaintext);
        var decrypted = encryption.DecryptFromBase64(encrypted);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_LargeData_WorksCorrectly()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = new byte[1024 * 1024]; // 1 MB
        Random.Shared.NextBytes(plaintext);

        // Act
        var encrypted = encryption.Encrypt(plaintext);
        var decrypted = encryption.Decrypt(encrypted);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_EmptyData_WorksCorrectly()
    {
        // Arrange
        var encryption = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = Array.Empty<byte>();

        // Act
        var encrypted = encryption.Encrypt(plaintext);
        var decrypted = encryption.Decrypt(encrypted);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void TwoInstances_SameKeyFile_CanDecryptEachOthersData()
    {
        // Arrange
        var encryption1 = SynchronousEncryption.CreateDefault(_tempDirectory);
        var encryption2 = SynchronousEncryption.CreateDefault(_tempDirectory);
        var plaintext = Encoding.UTF8.GetBytes("Shared Secret");

        // Act
        var encrypted = encryption1.Encrypt(plaintext);
        var decrypted = encryption2.Decrypt(encrypted);

        // Assert
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void TwoInstances_DifferentKeyFiles_CannotDecryptEachOthersData()
    {
        // Arrange
        var tempDir2 = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        try
        {
            Directory.CreateDirectory(tempDir2);
            var encryption1 = SynchronousEncryption.CreateDefault(_tempDirectory);
            var encryption2 = SynchronousEncryption.CreateDefault(tempDir2);
            var plaintext = Encoding.UTF8.GetBytes("Secret Message");
            var encrypted = encryption1.Encrypt(plaintext);

            // Act & Assert
            Assert.ThrowsAny<Exception>(() => encryption2.Decrypt(encrypted));
        }
        finally
        {
            if (Directory.Exists(tempDir2))
                Directory.Delete(tempDir2, true);
        }
    }
}
