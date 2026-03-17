using System;
using System.IO;
using System.Text;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class MfaSecretProtectorTests : IDisposable
{
    private readonly string _tempDirectory;
    private readonly MfaSecretProtector _protector;

    public MfaSecretProtectorTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(_tempDirectory);
        _protector = MfaSecretProtector.CreateDefault(_tempDirectory);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDirectory))
            Directory.Delete(_tempDirectory, true);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip_ReturnsOriginalSecret()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var userId = "user-123";

        // Act
        var encrypted = _protector.EncryptSecret(secret, userId);
        var success = _protector.TryDecryptSecret(encrypted, userId, out var decryptedBytes);

        // Assert
        Assert.True(success);
        Assert.Equal(secret, Encoding.UTF8.GetString(decryptedBytes));
    }

    [Fact]
    public void EncryptDecrypt_UnicodeSecret_RoundTripsCorrectly()
    {
        // Arrange
        var secret = "秘密Key🔑テスト";
        var userId = "user-unicode";

        // Act
        var encrypted = _protector.EncryptSecret(secret, userId);
        var success = _protector.TryDecryptSecret(encrypted, userId, out var decryptedBytes);

        // Assert
        Assert.True(success);
        Assert.Equal(secret, Encoding.UTF8.GetString(decryptedBytes));
    }

    [Fact]
    public void Encrypt_SameSecretTwice_ProducesDifferentCiphertext()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var userId = "user-123";

        // Act
        var encrypted1 = _protector.EncryptSecret(secret, userId);
        var encrypted2 = _protector.EncryptSecret(secret, userId);

        // Assert
        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public void Encrypt_ReturnsValidBase64()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var userId = "user-123";

        // Act
        var encrypted = _protector.EncryptSecret(secret, userId);

        // Assert
        Assert.NotNull(encrypted);
        Assert.NotEmpty(encrypted);
        var bytes = Convert.FromBase64String(encrypted);
        Assert.True(bytes.Length > 0);
    }

    [Fact]
    public void TryDecrypt_WrongUserId_ReturnsFalse()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var encrypted = _protector.EncryptSecret(secret, "user-123");

        // Act
        var success = _protector.TryDecryptSecret(encrypted, "wrong-user", out var decryptedBytes);

        // Assert
        Assert.False(success);
        Assert.Empty(decryptedBytes);
    }

    [Fact]
    public void TryDecrypt_DifferentKeyMaterial_ReturnsFalse()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var userId = "user-123";
        var encrypted = _protector.EncryptSecret(secret, userId);

        var tempDir2 = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        try
        {
            Directory.CreateDirectory(tempDir2);
            var otherProtector = MfaSecretProtector.CreateDefault(tempDir2);

            // Act
            var success = otherProtector.TryDecryptSecret(encrypted, userId, out var decryptedBytes);

            // Assert
            Assert.False(success);
            Assert.Empty(decryptedBytes);
        }
        finally
        {
            if (Directory.Exists(tempDir2))
                Directory.Delete(tempDir2, true);
        }
    }

    [Fact]
    public void TryDecrypt_TamperedCiphertext_ReturnsFalse()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var userId = "user-123";
        var encrypted = _protector.EncryptSecret(secret, userId);
        var payload = Convert.FromBase64String(encrypted);
        payload[^1] ^= 0xFF; // Flip bits in last byte
        var tampered = Convert.ToBase64String(payload);

        // Act
        var success = _protector.TryDecryptSecret(tampered, userId, out var decryptedBytes);

        // Assert
        Assert.False(success);
        Assert.Empty(decryptedBytes);
    }

    [Fact]
    public void TryDecrypt_TamperedTag_ReturnsFalse()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var userId = "user-123";
        var encrypted = _protector.EncryptSecret(secret, userId);
        var payload = Convert.FromBase64String(encrypted);
        // Tag starts at offset 1 + 16 (salt) + 12 (nonce) = 29
        payload[29] ^= 0xFF;
        var tampered = Convert.ToBase64String(payload);

        // Act
        var success = _protector.TryDecryptSecret(tampered, userId, out var decryptedBytes);

        // Assert
        Assert.False(success);
        Assert.Empty(decryptedBytes);
    }

    [Fact]
    public void TryDecrypt_InvalidBase64_ReturnsFalse()
    {
        // Act
        var success = _protector.TryDecryptSecret("not-valid-base64!!!", "user-123", out var decryptedBytes);

        // Assert
        Assert.False(success);
        Assert.Empty(decryptedBytes);
    }

    [Fact]
    public void TryDecrypt_TruncatedPayload_ReturnsFalse()
    {
        // Arrange
        var shortPayload = Convert.ToBase64String(new byte[10]);

        // Act
        var success = _protector.TryDecryptSecret(shortPayload, "user-123", out var decryptedBytes);

        // Assert
        Assert.False(success);
        Assert.Empty(decryptedBytes);
    }

    [Fact]
    public void TryDecrypt_WrongVersion_ReturnsFalse()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var userId = "user-123";
        var encrypted = _protector.EncryptSecret(secret, userId);
        var payload = Convert.FromBase64String(encrypted);
        payload[0] = 99; // Invalid version byte
        var tampered = Convert.ToBase64String(payload);

        // Act
        var success = _protector.TryDecryptSecret(tampered, userId, out var decryptedBytes);

        // Assert
        Assert.False(success);
        Assert.Empty(decryptedBytes);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void TryDecrypt_NullOrEmptyPayload_ReturnsFalse(string? payload)
    {
        // Act
        var success = _protector.TryDecryptSecret(payload!, "user-123", out var decryptedBytes);

        // Assert
        Assert.False(success);
        Assert.Empty(decryptedBytes);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void TryDecrypt_NullOrEmptyUserId_ReturnsFalse(string? userId)
    {
        // Arrange
        var encrypted = _protector.EncryptSecret("JBSWY3DPEHPK3PXP", "user-123");

        // Act
        var success = _protector.TryDecryptSecret(encrypted, userId!, out var decryptedBytes);

        // Assert
        Assert.False(success);
        Assert.Empty(decryptedBytes);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Encrypt_NullOrEmptySecret_ThrowsArgumentException(string? secret)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _protector.EncryptSecret(secret!, "user-123"));
        Assert.Equal("secret", exception.ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void Encrypt_NullOrEmptyUserId_ThrowsArgumentException(string? userId)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => _protector.EncryptSecret("JBSWY3DPEHPK3PXP", userId!));
        Assert.Equal("userId", exception.ParamName);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void CreateDefault_InvalidRootFolder_ThrowsArgumentException(string? rootFolder)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => MfaSecretProtector.CreateDefault(rootFolder!));
        Assert.Equal("rootFolder", exception.ParamName);
    }

    [Fact]
    public void TwoInstances_SameKeyFile_CanDecryptEachOthersData()
    {
        // Arrange
        var protector2 = MfaSecretProtector.CreateDefault(_tempDirectory);
        var secret = "JBSWY3DPEHPK3PXP";
        var userId = "user-123";
        var encrypted = _protector.EncryptSecret(secret, userId);

        // Act
        var success = protector2.TryDecryptSecret(encrypted, userId, out var decryptedBytes);

        // Assert
        Assert.True(success);
        Assert.Equal(secret, Encoding.UTF8.GetString(decryptedBytes));
    }

    [Fact]
    public void KeyRotation_ReEncryptWithNewKey_DecryptsWithNewKeyOnly()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var userId = "user-123";
        var encrypted = _protector.EncryptSecret(secret, userId);

        // Simulate key rotation: create a new protector with a different key
        var rotatedDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        try
        {
            Directory.CreateDirectory(rotatedDir);
            var rotatedProtector = MfaSecretProtector.CreateDefault(rotatedDir);

            // Decrypt with old key and re-encrypt with new key
            var decryptOld = _protector.TryDecryptSecret(encrypted, userId, out var plainBytes);
            Assert.True(decryptOld);
            var reEncrypted = rotatedProtector.EncryptSecret(Encoding.UTF8.GetString(plainBytes), userId);

            // Act
            var successNew = rotatedProtector.TryDecryptSecret(reEncrypted, userId, out var decryptedNew);
            var successOld = _protector.TryDecryptSecret(reEncrypted, userId, out _);

            // Assert
            Assert.True(successNew);
            Assert.Equal(secret, Encoding.UTF8.GetString(decryptedNew));
            Assert.False(successOld);
        }
        finally
        {
            if (Directory.Exists(rotatedDir))
                Directory.Delete(rotatedDir, true);
        }
    }

    [Fact]
    public void TryDecrypt_TamperedNonce_ReturnsFalse()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var userId = "user-123";
        var encrypted = _protector.EncryptSecret(secret, userId);
        var payload = Convert.FromBase64String(encrypted);
        // Nonce starts at offset 1 + 16 (salt) = 17
        payload[17] ^= 0xFF;
        var tampered = Convert.ToBase64String(payload);

        // Act
        var success = _protector.TryDecryptSecret(tampered, userId, out var decryptedBytes);

        // Assert
        Assert.False(success);
        Assert.Empty(decryptedBytes);
    }

    [Fact]
    public void TryDecrypt_TamperedSalt_ReturnsFalse()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var userId = "user-123";
        var encrypted = _protector.EncryptSecret(secret, userId);
        var payload = Convert.FromBase64String(encrypted);
        // Salt starts at offset 1
        payload[1] ^= 0xFF;
        var tampered = Convert.ToBase64String(payload);

        // Act
        var success = _protector.TryDecryptSecret(tampered, userId, out var decryptedBytes);

        // Assert
        Assert.False(success);
        Assert.Empty(decryptedBytes);
    }

    [Fact]
    public void Encrypt_PayloadContainsVersionByte()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var userId = "user-123";

        // Act
        var encrypted = _protector.EncryptSecret(secret, userId);
        var payload = Convert.FromBase64String(encrypted);

        // Assert — version byte is 1, payload has expected minimum length
        Assert.Equal(1, payload[0]);
        var expectedMinLength = 1 + 16 + 12 + 16; // version + salt + nonce + tag
        Assert.True(payload.Length > expectedMinLength);
    }

    [Fact]
    public void EncryptDecrypt_SingleCharSecret_RoundTripsCorrectly()
    {
        // Arrange
        var secret = "A";
        var userId = "user-123";

        // Act
        var encrypted = _protector.EncryptSecret(secret, userId);
        var success = _protector.TryDecryptSecret(encrypted, userId, out var decryptedBytes);

        // Assert
        Assert.True(success);
        Assert.Equal(secret, Encoding.UTF8.GetString(decryptedBytes));
    }

    [Fact]
    public void EncryptDecrypt_LongSecret_RoundTripsCorrectly()
    {
        // Arrange
        var secret = new string('X', 1024);
        var userId = "user-123";

        // Act
        var encrypted = _protector.EncryptSecret(secret, userId);
        var success = _protector.TryDecryptSecret(encrypted, userId, out var decryptedBytes);

        // Assert
        Assert.True(success);
        Assert.Equal(secret, Encoding.UTF8.GetString(decryptedBytes));
    }

    [Fact]
    public void Encrypt_DifferentUsers_SameSecret_ProducesDifferentCiphertext()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";

        // Act
        var encrypted1 = _protector.EncryptSecret(secret, "user-A");
        var encrypted2 = _protector.EncryptSecret(secret, "user-B");

        // Assert
        Assert.NotEqual(encrypted1, encrypted2);
    }

    [Fact]
    public void EncryptDecrypt_MultipleUsers_EachDecryptsOwnSecret()
    {
        // Arrange
        var secretA = "SECRET_FOR_A";
        var secretB = "SECRET_FOR_B";
        var encryptedA = _protector.EncryptSecret(secretA, "user-A");
        var encryptedB = _protector.EncryptSecret(secretB, "user-B");

        // Act
        var successA = _protector.TryDecryptSecret(encryptedA, "user-A", out var bytesA);
        var successB = _protector.TryDecryptSecret(encryptedB, "user-B", out var bytesB);
        var crossAB = _protector.TryDecryptSecret(encryptedA, "user-B", out _);
        var crossBA = _protector.TryDecryptSecret(encryptedB, "user-A", out _);

        // Assert
        Assert.True(successA);
        Assert.Equal(secretA, Encoding.UTF8.GetString(bytesA));
        Assert.True(successB);
        Assert.Equal(secretB, Encoding.UTF8.GetString(bytesB));
        Assert.False(crossAB);
        Assert.False(crossBA);
    }

    [Fact]
    public void CreateDefault_CreatesKeyFile_AndReusesIt()
    {
        // Arrange
        var keyPath = Path.Combine(_tempDirectory, ".keys", "mfa-master.key");

        // Assert — key file should exist after constructor
        Assert.True(File.Exists(keyPath));
        var keyBytes = File.ReadAllBytes(keyPath);
        Assert.Equal(64, keyBytes.Length);

        // Act — creating another instance should reuse the same key file
        var protector2 = MfaSecretProtector.CreateDefault(_tempDirectory);
        var keyBytes2 = File.ReadAllBytes(keyPath);

        // Assert
        Assert.Equal(keyBytes, keyBytes2);
    }

    [Fact]
    public void TryDecrypt_MinimumValidLengthPayload_ReturnsFalse()
    {
        // Arrange — payload with exactly header size (version + salt + nonce + tag) but no ciphertext
        var payload = new byte[1 + 16 + 12 + 16];
        payload[0] = 1; // valid version
        var base64 = Convert.ToBase64String(payload);

        // Act — this is structurally valid but decryption should fail (zeroed key material)
        var success = _protector.TryDecryptSecret(base64, "user-123", out var decryptedBytes);

        // Assert
        Assert.False(success);
    }

    [Fact]
    public void TryDecrypt_EmptyString_ReturnsFalse()
    {
        // Act
        var success = _protector.TryDecryptSecret(string.Empty, "user-123", out var decryptedBytes);

        // Assert
        Assert.False(success);
        Assert.Empty(decryptedBytes);
    }
}
