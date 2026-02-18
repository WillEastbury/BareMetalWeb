using System;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class MfaTotpTests
{
    [Fact]
    public void GenerateSecret_DefaultBytes_ReturnsBase32String()
    {
        // Act
        var secret = MfaTotp.GenerateSecret();

        // Assert
        Assert.NotNull(secret);
        Assert.NotEmpty(secret);
        // Base32 should only contain A-Z and 2-7
        Assert.All(secret, c => Assert.True((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')));
    }

    [Fact]
    public void GenerateSecret_CustomBytes_ReturnsCorrectLength()
    {
        // Arrange
        var numBytes = 10;

        // Act
        var secret = MfaTotp.GenerateSecret(numBytes);

        // Assert
        Assert.NotNull(secret);
        Assert.NotEmpty(secret);
        // Base32 encoding: 8 characters per 5 bytes
        Assert.True(secret.Length >= (numBytes * 8) / 5);
    }

    [Fact]
    public void GenerateSecret_MultipleCalls_GeneratesDifferentSecrets()
    {
        // Act
        var secret1 = MfaTotp.GenerateSecret();
        var secret2 = MfaTotp.GenerateSecret();

        // Assert
        Assert.NotEqual(secret1, secret2);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-10)]
    public void GenerateSecret_InvalidBytes_ThrowsArgumentOutOfRangeException(int numBytes)
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => MfaTotp.GenerateSecret(numBytes));
    }

    [Fact]
    public void GetOtpAuthUri_ValidInputs_ReturnsCorrectUri()
    {
        // Arrange
        var issuer = "TestApp";
        var accountName = "user@example.com";
        var secret = "JBSWY3DPEHPK3PXP";

        // Act
        var uri = MfaTotp.GetOtpAuthUri(issuer, accountName, secret);

        // Assert
        Assert.Contains("otpauth://totp/", uri);
        Assert.Contains("TestApp", uri);
        Assert.Contains("user", uri);
        Assert.Contains("secret=JBSWY3DPEHPK3PXP", uri);
        Assert.Contains("issuer=TestApp", uri);
    }

    [Fact]
    public void GetOtpAuthUri_SpecialCharactersInIssuer_EscapesCorrectly()
    {
        // Arrange
        var issuer = "Test App & Co.";
        var accountName = "user@example.com";
        var secret = "JBSWY3DPEHPK3PXP";

        // Act
        var uri = MfaTotp.GetOtpAuthUri(issuer, accountName, secret);

        // Assert
        Assert.Contains("Test%20App%20%26%20Co.", uri);
    }

    [Fact]
    public void GetOtpAuthUri_SpecialCharactersInAccountName_EscapesCorrectly()
    {
        // Arrange
        var issuer = "TestApp";
        var accountName = "user+tag@example.com";
        var secret = "JBSWY3DPEHPK3PXP";

        // Act
        var uri = MfaTotp.GetOtpAuthUri(issuer, accountName, secret);

        // Assert
        Assert.Contains("user%2Btag%40example.com", uri);
    }

    [Theory]
    [InlineData("", "user", "secret")]
    [InlineData(" ", "user", "secret")]
    [InlineData(null, "user", "secret")]
    public void GetOtpAuthUri_InvalidIssuer_ThrowsArgumentException(string issuer, string accountName, string secret)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => MfaTotp.GetOtpAuthUri(issuer, accountName, secret));
        Assert.Equal("issuer", exception.ParamName);
    }

    [Theory]
    [InlineData("issuer", "", "secret")]
    [InlineData("issuer", " ", "secret")]
    [InlineData("issuer", null, "secret")]
    public void GetOtpAuthUri_InvalidAccountName_ThrowsArgumentException(string issuer, string accountName, string secret)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => MfaTotp.GetOtpAuthUri(issuer, accountName, secret));
        Assert.Equal("accountName", exception.ParamName);
    }

    [Theory]
    [InlineData("issuer", "user", "")]
    [InlineData("issuer", "user", " ")]
    [InlineData("issuer", "user", null)]
    public void GetOtpAuthUri_InvalidSecret_ThrowsArgumentException(string issuer, string accountName, string secret)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => MfaTotp.GetOtpAuthUri(issuer, accountName, secret));
        Assert.Equal("secret", exception.ParamName);
    }

    [Fact]
    public void ValidateCode_ValidCodeNoDrift_ReturnsTrue()
    {
        // Arrange - compute the current TOTP code for a known secret
        var secret = "JBSWY3DPEHPK3PXP";
        var currentCode = ComputeCurrentCode(secret);

        // Act
        var result = MfaTotp.ValidateCode(secret, currentCode, out var matchedStep);

        // Assert
        Assert.True(result);
        Assert.NotEqual(0, matchedStep);
    }

    [Theory]
    [InlineData("", "123456")]
    [InlineData(" ", "123456")]
    [InlineData(null, "123456")]
    public void ValidateCode_InvalidSecret_ReturnsFalse(string secret, string code)
    {
        // Act
        var result = MfaTotp.ValidateCode(secret, code, out var matchedStep);

        // Assert
        Assert.False(result);
        Assert.Equal(0, matchedStep);
    }

    [Theory]
    [InlineData("JBSWY3DPEHPK3PXP", "")]
    [InlineData("JBSWY3DPEHPK3PXP", " ")]
    [InlineData("JBSWY3DPEHPK3PXP", null)]
    public void ValidateCode_InvalidCode_ReturnsFalse(string secret, string code)
    {
        // Act
        var result = MfaTotp.ValidateCode(secret, code, out var matchedStep);

        // Assert
        Assert.False(result);
        Assert.Equal(0, matchedStep);
    }

    [Theory]
    [InlineData("12345")]   // Too short
    [InlineData("1234567")] // Too long
    [InlineData("12345a")]  // Non-numeric
    [InlineData("abc123")]  // Non-numeric
    public void ValidateCode_InvalidCodeFormat_ReturnsFalse(string code)
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";

        // Act
        var result = MfaTotp.ValidateCode(secret, code, out var matchedStep);

        // Assert
        Assert.False(result);
        Assert.Equal(0, matchedStep);
    }

    [Fact]
    public void ValidateCode_InvalidBase32Secret_ReturnsFalse()
    {
        // Arrange
        var invalidSecret = "INVALID!!!"; // Contains characters not in Base32 alphabet

        // Act
        var result = MfaTotp.ValidateCode(invalidSecret, "123456", out var matchedStep);

        // Assert
        Assert.False(result);
        Assert.Equal(0, matchedStep);
    }

    [Fact]
    public void ValidateCode_WithDriftSteps_AcceptsRange()
    {
        // Arrange - compute the current TOTP code for a known secret
        var secret = "JBSWY3DPEHPK3PXP";
        var allowedDriftSteps = 2;
        var currentCode = ComputeCurrentCode(secret);

        // Act
        var result = MfaTotp.ValidateCode(secret, currentCode, out var matchedStep, allowedDriftSteps);

        // Assert
        Assert.True(result);
        Assert.NotEqual(0, matchedStep);
    }

    [Fact]
    public void ValidateCode_WrongCode_ReturnsFalse()
    {
        // Arrange - use a code that is extremely unlikely to match any drift window
        var secret = "JBSWY3DPEHPK3PXP";
        var currentCode = ComputeCurrentCode(secret);
        // Compute a definitely-wrong code by incrementing each digit
        var wrongCode = string.Create(6, currentCode, (span, code) =>
        {
            for (int i = 0; i < span.Length; i++)
                span[i] = (char)('0' + ((code[i] - '0' + 5) % 10));
        });

        // Act
        var result = MfaTotp.ValidateCode(secret, wrongCode, out var matchedStep);

        // Assert — wrong code should be rejected (with only 1 drift step, 3 windows, collision is near-impossible)
        Assert.False(result);
        Assert.Equal(0, matchedStep);
    }

    /// <summary>
    /// Computes the current TOTP code using the same algorithm as MfaTotp (HMAC-SHA1, 6 digits, 30s period).
    /// </summary>
    private static string ComputeCurrentCode(string secretBase32)
    {
        var key = FromBase32(secretBase32);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var step = now / 30;

        Span<byte> counter = stackalloc byte[8];
        for (int i = 7; i >= 0; i--)
        {
            counter[i] = (byte)(step & 0xff);
            step >>= 8;
        }

        using var hmac = new System.Security.Cryptography.HMACSHA1(key);
        var hash = hmac.ComputeHash(counter.ToArray());

        int offset = hash[^1] & 0x0f;
        int binary = ((hash[offset] & 0x7f) << 24)
                     | ((hash[offset + 1] & 0xff) << 16)
                     | ((hash[offset + 2] & 0xff) << 8)
                     | (hash[offset + 3] & 0xff);

        int otp = binary % 1000000;
        return otp.ToString("D6");
    }

    private static byte[] FromBase32(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var normalized = input.Trim().ToUpperInvariant();
        var output = new byte[normalized.Length * 5 / 8];
        int buffer = 0, bitsLeft = 0, index = 0;
        foreach (var c in normalized)
        {
            buffer <<= 5;
            buffer |= alphabet.IndexOf(c) & 0x1f;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                output[index++] = (byte)((buffer >> (bitsLeft - 8)) & 0xff);
                bitsLeft -= 8;
            }
        }
        return output[..index];
    }

    [Fact]
    public void ValidateCode_CodeWithWhitespace_Normalizes()
    {
        // Arrange
        var secret = "JBSWY3DPEHPK3PXP";
        var codeWithSpaces = " 123456 ";

        // Act
        var result1 = MfaTotp.ValidateCode(secret, codeWithSpaces, out var step1);
        var result2 = MfaTotp.ValidateCode(secret, "123456", out var step2);

        // Assert
        // Both should produce the same result (normalize whitespace)
        Assert.Equal(result1, result2);
        Assert.Equal(step1, step2);
    }

    [Fact]
    public void GenerateSecret_1Byte_GeneratesValidSecret()
    {
        // Act
        var secret = MfaTotp.GenerateSecret(1);

        // Assert
        Assert.NotNull(secret);
        Assert.NotEmpty(secret);
    }

    [Fact]
    public void GenerateSecret_100Bytes_GeneratesValidSecret()
    {
        // Act
        var secret = MfaTotp.GenerateSecret(100);

        // Assert
        Assert.NotNull(secret);
        Assert.NotEmpty(secret);
        // Should be significantly longer
        Assert.True(secret.Length > 100);
    }
}
