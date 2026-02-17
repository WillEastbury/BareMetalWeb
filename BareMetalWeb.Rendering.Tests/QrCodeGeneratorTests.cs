using System;
using Xunit;

namespace BareMetalWeb.Rendering.Tests;

public class QrCodeGeneratorTests
{
    [Fact]
    public void GenerateSvgDataUri_ValidText_ReturnsDataUri()
    {
        // Arrange
        var text = "https://example.com";

        // Act
        var result = QrCodeGenerator.GenerateSvgDataUri(text);

        // Assert
        Assert.NotNull(result);
        Assert.StartsWith("data:image/svg+xml;base64,", result);
    }

    [Fact]
    public void GenerateSvgDataUri_SimpleText_ContainsSvgElements()
    {
        // Arrange
        var text = "Hello";

        // Act
        var result = QrCodeGenerator.GenerateSvgDataUri(text);
        var base64Part = result.Substring("data:image/svg+xml;base64,".Length);
        var svg = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(base64Part));

        // Assert
        Assert.Contains("<svg", svg);
        Assert.Contains("</svg>", svg);
        Assert.Contains("xmlns=\"http://www.w3.org/2000/svg\"", svg);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void GenerateSvgDataUri_NullOrEmptyText_ThrowsArgumentException(string text)
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => QrCodeGenerator.GenerateSvgDataUri(text));
        Assert.Equal("text", exception.ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-10)]
    public void GenerateSvgDataUri_InvalidPixelsPerModule_ThrowsArgumentOutOfRangeException(int pixelsPerModule)
    {
        // Arrange
        var text = "Test";

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QrCodeGenerator.GenerateSvgDataUri(text, pixelsPerModule));
        Assert.Equal("pixelsPerModule", exception.ParamName);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-10)]
    public void GenerateSvgDataUri_NegativeBorder_ThrowsArgumentOutOfRangeException(int border)
    {
        // Arrange
        var text = "Test";

        // Act & Assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            QrCodeGenerator.GenerateSvgDataUri(text, 4, border));
        Assert.Equal("border", exception.ParamName);
    }

    [Fact]
    public void GenerateSvgDataUri_SameText_GeneratesSameQrCode()
    {
        // Arrange
        var text = "Test123";

        // Act
        var result1 = QrCodeGenerator.GenerateSvgDataUri(text);
        var result2 = QrCodeGenerator.GenerateSvgDataUri(text);

        // Assert
        Assert.Equal(result1, result2);
    }

    [Fact]
    public void GenerateSvgDataUri_DifferentText_GeneratesDifferentQrCodes()
    {
        // Act
        var result1 = QrCodeGenerator.GenerateSvgDataUri("Text1");
        var result2 = QrCodeGenerator.GenerateSvgDataUri("Text2");

        // Assert
        Assert.NotEqual(result1, result2);
    }

    [Fact]
    public void GenerateSvgDataUri_CustomPixelsPerModule_AffectsSize()
    {
        // Arrange
        var text = "Test";

        // Act
        var result1 = QrCodeGenerator.GenerateSvgDataUri(text, pixelsPerModule: 4);
        var result2 = QrCodeGenerator.GenerateSvgDataUri(text, pixelsPerModule: 8);

        // Assert
        Assert.NotEqual(result1, result2);
        // Larger pixels should result in larger SVG
        Assert.True(result2.Length > result1.Length);
    }

    [Fact]
    public void GenerateSvgDataUri_CustomBorder_AffectsSize()
    {
        // Arrange
        var text = "Test";

        // Act
        var result1 = QrCodeGenerator.GenerateSvgDataUri(text, border: 2);
        var result2 = QrCodeGenerator.GenerateSvgDataUri(text, border: 8);

        // Assert
        Assert.NotEqual(result1, result2);
    }

    [Fact]
    public void GenerateSvgDataUri_ZeroBorder_Works()
    {
        // Arrange
        var text = "Test";

        // Act
        var result = QrCodeGenerator.GenerateSvgDataUri(text, border: 0);

        // Assert
        Assert.NotNull(result);
        Assert.StartsWith("data:image/svg+xml;base64,", result);
    }

    [Fact]
    public void GenerateSvgDataUri_LongText_GeneratesQrCode()
    {
        // Arrange
        var text = "This is a longer text that should still generate a QR code without issues";

        // Act
        var result = QrCodeGenerator.GenerateSvgDataUri(text);

        // Assert
        Assert.NotNull(result);
        Assert.StartsWith("data:image/svg+xml;base64,", result);
    }

    [Fact]
    public void GenerateSvgDataUri_SpecialCharacters_GeneratesQrCode()
    {
        // Arrange
        var text = "Hello! @#$%^&*() Test";

        // Act
        var result = QrCodeGenerator.GenerateSvgDataUri(text);

        // Assert
        Assert.NotNull(result);
        Assert.StartsWith("data:image/svg+xml;base64,", result);
    }

    [Fact]
    public void GenerateSvgDataUri_UnicodeCharacters_GeneratesQrCode()
    {
        // Arrange
        var text = "Hello 世界 🌍";

        // Act
        var result = QrCodeGenerator.GenerateSvgDataUri(text);

        // Assert
        Assert.NotNull(result);
        Assert.StartsWith("data:image/svg+xml;base64,", result);
    }

    [Fact]
    public void GenerateSvgDataUri_Url_GeneratesQrCode()
    {
        // Arrange
        var text = "https://example.com/path?query=value&foo=bar#fragment";

        // Act
        var result = QrCodeGenerator.GenerateSvgDataUri(text);

        // Assert
        Assert.NotNull(result);
        Assert.StartsWith("data:image/svg+xml;base64,", result);
    }

    [Fact]
    public void GenerateSvgDataUri_Email_GeneratesQrCode()
    {
        // Arrange
        var text = "mailto:user@example.com";

        // Act
        var result = QrCodeGenerator.GenerateSvgDataUri(text);

        // Assert
        Assert.NotNull(result);
        Assert.StartsWith("data:image/svg+xml;base64,", result);
    }

    [Fact]
    public void GenerateSvgDataUri_Phone_GeneratesQrCode()
    {
        // Arrange
        var text = "tel:+1234567890";

        // Act
        var result = QrCodeGenerator.GenerateSvgDataUri(text);

        // Assert
        Assert.NotNull(result);
        Assert.StartsWith("data:image/svg+xml;base64,", result);
    }

    [Fact]
    public void GenerateSvgDataUri_SingleCharacter_GeneratesQrCode()
    {
        // Arrange
        var text = "A";

        // Act
        var result = QrCodeGenerator.GenerateSvgDataUri(text);

        // Assert
        Assert.NotNull(result);
        Assert.StartsWith("data:image/svg+xml;base64,", result);
    }

    [Fact]
    public void GenerateSvgDataUri_Numbers_GeneratesQrCode()
    {
        // Arrange
        var text = "1234567890";

        // Act
        var result = QrCodeGenerator.GenerateSvgDataUri(text);

        // Assert
        Assert.NotNull(result);
        Assert.StartsWith("data:image/svg+xml;base64,", result);
    }

    [Fact]
    public void GenerateSvgDataUri_ValidBase64Output()
    {
        // Arrange
        var text = "Test";

        // Act
        var result = QrCodeGenerator.GenerateSvgDataUri(text);
        var base64Part = result.Substring("data:image/svg+xml;base64,".Length);

        // Assert
        // Should be valid base64 and decodable
        var decoded = Convert.FromBase64String(base64Part);
        Assert.NotEmpty(decoded);
    }
}
