using System.Text;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Rendering.Tests;

public class HtmlFragmentRendererUploadTests
{
    [Fact]
    public void RenderForm_WithFileField_UsesMultipartFormEncoding()
    {
        // Arrange
        var renderer = new HtmlFragmentRenderer(new HtmlFragmentStore());
        var fields = new List<FormField>
        {
            new(FormFieldType.File, "document", "Document")
        };
        var form = new FormDefinition("/upload", "post", "Save", fields);

        // Act
        var html = Encoding.UTF8.GetString(renderer.RenderForm(form));

        // Assert
        Assert.Contains("enctype=\"multipart/form-data\"", html);
    }

    [Fact]
    public void RenderForm_WithStoredImageMetadata_RendersExistingImageUrl()
    {
        // Arrange
        var renderer = new HtmlFragmentRenderer(new HtmlFragmentStore());
        var fields = new List<FormField>
        {
            new(FormFieldType.Image, "photo", "Photo", ExistingFileUrl: "/api/photos/1/files/photo", Accept: "image/png")
        };
        var form = new FormDefinition("/upload", "post", "Save", fields);

        // Act
        var html = Encoding.UTF8.GetString(renderer.RenderForm(form));

        // Assert
        Assert.Contains("/api/photos/1/files/photo", html);
        Assert.Contains("accept=\"image/png\"", html);
    }
}
