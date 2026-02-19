using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Data;

[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class ImageFieldAttribute : Attribute
{
    public string? Label { get; set; }
    public int Order { get; set; }
    public bool Required { get; set; }
    public bool List { get; set; } = true;
    public bool View { get; set; } = true;
    public bool Edit { get; set; } = true;
    public bool Create { get; set; } = true;
    public bool ReadOnly { get; set; }
    public string? Placeholder { get; set; }
    public long MaxFileSizeBytes { get; set; } = 5L * 1024 * 1024;
    public string[] AllowedMimeTypes { get; set; } = ["image/jpeg", "image/png", "image/gif", "image/webp"];
    public int MaxWidth { get; set; }
    public int MaxHeight { get; set; }
    public bool GenerateThumbnail { get; set; }
    public FormFieldType FieldType => FormFieldType.Image;
}
