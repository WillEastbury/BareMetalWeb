using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Data;

[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class DataFieldAttribute : Attribute
{
    public string? Label { get; set; }
    public FormFieldType FieldType { get; set; } = FormFieldType.Unknown;
    public int Order { get; set; } = 0;
    public bool Required { get; set; } = false;
    public bool List { get; set; } = true;
    public bool View { get; set; } = true;
    public bool Edit { get; set; } = true;
    public bool Create { get; set; } = true;
    public bool ReadOnly { get; set; } = false;
    public string? Placeholder { get; set; }
}


