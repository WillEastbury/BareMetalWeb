using System.Collections.Generic;

namespace BareMetalWeb.Rendering;

public enum FormFieldType
{
    Unknown,
    String,
    TextArea,
    Enum,
    DateOnly,
    TimeOnly,
    DateTime,
    Integer,
    Decimal,
    Money,
    Image,
    File,
    Password,
    Email,
    Country,
    YesNo,
    LookupList,
    Otp,
    Button,
    Link,
    Hidden,
    CustomHtml
}

public sealed record FormField(
    FormFieldType FieldType,
    string Name,
    string Label,
    bool Required = false,
    string? Placeholder = null,
    string? Value = null,
    int DecimalPlaces = 2,
    string? SelectedValue = null,
    IReadOnlyList<KeyValuePair<string, string>>? LookupOptions = null,
    IReadOnlyList<string>? CurrencyOptions = null,
    IReadOnlyList<KeyValuePair<string, string>>? CountryOptions = null,
    string? EmailPattern = null,
    string? ButtonType = null,
    string? ButtonStyle = null,
    string? ButtonText = null,
    string? LinkUrl = null,
    string? LinkText = null,
    string? LinkTarget = null,
    string? LinkClass = null,
    string? Html = null
);

public sealed record FormDefinition(
    string Action,
    string Method,
    string SubmitLabel,
    IReadOnlyList<FormField> Fields
);
