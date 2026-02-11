using System.Collections.Generic;

namespace BareMetalWeb.Rendering.Models;

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
