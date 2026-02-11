namespace BareMetalWeb.Data;

    public enum TypeKind
    {
        Primitive,
        String,
        Guid,
        Blittable,
        DateTime,
        DateOnly,
        TimeOnly,
        DateTimeOffset,
        TimeSpan,
        Half,
        IntPtr,
        UIntPtr,
        Array,
        List,
        Dictionary,
        Enum,
        Object
    }
