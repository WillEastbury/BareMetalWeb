namespace BareMetalWeb.Data;

    public enum TypeKind
    {
        Primitive,
        String,
        Guid,
        Blittable, // Removed — no longer used
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
