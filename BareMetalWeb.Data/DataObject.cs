using System;

namespace BareMetalWeb.Data;

public abstract class BaseDataObject : IBaseDataObject
{
    public uint Key { get; set; }
    public IdentifierValue Identifier { get; set; }
    public DateTime CreatedOnUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedOnUtc { get; set; } = DateTime.UtcNow;
    public string CreatedBy { get; set; } = string.Empty;
    public string UpdatedBy { get; set; } = string.Empty;
    public string ETag { get; set; } = string.Empty;
    /// <summary>Monotonic version counter for optimistic concurrency. Incremented on every save.</summary>
    public uint Version { get; set; }

    protected BaseDataObject()
    {
        // only here for the serializer - not intended for general use
    }

    public BaseDataObject(string createdBy)
    {
        CreatedBy = createdBy;
        CreatedOnUtc = DateTime.UtcNow;
        UpdatedOnUtc = CreatedOnUtc;
        ETag = Guid.NewGuid().ToString("N");
    }

    public void Touch(string updatedBy)
    {
        UpdatedBy = updatedBy ?? string.Empty;
        UpdatedOnUtc = DateTime.UtcNow;
        ETag = Guid.NewGuid().ToString("N");
        Version++;
    }
}
