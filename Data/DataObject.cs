using System;

namespace BareMetalWeb.Data;

public class RenderableDataObject : BaseDataObject , IBaseDataObject
{

}

public abstract class BaseDataObject : IBaseDataObject
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public DateTime CreatedOnUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedOnUtc { get; set; } = DateTime.UtcNow;
    public string CreatedBy { get; set; } = string.Empty;
    public string UpdatedBy { get; set; } = string.Empty;
    public string ETag { get; set; } = string.Empty;

    protected BaseDataObject()
    {
        // only here for the serializer - not intended for general use
    }

    public BaseDataObject(string createdBy)
    {
        CreatedBy = createdBy;
        Id = Guid.NewGuid().ToString("N");
        CreatedOnUtc = DateTime.UtcNow;
        UpdatedOnUtc = CreatedOnUtc;
        ETag = Guid.NewGuid().ToString("N");
    }

    public void Touch(string updatedBy)
    {
        UpdatedBy = updatedBy ?? string.Empty;
        UpdatedOnUtc = DateTime.UtcNow;
        ETag = Guid.NewGuid().ToString("N");
    }
}
