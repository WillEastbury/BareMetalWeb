namespace BareMetalWeb.Data;

public interface IBaseDataObject
{
    string Id { get; set; }
    DateTime CreatedOnUtc { get; set; }
    DateTime UpdatedOnUtc { get; set; }
    string CreatedBy { get; set; }
    string UpdatedBy { get; set; }
    string ETag { get; set; }

    void Touch(string updatedBy);
}
