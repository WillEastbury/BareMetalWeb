namespace BareMetalWeb.Data;

public sealed class StoredFileData
{
    public string FileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = "application/octet-stream";
    public long SizeBytes { get; set; }
    public string StorageKey { get; set; } = string.Empty;
    public bool IsImage { get; set; }
    public int? Width { get; set; }
    public int? Height { get; set; }
}
