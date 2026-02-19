namespace BareMetalWeb.Data;

public sealed record UploadFieldConfig(
    long MaxFileSizeBytes,
    string[] AllowedMimeTypes,
    int? MaxImageWidth,
    int? MaxImageHeight,
    bool GenerateThumbnail
);
