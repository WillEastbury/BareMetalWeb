using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.FileProviders;

namespace BareMetalWeb.Core.Host;

public sealed class StaticFileOptionsConfig
{
    public bool Enabled { get; set; } = true;
    public string? RequestPathPrefix { get; set; } = "/static";
    public string? RootDirectory { get; set; } = "wwwroot/static";
    public bool EnableCaching { get; set; } = true;
    public int CacheSeconds { get; set; } = 86400;
    public bool AddETag { get; set; } = true;
    public bool AddLastModified { get; set; } = true;
    public bool AddExpiresHeader { get; set; } = true;
    public bool AllowUnknownMime { get; set; } = false;
    public bool HideUnknownMimeFiles { get; set; } = false;
    public string? DefaultMimeType { get; set; } = "application/octet-stream";
    public string? DefaultFile { get; set; } = null;
    public List<string>? DefaultFiles { get; set; } = new();
    public bool EnableDirectoryBrowsing { get; set; } = false;
    public bool DirectoryListingHideDotFiles { get; set; } = true;
    public bool DirectoryListingHideUnknownMime { get; set; } = false;
    public bool DirectoryListingSortDirectoriesFirst { get; set; } = true;
    public int DirectoryListingMaxEntries { get; set; } = 2000;
    public Dictionary<string, string>? MimeTypes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public bool EnableDynamicCompression { get; set; } = false;
    public int MinBytesToCompress { get; set; } = 1024;
    public bool PreferBrotli { get; set; } = true;
    public bool AllowRangeOnPrecompressed { get; set; } = true;
    public int MaxRanges { get; set; } = 5;
    public int MetadataCacheMaxEntries { get; set; } = 50_000;
    public List<string>? CompressibleContentTypePrefixes { get; set; } = new()
    {
        "text/",
        "application/javascript",
        "application/json",
        "application/xml",
        "image/svg+xml"
    };
}

public sealed class StaticFileConfigOptions
{
    public bool Enabled { get; set; } = true;
    public string RequestPathPrefix { get; set; } = "/static";
    public string RootDirectory { get; set; } = "wwwroot/static";
    public bool EnableCaching { get; set; } = true;
    public int CacheSeconds { get; set; } = 86400;
    public bool AddETag { get; set; } = true;
    public bool AddLastModified { get; set; } = true;
    public bool AddExpiresHeader { get; set; } = true;
    public bool AllowUnknownMime { get; set; } = false;
    public bool HideUnknownMimeFiles { get; set; } = false;
    public string DefaultMimeType { get; set; } = "application/octet-stream";
    public string? DefaultFile { get; set; } = null;
    public List<string> DefaultFiles { get; set; } = new();
    public bool EnableDirectoryBrowsing { get; set; } = false;
    public bool DirectoryListingHideDotFiles { get; set; } = true;
    public bool DirectoryListingHideUnknownMime { get; set; } = false;
    public bool DirectoryListingSortDirectoriesFirst { get; set; } = true;
    public int DirectoryListingMaxEntries { get; set; } = 2000;
    public Dictionary<string, string> MimeTypes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public bool EnableDynamicCompression { get; set; } = false;
    public int MinBytesToCompress { get; set; } = 1024;
    public bool PreferBrotli { get; set; } = true;
    public bool AllowRangeOnPrecompressed { get; set; } = true;
    public int MaxRanges { get; set; } = 5;
    public int MetadataCacheMaxEntries { get; set; } = 50_000;
    public List<string> CompressibleContentTypePrefixes { get; set; } = new()
    {
        "text/",
        "application/javascript",
        "application/json",
        "application/xml",
        "image/svg+xml"
    };
    public string NormalizedRequestPathPrefix { get; private set; } = "/static";
    public string RootPathFull { get; private set; } = string.Empty;
    public FileExtensionContentTypeProvider ContentTypeProvider { get; private set; } = new();
    public PhysicalFileProvider? FileProvider { get; private set; }
    public MemoryCache MetadataCache { get; private set; } = new(new MemoryCacheOptions { SizeLimit = 50_000 });
    public int MetadataCacheSizeLimit { get; private set; } = 50_000;

    public static readonly Dictionary<string, string> DefaultMimeTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        [".html"] = "text/html; charset=utf-8",
        [".htm"] = "text/html; charset=utf-8",
        [".css"] = "text/css; charset=utf-8",
        [".js"] = "application/javascript",
        [".json"] = "application/json; charset=utf-8",
        [".txt"] = "text/plain; charset=utf-8",
        [".xml"] = "application/xml; charset=utf-8",
        [".svg"] = "image/svg+xml",
        [".png"] = "image/png",
        [".jpg"] = "image/jpeg",
        [".jpeg"] = "image/jpeg",
        [".gif"] = "image/gif",
        [".webp"] = "image/webp",
        [".ico"] = "image/x-icon",
        [".woff"] = "font/woff",
        [".woff2"] = "font/woff2",
        [".ttf"] = "font/ttf",
        [".eot"] = "application/vnd.ms-fontobject",
        [".map"] = "application/json; charset=utf-8",
        [".pdf"] = "application/pdf"
    };

    public static StaticFileConfigOptions FromConfig(StaticFileOptionsConfig? config)
    {
        var options = new StaticFileConfigOptions();
        if (config == null)
            return options;

        options.Enabled = config.Enabled;
        options.RequestPathPrefix = config.RequestPathPrefix ?? options.RequestPathPrefix;
        options.RootDirectory = config.RootDirectory ?? options.RootDirectory;
        options.EnableCaching = config.EnableCaching;
        options.CacheSeconds = config.CacheSeconds;
        options.AddETag = config.AddETag;
        options.AddLastModified = config.AddLastModified;
        options.AddExpiresHeader = config.AddExpiresHeader;
        options.AllowUnknownMime = config.AllowUnknownMime;
        options.HideUnknownMimeFiles = config.HideUnknownMimeFiles;
        options.DefaultMimeType = config.DefaultMimeType ?? options.DefaultMimeType;
        options.DefaultFile = config.DefaultFile;
        options.DefaultFiles = config.DefaultFiles?.ToList() ?? new List<string>();
        options.EnableDirectoryBrowsing = config.EnableDirectoryBrowsing;
        options.DirectoryListingHideDotFiles = config.DirectoryListingHideDotFiles;
        options.DirectoryListingHideUnknownMime = config.DirectoryListingHideUnknownMime;
        options.DirectoryListingSortDirectoriesFirst = config.DirectoryListingSortDirectoriesFirst;
        options.DirectoryListingMaxEntries = config.DirectoryListingMaxEntries;
        options.MimeTypes = config.MimeTypes != null
            ? new Dictionary<string, string>(config.MimeTypes, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        options.EnableDynamicCompression = config.EnableDynamicCompression;
        options.MinBytesToCompress = config.MinBytesToCompress;
        options.PreferBrotli = config.PreferBrotli;
        options.AllowRangeOnPrecompressed = config.AllowRangeOnPrecompressed;
        options.MaxRanges = config.MaxRanges;
        options.MetadataCacheMaxEntries = config.MetadataCacheMaxEntries;
        options.CompressibleContentTypePrefixes = config.CompressibleContentTypePrefixes?.ToList() ?? new List<string>();

        return options;
    }

    public void Normalize()
    {
        if (string.IsNullOrWhiteSpace(RequestPathPrefix))
            RequestPathPrefix = "/static";

        if (!RequestPathPrefix.StartsWith("/", StringComparison.Ordinal))
            RequestPathPrefix = "/" + RequestPathPrefix;

        if (RequestPathPrefix.Length > 1 && RequestPathPrefix.EndsWith("/", StringComparison.Ordinal))
            RequestPathPrefix = RequestPathPrefix.TrimEnd('/');

        NormalizedRequestPathPrefix = RequestPathPrefix;

        if (string.IsNullOrWhiteSpace(RootDirectory))
            RootDirectory = "wwwroot/static";

        RootPathFull = Path.GetFullPath(Path.IsPathRooted(RootDirectory)
            ? RootDirectory
            : Path.Combine(AppContext.BaseDirectory, RootDirectory));

        if (!Directory.Exists(RootPathFull) && !Path.IsPathRooted(RootDirectory))
        {
            var repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
            var repoRootPath = Path.Combine(repoRoot, "BareMetalWeb.Core", RootDirectory.Replace('/', Path.DirectorySeparatorChar));
            if (Directory.Exists(repoRootPath))
            {
                RootPathFull = repoRootPath;
            }
        }

        if (Directory.Exists(RootPathFull))
        {
            FileProvider?.Dispose();
            FileProvider = new PhysicalFileProvider(RootPathFull);
        }

        if (CacheSeconds < 0)
            CacheSeconds = 0;

        if (MetadataCacheMaxEntries <= 0)
            MetadataCacheMaxEntries = 50_000;

        if (MetadataCacheSizeLimit != MetadataCacheMaxEntries)
        {
            MetadataCache.Dispose();
            MetadataCache = new MemoryCache(new MemoryCacheOptions { SizeLimit = MetadataCacheMaxEntries });
            MetadataCacheSizeLimit = MetadataCacheMaxEntries;
        }

        if (DefaultFiles.Count == 0 && !string.IsNullOrWhiteSpace(DefaultFile))
            DefaultFiles.Add(DefaultFile);

        foreach (var kvp in DefaultMimeTypes)
        {
            if (!MimeTypes.ContainsKey(kvp.Key))
                MimeTypes[kvp.Key] = kvp.Value;
        }

        var keys = new List<string>(MimeTypes.Keys);
        foreach (var key in keys)
        {
            if (!key.StartsWith(".", StringComparison.Ordinal))
            {
                var value = MimeTypes[key];
                MimeTypes.Remove(key);
                MimeTypes["." + key] = value;
            }
        }

        ContentTypeProvider = new FileExtensionContentTypeProvider();
        foreach (var kvp in MimeTypes)
        {
            ContentTypeProvider.Mappings[kvp.Key] = kvp.Value;
        }
    }
}
