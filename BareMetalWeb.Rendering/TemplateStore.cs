using System;
using System.Collections.Generic;
using System.IO;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Rendering;

public sealed class TemplateStore : ITemplateStore
{
    private readonly Dictionary<string, global::BareMetalWeb.Interfaces.IHtmlTemplate> _cache = new();
    private readonly object _lock = new();

    private static string ResolveTemplatesBasePath()
    {
        var basePath = Path.Combine(AppContext.BaseDirectory, "wwwroot", "templates");
        if (Directory.Exists(basePath))
            return basePath;

        var repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
        var repoTemplatesPath = Path.Combine(repoRoot, "BareMetalWeb.Core", "wwwroot", "templates");
        return Directory.Exists(repoTemplatesPath) ? repoTemplatesPath : basePath;
    }

    public global::BareMetalWeb.Interfaces.IHtmlTemplate Get(string name)
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(name, out var cached))
                return cached;

            // Reject path traversal attempts
            if (name.Contains("..") || name.Contains('/') || name.Contains('\\') ||
                name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                throw new ArgumentException($"Invalid template name: '{name}'");

            var templatesDir = ResolveTemplatesBasePath();
            string basePath = Path.Combine(templatesDir, name.ToLowerInvariant());

            // Ensure resolved path stays within the templates directory
            var fullPath = Path.GetFullPath(basePath);
            var fullTemplatesDir = Path.GetFullPath(templatesDir);
            if (!fullPath.StartsWith(fullTemplatesDir, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException($"Invalid template name: '{name}'");

            var template = new HtmlTemplate(
                File.ReadAllText(fullPath + ".head.html"),
                File.ReadAllText(fullPath + ".body.html"),
                File.ReadAllText(fullPath + ".footer.html"),
                File.ReadAllText(fullPath + ".script.html")
            );

            _cache[name] = template;
            return template;
        }
    }

    public void ReloadAll()
    {
        lock (_lock)
        {
            _cache.Clear();

            string basePath = ResolveTemplatesBasePath();
            foreach (var headFile in Directory.GetFiles(basePath, "*.head.html"))
            {
                var name = Path.GetFileNameWithoutExtension(headFile).Replace(".head", "");
                var template = new HtmlTemplate(
                    File.ReadAllText(Path.Combine(basePath, name + ".head.html")),
                    File.ReadAllText(Path.Combine(basePath, name + ".body.html")),
                    File.ReadAllText(Path.Combine(basePath, name + ".footer.html")),
                    File.ReadAllText(Path.Combine(basePath, name + ".script.html"))
                );
                _cache[name] = template;
            }
        }
    }
}
