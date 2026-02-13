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

            string basePath = Path.Combine(ResolveTemplatesBasePath(), name.ToLowerInvariant());

            var template = new HtmlTemplate(
                File.ReadAllText(basePath + ".head.html"),
                File.ReadAllText(basePath + ".body.html"),
                File.ReadAllText(basePath + ".footer.html"),
                File.ReadAllText(basePath + ".script.html")
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
