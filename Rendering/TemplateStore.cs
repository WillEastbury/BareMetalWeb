using System;
using System.Collections.Generic;
using System.IO;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Rendering;

public sealed class TemplateStore : ITemplateStore
{
    private readonly Dictionary<string, IHtmlTemplate> _cache = new();
    private readonly object _lock = new();

    public IHtmlTemplate Get(string name)
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(name, out var cached))
                return cached;

            string basePath = Path.Combine(
                AppContext.BaseDirectory,
                "wwwroot",
                "templates",
                name
            );

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

            string basePath = Path.Combine(AppContext.BaseDirectory, "wwwroot", "templates");
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
