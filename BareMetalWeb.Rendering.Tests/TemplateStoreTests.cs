using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Rendering.Tests;

/// <summary>
/// Tests for the sealed TemplateStore class.
/// Uses the resolved templates directory (AppContext.BaseDirectory/wwwroot/templates)
/// with uniquely-named template files to avoid conflicts.
/// </summary>
public class TemplateStoreTests : IDisposable
{
    private readonly string _templatesDir;
    private readonly List<string> _createdFiles = new();
    private readonly string _uniquePrefix;

    public TemplateStoreTests()
    {
        // TemplateStore.ResolveTemplatesBasePath() resolves to this path
        _templatesDir = Path.Combine(AppContext.BaseDirectory, "wwwroot", "templates");
        Directory.CreateDirectory(_templatesDir);
        _uniquePrefix = "test_" + Guid.NewGuid().ToString("N")[..8];
    }

    public void Dispose()
    {
        foreach (var file in _createdFiles)
        {
            if (File.Exists(file))
                File.Delete(file);
        }
    }

    private string UniqueName(string baseName) => $"{_uniquePrefix}_{baseName}";

    private void WriteTemplateFiles(string name, string head = "", string body = "", string footer = "", string script = "")
    {
        WriteAndTrack(Path.Combine(_templatesDir, $"{name}.head.html"), head);
        WriteAndTrack(Path.Combine(_templatesDir, $"{name}.body.html"), body);
        WriteAndTrack(Path.Combine(_templatesDir, $"{name}.footer.html"), footer);
        WriteAndTrack(Path.Combine(_templatesDir, $"{name}.script.html"), script);
    }

    private void WriteAndTrack(string path, string content)
    {
        File.WriteAllText(path, content);
        _createdFiles.Add(path);
    }

    [Fact]
    public void Get_LoadsTemplateFromDisk()
    {
        var name = UniqueName("load");
        WriteTemplateFiles(name,
            head: "<title>Test</title>",
            body: "<h1>Hello</h1>",
            footer: "<footer>ft</footer>",
            script: "console.log('hi');");

        var store = new TemplateStore();

        // Get uses ToLowerInvariant on the name, so pass it with any casing
        var template = store.Get(name.ToUpperInvariant());

        Assert.NotNull(template);
        Assert.Equal("<title>Test</title>", template.Head);
        Assert.Equal("<h1>Hello</h1>", template.Body);
        Assert.Equal("<footer>ft</footer>", template.Footer);
        Assert.Equal("console.log('hi');", template.Script);
    }

    [Fact]
    public void Get_ReturnsSameInstanceOnRepeatedCalls()
    {
        var name = UniqueName("cached");
        WriteTemplateFiles(name, head: "h", body: "b", footer: "f", script: "s");
        var store = new TemplateStore();

        var first = store.Get(name);
        var second = store.Get(name);

        Assert.Same(first, second);
    }

    [Fact]
    public void Get_MissingTemplateFile_ThrowsFileNotFoundException()
    {
        var store = new TemplateStore();

        Assert.ThrowsAny<FileNotFoundException>(() => store.Get(UniqueName("nonexistent")));
    }

    [Fact]
    public void ReloadAll_ClearsCacheAndReloads()
    {
        var name = UniqueName("reload");
        WriteTemplateFiles(name, head: "v1", body: "b1", footer: "f1", script: "s1");
        var store = new TemplateStore();

        var beforeReload = store.Get(name);
        Assert.Equal("v1", beforeReload.Head);

        // Update files on disk
        File.WriteAllText(Path.Combine(_templatesDir, $"{name}.head.html"), "v2");
        File.WriteAllText(Path.Combine(_templatesDir, $"{name}.body.html"), "b2");
        File.WriteAllText(Path.Combine(_templatesDir, $"{name}.footer.html"), "f2");
        File.WriteAllText(Path.Combine(_templatesDir, $"{name}.script.html"), "s2");

        store.ReloadAll();

        // After reload, Get should return new content (ReloadAll pre-loads all templates)
        var afterReload = store.Get(name);
        Assert.NotSame(beforeReload, afterReload);
        Assert.Equal("v2", afterReload.Head);
    }

    [Fact]
    public void ReloadAll_PreloadsAllTemplatesFromDisk()
    {
        var alpha = UniqueName("alpha");
        var beta = UniqueName("beta");
        WriteTemplateFiles(alpha, head: "aH", body: "aB", footer: "aF", script: "aS");
        WriteTemplateFiles(beta, head: "bH", body: "bB", footer: "bF", script: "bS");
        var store = new TemplateStore();

        store.ReloadAll();

        // Templates loaded by ReloadAll should be cached
        var a = store.Get(alpha);
        var b = store.Get(beta);
        Assert.Equal("aH", a.Head);
        Assert.Equal("bH", b.Head);

        // Verify they are the same cached instances
        Assert.Same(a, store.Get(alpha));
        Assert.Same(b, store.Get(beta));
    }

    [Fact]
    public void Get_NameIsCaseInsensitive_FileResolution()
    {
        var name = UniqueName("casepage");
        WriteTemplateFiles(name, head: "H", body: "B", footer: "F", script: "S");
        var store = new TemplateStore();

        var upper = store.Get(name.ToUpperInvariant());
        var lower = store.Get(name.ToLowerInvariant());

        // Both resolve to the same lowercase file
        Assert.Equal("H", upper.Head);
        Assert.Equal("H", lower.Head);
    }

    [Fact]
    public void Get_DifferentCasingKeys_CachedSeparately()
    {
        // TemplateStore caches by the exact name key passed in
        var name = UniqueName("sep");
        WriteTemplateFiles(name, head: "H", body: "B", footer: "F", script: "S");
        var store = new TemplateStore();

        var upper = store.Get(name.ToUpperInvariant());
        var lower = store.Get(name.ToLowerInvariant());

        // Cached under different keys, so different instances (both loaded from same file)
        Assert.NotSame(upper, lower);
        Assert.Equal(upper.Head, lower.Head);
    }
}
