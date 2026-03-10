using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Unit tests for RouteHandlers — testing pure/static logic, argument validation,
/// and handler behaviour that can be exercised without a full HTTP server.
/// </summary>
[Collection("SharedState")]
public class RouteHandlerTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;
    private readonly InMemoryDataStore _testStore;
    private readonly RouteHandlers _handlers;
    private readonly string _keyRootDirectory;

    public RouteHandlerTests()
    {
        _keyRootDirectory = Path.Combine(Path.GetTempPath(), $"bmw-rh-tests-{Guid.NewGuid()}");
        Directory.CreateDirectory(_keyRootDirectory);
        CookieProtection.ConfigureKeyRoot(_keyRootDirectory);

        _originalStore = DataStoreProvider.Current;
        _testStore = new InMemoryDataStore();
        DataStoreProvider.Current = _testStore;

        _handlers = new RouteHandlers(
            new MockHtmlRenderer(),
            new MockTemplateStore(),
            allowAccountCreation: true,
            mfaKeyRootFolder: _keyRootDirectory,
            auditService: new AuditService(_testStore));
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
        if (Directory.Exists(_keyRootDirectory))
            Directory.Delete(_keyRootDirectory, true);
    }

    private void EnsureStore()
    {
        DataStoreProvider.Current = _testStore;
    }

    // ──────────────────────────────────────────────────────────────
    //  Helpers – invoke private static methods via reflection
    // ──────────────────────────────────────────────────────────────

    private static readonly Type RhType = typeof(RouteHandlers);

    private static T InvokeStatic<T>(string methodName, params object?[] args)
    {
        var mi = RhType.GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new MissingMethodException(nameof(RouteHandlers), methodName);
        return (T)mi.Invoke(null, args)!;
    }

    private static object? InvokeStaticRaw(string methodName, Type[] paramTypes, params object?[] args)
    {
        var mi = RhType.GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static, null, paramTypes, null)
            ?? throw new MissingMethodException(nameof(RouteHandlers), methodName);
        return mi.Invoke(null, args);
    }

    // ──────────────────────────────────────────────────────────────
    //  NormalizeOtpCode tests
    // ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null, null)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData("12345", null)]       // too short
    [InlineData("1234567", null)]     // too long
    [InlineData("abcdef", null)]      // non-digits
    [InlineData("12ab56", null)]      // mixed
    [InlineData("123456", "123456")]  // valid
    [InlineData(" 123456 ", "123456")] // trimmed
    [InlineData("000000", "000000")] // all zeros
    public void NormalizeOtpCode_VariousInputs_ReturnsExpected(string? input, string? expected)
    {
        var result = InvokeStatic<string?>("NormalizeOtpCode", input!);
        Assert.Equal(expected, result);
    }

    // ──────────────────────────────────────────────────────────────
    //  MaskSecret tests
    // ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("   ", "")]
    [InlineData("ABCD", "****")]           // length == reveal
    [InlineData("AB", "**")]               // length < reveal
    [InlineData("ABCDEFGHIJ", "******GHIJ")] // length > reveal
    public void MaskSecret_VariousInputs_ReturnsExpected(string? input, string expected)
    {
        var result = InvokeStatic<string>("MaskSecret", input!);
        Assert.Equal(expected, result);
    }

    // ──────────────────────────────────────────────────────────────
    //  FormatThrottleMessage tests
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void FormatThrottleMessage_NullRetryAfter_ReturnsGenericMessage()
    {
        var result = InvokeStatic<string>("FormatThrottleMessage", (TimeSpan?)null);
        Assert.Equal("Too many attempts. Please try again shortly.", result);
    }

    [Fact]
    public void FormatThrottleMessage_WithRetryAfter_IncludesSeconds()
    {
        var result = InvokeStatic<string>("FormatThrottleMessage", (TimeSpan?)TimeSpan.FromSeconds(30.2));
        Assert.Contains("31 seconds", result);
    }

    [Fact]
    public void FormatThrottleMessage_SmallRetryAfter_RoundsUp()
    {
        var result = InvokeStatic<string>("FormatThrottleMessage", (TimeSpan?)TimeSpan.FromSeconds(0.1));
        Assert.Contains("1 seconds", result);
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("TRUE", true)]
    [InlineData("on", true)]
    [InlineData("1", true)]
    [InlineData("false", false)]
    [InlineData("0", false)]
    [InlineData("", false)]
    public void IsTruthyFormValue_VariousInputs_ReturnsExpected(string value, bool expected)
    {
        var result = InvokeStatic<bool>("IsTruthyFormValue", (object)new StringValues(value));
        Assert.Equal(expected, result);
    }

    [Fact]
    public void ValidateSetupRegistrationInput_MissingCallback_ReturnsError()
    {
        var form = new FormCollection(new Dictionary<string, StringValues>(StringComparer.OrdinalIgnoreCase)
        {
            ["management_registration_enabled"] = new StringValues("true"),
            ["management_callback_url"] = StringValues.Empty,
            ["management_principal_name"] = new StringValues("agent-one")
        });

        var input = InvokeStaticRaw("ReadSetupRegistrationInput", new[] { typeof(IFormCollection) }, form);
        Assert.NotNull(input);

        var error = (string?)InvokeStaticRaw("ValidateSetupRegistrationInput", new[] { input!.GetType() }, input);
        Assert.Equal("Management callback URL is required when registration is enabled.", error);
    }

    [Fact]
    public void ValidateSetupRegistrationInput_HttpsCallback_ReturnsNull()
    {
        var form = new FormCollection(new Dictionary<string, StringValues>(StringComparer.OrdinalIgnoreCase)
        {
            ["management_registration_enabled"] = new StringValues("true"),
            ["management_callback_url"] = new StringValues("https://controlplane.example/api/setup/register"),
            ["management_principal_name"] = new StringValues("agent-one")
        });

        var input = InvokeStaticRaw("ReadSetupRegistrationInput", new[] { typeof(IFormCollection) }, form);
        Assert.NotNull(input);

        var error = (string?)InvokeStaticRaw("ValidateSetupRegistrationInput", new[] { input!.GetType() }, input);
        Assert.Null(error);
    }

    // ──────────────────────────────────────────────────────────────
    //  CsvEscape tests
    // ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("hello", "hello")]
    [InlineData("", "")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("a\"b", "\"a\"\"b\"")]
    [InlineData("a\nb", "\"a\nb\"")]
    [InlineData("a\rb", "\"a\rb\"")]
    public void CsvEscape_VariousInputs_ReturnsExpected(string input, string expected)
    {
        var result = InvokeStatic<string>("CsvEscape", input);
        Assert.Equal(expected, result);
    }

    // ──────────────────────────────────────────────────────────────
    //  StripHtml tests
    // ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("hello", "hello")]
    [InlineData("<b>bold</b>", "bold")]
    [InlineData("<a href=\"/\">link</a> text", "link text")]
    [InlineData("no tags here", "no tags here")]
    public void StripHtml_VariousInputs_ReturnsExpected(string? input, string expected)
    {
        var result = InvokeStatic<string>("StripHtml", input!);
        Assert.Equal(expected, result);
    }

    // ──────────────────────────────────────────────────────────────
    //  FormatSizeBytes tests
    // ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(0, "0 B")]
    [InlineData(500, "500 B")]
    [InlineData(1024, "1 KB")]
    [InlineData(1536, "1.5 KB")]
    [InlineData(1048576, "1 MB")]
    public void FormatSizeBytes_VariousValues_ReturnsExpected(long bytes, string expected)
    {
        var result = InvokeStatic<string>("FormatSizeBytes", bytes);
        Assert.Equal(expected, result);
    }

    // ──────────────────────────────────────────────────────────────
    //  ParseCsvRows tests
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void ParseCsvRows_EmptyContent_ReturnsEmptyList()
    {
        var result = InvokeStatic<List<string[]>>("ParseCsvRows", "");
        Assert.Empty(result);
    }

    [Fact]
    public void ParseCsvRows_NullContent_ReturnsEmptyList()
    {
        var result = InvokeStatic<List<string[]>>("ParseCsvRows", (string)null!);
        Assert.Empty(result);
    }

    [Fact]
    public void ParseCsvRows_SingleRow_ReturnsOneRow()
    {
        var result = InvokeStatic<List<string[]>>("ParseCsvRows", "a,b,c");
        Assert.Single(result);
        Assert.Equal(new[] { "a", "b", "c" }, result[0]);
    }

    [Fact]
    public void ParseCsvRows_MultipleRows_ParsesCorrectly()
    {
        var result = InvokeStatic<List<string[]>>("ParseCsvRows", "Name,Email\nAlice,a@b.com\nBob,b@b.com");
        Assert.Equal(3, result.Count);
        Assert.Equal("Name", result[0][0]);
        Assert.Equal("Alice", result[1][0]);
        Assert.Equal("Bob", result[2][0]);
    }

    [Fact]
    public void ParseCsvRows_QuotedFields_HandlesEscaping()
    {
        var result = InvokeStatic<List<string[]>>("ParseCsvRows", "\"a,b\",\"c\"\"d\"");
        Assert.Single(result);
        Assert.Equal("a,b", result[0][0]);
        Assert.Equal("c\"d", result[0][1]);
    }

    [Fact]
    public void ParseCsvRows_CrLfLineEndings_ParsesCorrectly()
    {
        var result = InvokeStatic<List<string[]>>("ParseCsvRows", "a,b\r\nc,d\r\n");
        Assert.Equal(2, result.Count);
        Assert.Equal(new[] { "a", "b" }, result[0]);
        Assert.Equal(new[] { "c", "d" }, result[1]);
    }

    // ──────────────────────────────────────────────────────────────
    //  BuildCsv tests
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void BuildCsv_SimpleInput_ProducesValidCsv()
    {
        var headers = new[] { "Name", "Age" };
        var rows = new[] { new[] { "Alice", "30" }, new[] { "Bob", "25" } };
        var result = InvokeStatic<string>("BuildCsv", headers, rows);

        Assert.Contains("Name,Age", result);
        Assert.Contains("Alice,30", result);
        Assert.Contains("Bob,25", result);
    }

    [Fact]
    public void BuildCsv_SpecialCharacters_EscapesCorrectly()
    {
        var headers = new[] { "Value" };
        var rows = new[] { new[] { "has,comma" } };
        var result = InvokeStatic<string>("BuildCsv", headers, rows);

        Assert.Contains("\"has,comma\"", result);
    }

    private class InMemoryDataStore : IDataObjectStore
    {
        private readonly Dictionary<(Type, uint), BaseDataObject> _store = new();
        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }
        public void Save<T>(T obj) where T : BaseDataObject => _store[(typeof(T), obj.Key)] = obj;
        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject { Save(obj); return ValueTask.CompletedTask; }
        public T? Load<T>(uint key) where T : BaseDataObject => _store.TryGetValue((typeof(T), key), out var obj) ? obj as T : null;
        public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject => ValueTask.FromResult(Load<T>(key));
        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject => _store.Values.OfType<T>();
        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject => ValueTask.FromResult(Query<T>(query));
        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject => ValueTask.FromResult(Query<T>(query).Count());
        public void Delete<T>(uint key) where T : BaseDataObject => _store.Remove((typeof(T), key));
        public ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject { Delete<T>(key); return ValueTask.CompletedTask; }
    }

    private class MockHtmlRenderer : IHtmlRenderer
    {
        public ValueTask RenderPage(BmwContext context) => ValueTask.CompletedTask;
        public ValueTask RenderPage(BmwContext context, PageInfo page, IBareWebHost app) => ValueTask.CompletedTask;
        public ValueTask<ReadOnlyMemory<byte>> RenderToBytesAsync(BmwContext context, PageInfo page, IBareWebHost app) => ValueTask.FromResult(ReadOnlyMemory<byte>.Empty);
        public ValueTask<ReadOnlyMemory<byte>> RenderToBytesAsync(IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null)
            => ValueTask.FromResult<ReadOnlyMemory<byte>>(Array.Empty<byte>());
        public ValueTask RenderToStreamAsync(PipeWriter writer, IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null)
            => ValueTask.CompletedTask;
    }

    private class MockTemplateStore : ITemplateStore
    {
        public IHtmlTemplate Get(string name) => new EmptyTemplate();
        public void ReloadAll() { }
        private class EmptyTemplate : IHtmlTemplate
        {
            public System.Text.Encoding Encoding => System.Text.Encoding.UTF8;
            public string ContentTypeHeader => "text/html";
            public string Head => string.Empty;
            public string Body => string.Empty;
            public string Footer => string.Empty;
            public string Script => string.Empty;
        }
    }
}
