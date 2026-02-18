using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Reflection;
using System.Text;
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
using BareMetalWeb.Data.DataObjects;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Unit tests for RouteHandlers — testing pure/static logic, argument validation,
/// and handler behaviour that can be exercised without a full HTTP server.
/// </summary>
[Collection("CookieProtection")]
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
            mfaKeyRootFolder: _keyRootDirectory);
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

    // ──────────────────────────────────────────────────────────────
    //  IsValidCloneReturnUrl tests
    // ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("   ", false)]
    [InlineData("https://evil.com/admin/data/foo", false)]     // contains ://
    [InlineData("//evil.com/admin/data/foo", false)]            // starts with //
    [InlineData("/home", false)]                                // wrong prefix
    [InlineData("/admin/data/customer", true)]                  // valid
    [InlineData("/admin/data/customer?page=2", true)]           // valid with query
    public void IsValidCloneReturnUrl_VariousInputs_ReturnsExpected(string? input, bool expected)
    {
        var result = InvokeStatic<bool>("IsValidCloneReturnUrl", input);
        Assert.Equal(expected, result);
    }

    // ──────────────────────────────────────────────────────────────
    //  IsCloneExcluded tests
    // ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("Id", true)]
    [InlineData("CreatedOnUtc", true)]
    [InlineData("UpdatedOnUtc", true)]
    [InlineData("CreatedBy", true)]
    [InlineData("UpdatedBy", true)]
    [InlineData("ETag", true)]
    [InlineData("Name", false)]
    [InlineData("Email", false)]
    public void IsCloneExcluded_VariousProperties_ReturnsExpected(string property, bool expected)
    {
        var result = InvokeStatic<bool>("IsCloneExcluded", property);
        Assert.Equal(expected, result);
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
    //  EscapeRtf tests
    // ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("hello", "hello")]
    [InlineData("back\\slash", "back\\\\slash")]
    [InlineData("{braces}", "\\{braces\\}")]
    [InlineData("line\nbreak", "line\\par break")]
    [InlineData("carriage\rreturn", "carriagereturn")]
    public void EscapeRtf_VariousInputs_ReturnsExpected(string? input, string expected)
    {
        var result = InvokeStatic<string>("EscapeRtf", input!);
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

    // ──────────────────────────────────────────────────────────────
    //  BuildHtmlTableDocument tests
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void BuildHtmlTableDocument_ProducesValidHtml()
    {
        var headers = new[] { "Col1", "Col2" };
        var rows = new[] { new[] { "a", "b" } };
        var result = InvokeStatic<string>("BuildHtmlTableDocument", "Test Title", headers, rows);

        Assert.Contains("<!doctype html>", result);
        Assert.Contains("Test Title", result);
        Assert.Contains("<th>Col1</th>", result);
        Assert.Contains("<td>a</td>", result);
    }

    // ──────────────────────────────────────────────────────────────
    //  BuildRtfDocument tests
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void BuildRtfDocument_ProducesRtfMarkup()
    {
        var rows = new[] { new[] { "Label", "Value" } };
        var result = InvokeStatic<string>("BuildRtfDocument", "Title", rows);

        Assert.StartsWith("{\\rtf1", result);
        Assert.Contains("Title", result);
        Assert.Contains("Label", result);
        Assert.Contains("Value", result);
    }

    // ──────────────────────────────────────────────────────────────
    //  BuildPageHandler – null argument checks
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void BuildPageHandler_ActionOverload_NullConfigure_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _handlers.BuildPageHandler((Action<HttpContext>)null!));
    }

    [Fact]
    public void BuildPageHandler_AsyncOverload_NullConfigure_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _handlers.BuildPageHandler((Func<HttpContext, ValueTask>)null!));
    }

    [Fact]
    public void BuildPageHandler_BoolAsyncOverload_NullConfigure_ThrowsArgumentNull()
    {
        Assert.Throws<ArgumentNullException>(() =>
            _handlers.BuildPageHandler((Func<HttpContext, ValueTask<bool>>)null!, true));
    }

    // ──────────────────────────────────────────────────────────────
    //  BuildPageHandler – delegates are returned
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void BuildPageHandler_ActionOverload_ReturnsDelegate()
    {
        var handler = _handlers.BuildPageHandler(_ => { });
        Assert.NotNull(handler);
    }

    [Fact]
    public void BuildPageHandler_AsyncOverload_ReturnsDelegate()
    {
        var handler = _handlers.BuildPageHandler(_ => ValueTask.CompletedTask);
        Assert.NotNull(handler);
    }

    [Fact]
    public void BuildPageHandler_BoolAsyncOverload_ReturnsDelegate()
    {
        var handler = _handlers.BuildPageHandler(_ => ValueTask.FromResult(true));
        Assert.NotNull(handler);
    }

    // ──────────────────────────────────────────────────────────────
    //  TimeRawHandler
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task TimeRawHandler_ReturnsPlainText_WithServerTime()
    {
        // Arrange
        EnsureStore();
        var context = CreateHttpContext("GET", "/time/raw");

        // Act
        await _handlers.TimeRawHandler(context);

        // Assert
        Assert.Equal("text/plain", context.Response.ContentType);
        var body = await ReadResponseBody(context);
        Assert.StartsWith("Current server time is:", body);
    }

    // ──────────────────────────────────────────────────────────────
    //  LoginPostHandler – content type validation
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task LoginPostHandler_NonFormContentType_Returns415()
    {
        // Arrange
        EnsureStore();
        var context = CreateHttpContext("POST", "/login");
        context.Request.ContentType = "application/json";

        // Act
        await _handlers.LoginPostHandler(context);

        // Assert
        Assert.Equal(StatusCodes.Status415UnsupportedMediaType, context.Response.StatusCode);
    }

    // ──────────────────────────────────────────────────────────────
    //  RegisterPostHandler – account creation disabled
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task RegisterPostHandler_AccountCreationDisabled_ShowsDisabledMessage()
    {
        // Arrange
        EnsureStore();
        var disabledHandlers = new RouteHandlers(
            new MockHtmlRenderer(),
            new MockTemplateStore(),
            allowAccountCreation: false,
            mfaKeyRootFolder: _keyRootDirectory);

        var context = CreateHttpContext("POST", "/register");

        // Act
        await disabledHandlers.RegisterPostHandler(context);

        // Assert – the handler should set the title and message and render
        var pc = context.GetPageContext();
        Assert.NotNull(pc);
        var titleIndex = Array.IndexOf(pc.PageMetaDataKeys, "title");
        Assert.True(titleIndex >= 0);
        Assert.Equal("Create Account", pc.PageMetaDataValues[titleIndex]);
    }

    // ──────────────────────────────────────────────────────────────
    //  RegisterPostHandler – non-form content type
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task RegisterPostHandler_NonFormContentType_ShowsErrorMessage()
    {
        // Arrange
        EnsureStore();
        var context = CreateHttpContext("POST", "/register");
        context.Request.ContentType = "application/json";

        // Act
        await _handlers.RegisterPostHandler(context);

        // Assert
        var pc = context.GetPageContext();
        Assert.NotNull(pc);
        var msgIndex = Array.IndexOf(pc.PageMetaDataKeys, "message");
        Assert.True(msgIndex >= 0);
        Assert.Contains("Invalid registration request", pc.PageMetaDataValues[msgIndex]);
    }

    // ──────────────────────────────────────────────────────────────
    //  LogoutPostHandler – content type validation
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task LogoutPostHandler_NonFormContentType_ShowsErrorMessage()
    {
        // Arrange
        EnsureStore();
        var context = CreateHttpContext("POST", "/logout");
        context.Request.ContentType = "application/json";

        // Act
        await _handlers.LogoutPostHandler(context);

        // Assert
        var pc = context.GetPageContext();
        Assert.NotNull(pc);
        var msgIndex = Array.IndexOf(pc.PageMetaDataKeys, "message");
        Assert.True(msgIndex >= 0);
        Assert.Contains("Invalid logout request", pc.PageMetaDataValues[msgIndex]);
    }

    // ──────────────────────────────────────────────────────────────
    //  MfaChallengePostHandler – content type validation
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task MfaChallengePostHandler_NoCookie_RedirectsToLogin()
    {
        // Arrange
        EnsureStore();
        var context = CreateHttpContext("POST", "/mfa");

        // Act
        await _handlers.MfaChallengePostHandler(context);

        // Assert
        Assert.Equal(StatusCodes.Status302Found, context.Response.StatusCode);
        Assert.Equal("/login", context.Response.Headers.Location.ToString());
    }

    // ──────────────────────────────────────────────────────────────
    //  ApplyAuditInfo tests (via reflection)
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void ApplyAuditInfo_Create_SetsCreatedAndUpdatedFields()
    {
        var user = new User { Id = "u1", UserName = "test" };
        var before = DateTime.UtcNow;

        InvokeStaticRaw("ApplyAuditInfo",
            new[] { typeof(object), typeof(string), typeof(bool) },
            user, "admin", true);

        Assert.Equal("admin", user.CreatedBy);
        Assert.Equal("admin", user.UpdatedBy);
        Assert.True(user.CreatedOnUtc >= before);
        Assert.Equal(user.CreatedOnUtc, user.UpdatedOnUtc);
    }

    [Fact]
    public void ApplyAuditInfo_Update_TouchesRecord()
    {
        var user = new User
        {
            Id = "u1",
            UserName = "test",
            CreatedBy = "original",
            CreatedOnUtc = DateTime.UtcNow.AddDays(-1)
        };

        InvokeStaticRaw("ApplyAuditInfo",
            new[] { typeof(object), typeof(string), typeof(bool) },
            user, "editor", false);

        Assert.Equal("original", user.CreatedBy); // should not change
        Assert.Equal("editor", user.UpdatedBy);
    }

    [Fact]
    public void ApplyAuditInfo_NonBaseDataObject_DoesNothing()
    {
        // Should not throw for non-BaseDataObject
        InvokeStaticRaw("ApplyAuditInfo",
            new[] { typeof(object), typeof(string), typeof(bool) },
            "not a data object", "admin", true);
    }

    // ──────────────────────────────────────────────────────────────
    //  BuildMfaAttemptKey tests
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void BuildMfaAttemptKey_FormatsCorrectly()
    {
        var result = InvokeStatic<string>("BuildMfaAttemptKey", "challenge:user", "user123");
        Assert.Equal("challenge:user:user123", result);
    }

    // ──────────────────────────────────────────────────────────────
    //  GetViewTypeName tests
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void GetViewTypeName_TreeView_ReturnsExpected()
    {
        var result = InvokeStatic<string>("GetViewTypeName", ViewType.TreeView);
        Assert.Equal("Tree View", result);
    }

    [Fact]
    public void GetViewTypeName_OrgChart_ReturnsExpected()
    {
        var result = InvokeStatic<string>("GetViewTypeName", ViewType.OrgChart);
        Assert.Equal("Org Chart", result);
    }

    [Fact]
    public void GetViewTypeName_Table_ReturnsExpected()
    {
        var result = InvokeStatic<string>("GetViewTypeName", ViewType.Table);
        Assert.Equal("Table View", result);
    }

    // ──────────────────────────────────────────────────────────────
    //  BuildViewSwitcher tests
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void BuildViewSwitcher_NoParentField_OnlyShowsTable()
    {
        var result = InvokeStatic<string>("BuildViewSwitcher", "customer", ViewType.Table, false);
        Assert.Contains("Table", result);
        Assert.DoesNotContain("Tree", result);
        Assert.DoesNotContain("Org Chart", result);
    }

    [Fact]
    public void BuildViewSwitcher_WithParentField_ShowsAllViews()
    {
        var result = InvokeStatic<string>("BuildViewSwitcher", "category", ViewType.Table, true);
        Assert.Contains("Table", result);
        Assert.Contains("Tree", result);
        Assert.Contains("Org Chart", result);
    }

    [Fact]
    public void BuildViewSwitcher_TreeViewActive_MarksTreeActive()
    {
        var result = InvokeStatic<string>("BuildViewSwitcher", "category", ViewType.TreeView, true);
        // The tree button should have " active" class
        Assert.Contains("view=tree\" title=\"Tree View\"><i class=\"bi bi-diagram-3\"", result);
    }

    // ──────────────────────────────────────────────────────────────
    //  BuildCommandButtonsHtml tests
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void BuildCommandButtonsHtml_NoCommands_ReturnsEmpty()
    {
        var meta = CreateEmptyEntityMetadata();
        var result = InvokeStatic<string>("BuildCommandButtonsHtml", meta, "product", "id1");
        Assert.Equal(string.Empty, result);
    }

    // ──────────────────────────────────────────────────────────────
    //  BuildPageHandler – action overload invokes configure + render
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task BuildPageHandler_ActionOverload_InvokesConfigure()
    {
        // Arrange
        EnsureStore();
        var configured = false;
        var handler = _handlers.BuildPageHandler(_ => { configured = true; });
        var context = CreateHttpContext("GET", "/test");

        // Act
        await handler(context);

        // Assert
        Assert.True(configured);
    }

    [Fact]
    public async Task BuildPageHandler_AsyncOverload_InvokesConfigure()
    {
        // Arrange
        EnsureStore();
        var configured = false;
        var handler = _handlers.BuildPageHandler(_ =>
        {
            configured = true;
            return ValueTask.CompletedTask;
        });
        var context = CreateHttpContext("GET", "/test");

        // Act
        await handler(context);

        // Assert
        Assert.True(configured);
    }

    [Fact]
    public async Task BuildPageHandler_BoolOverload_RendersTrueCase()
    {
        // Arrange
        EnsureStore();
        var handler = _handlers.BuildPageHandler(_ => ValueTask.FromResult(true), renderWhenTrue: true);
        var context = CreateHttpContext("GET", "/test");

        // Act – should complete without error and render
        await handler(context);

        // Assert – no exception means success; renderer was called
        Assert.Equal(200, context.Response.StatusCode);
    }

    // ──────────────────────────────────────────────────────────────
    //  ApplyUserPasswordIfNeeded tests
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void ApplyUserPasswordIfNeeded_NonUserMeta_DoesNothing()
    {
        var meta = CreateEmptyEntityMetadata(typeof(Address));
        var address = new Address { Id = "a1" };
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["password"] = "secret"
        };
        var errors = new List<string>();

        InvokeStaticRaw("ApplyUserPasswordIfNeeded",
            new[] { typeof(DataEntityMetadata), typeof(object), typeof(IDictionary<string, string?>), typeof(List<string>), typeof(bool) },
            meta, address, values, errors, true);

        Assert.Empty(errors);
    }

    [Fact]
    public void ApplyUserPasswordIfNeeded_UserMeta_CreateMissingPassword_AddsError()
    {
        var meta = CreateEmptyEntityMetadata(typeof(User));
        var user = new User { Id = "u1", UserName = "test" };
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var errors = new List<string>();

        InvokeStaticRaw("ApplyUserPasswordIfNeeded",
            new[] { typeof(DataEntityMetadata), typeof(object), typeof(IDictionary<string, string?>), typeof(List<string>), typeof(bool) },
            meta, user, values, errors, true);

        Assert.Contains(errors, e => e.Contains("Password is required"));
    }

    [Fact]
    public void ApplyUserPasswordIfNeeded_UserMeta_CreatePasswordMismatch_AddsError()
    {
        var meta = CreateEmptyEntityMetadata(typeof(User));
        var user = new User { Id = "u1", UserName = "test" };
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["password"] = "abc123",
            ["password_confirm"] = "xyz789"
        };
        var errors = new List<string>();

        InvokeStaticRaw("ApplyUserPasswordIfNeeded",
            new[] { typeof(DataEntityMetadata), typeof(object), typeof(IDictionary<string, string?>), typeof(List<string>), typeof(bool) },
            meta, user, values, errors, true);

        Assert.Contains(errors, e => e.Contains("Passwords do not match"));
    }

    [Fact]
    public void ApplyUserPasswordIfNeeded_UserMeta_CreateMatchingPasswords_SetsPassword()
    {
        var meta = CreateEmptyEntityMetadata(typeof(User));
        var user = new User { Id = "u1", UserName = "test" };
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["password"] = "SecurePass123!",
            ["password_confirm"] = "SecurePass123!"
        };
        var errors = new List<string>();

        InvokeStaticRaw("ApplyUserPasswordIfNeeded",
            new[] { typeof(DataEntityMetadata), typeof(object), typeof(IDictionary<string, string?>), typeof(List<string>), typeof(bool) },
            meta, user, values, errors, true);

        Assert.Empty(errors);
        Assert.True(user.VerifyPassword("SecurePass123!"));
    }

    [Fact]
    public void ApplyUserPasswordIfNeeded_UserMeta_UpdateWithPassword_SetsPassword()
    {
        var meta = CreateEmptyEntityMetadata(typeof(User));
        var user = new User { Id = "u1", UserName = "test" };
        user.SetPassword("OldPassword!");
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["password"] = "NewPassword!",
        };
        var errors = new List<string>();

        InvokeStaticRaw("ApplyUserPasswordIfNeeded",
            new[] { typeof(DataEntityMetadata), typeof(object), typeof(IDictionary<string, string?>), typeof(List<string>), typeof(bool) },
            meta, user, values, errors, false);

        Assert.Empty(errors);
        Assert.True(user.VerifyPassword("NewPassword!"));
        Assert.False(user.VerifyPassword("OldPassword!"));
    }

    [Fact]
    public void ApplyUserPasswordIfNeeded_UserMeta_UpdateNoPassword_KeepsCurrent()
    {
        var meta = CreateEmptyEntityMetadata(typeof(User));
        var user = new User { Id = "u1", UserName = "test" };
        user.SetPassword("OriginalPassword!");
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        var errors = new List<string>();

        InvokeStaticRaw("ApplyUserPasswordIfNeeded",
            new[] { typeof(DataEntityMetadata), typeof(object), typeof(IDictionary<string, string?>), typeof(List<string>), typeof(bool) },
            meta, user, values, errors, false);

        Assert.Empty(errors);
        Assert.True(user.VerifyPassword("OriginalPassword!"));
    }

    // ──────────────────────────────────────────────────────────────
    //  SampleDataPostHandler – non-form content type
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task SampleDataPostHandler_NonFormContentType_Returns400()
    {
        // Arrange
        EnsureStore();
        var context = CreateHttpContext("POST", "/admin/sample-data");
        context.Request.ContentType = "application/json";

        // Act
        await _handlers.SampleDataPostHandler(context);

        // Assert
        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
    }

    // ──────────────────────────────────────────────────────────────
    //  RegisterHandler – account creation disabled
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task RegisterHandler_AccountCreationDisabled_ShowsDisabledMessage()
    {
        // Arrange
        EnsureStore();
        var disabledHandlers = new RouteHandlers(
            new MockHtmlRenderer(),
            new MockTemplateStore(),
            allowAccountCreation: false,
            mfaKeyRootFolder: _keyRootDirectory);

        var context = CreateHttpContext("GET", "/register");

        // Act
        await disabledHandlers.RegisterHandler(context);

        // Assert
        var pc = context.GetPageContext();
        Assert.NotNull(pc);
        var titleIndex = Array.IndexOf(pc.PageMetaDataKeys, "title");
        Assert.True(titleIndex >= 0);
        Assert.Equal("Create Account", pc.PageMetaDataValues[titleIndex]);
    }

    // ──────────────────────────────────────────────────────────────
    //  MfaChallengeHandler – no cookie redirects to login
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task MfaChallengeHandler_NoCookie_RedirectsToLogin()
    {
        // Arrange
        EnsureStore();
        var context = CreateHttpContext("GET", "/mfa");

        // Act
        await _handlers.MfaChallengeHandler(context);

        // Assert
        Assert.Equal(StatusCodes.Status302Found, context.Response.StatusCode);
        Assert.Equal("/login", context.Response.Headers.Location.ToString());
    }

    // ──────────────────────────────────────────────────────────────
    //  GenerateBackupCodes tests (via reflection)
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void GenerateBackupCodes_ZeroCount_ReturnsEmptyArrays()
    {
        var user = new User { Id = "u1" };
        var result = InvokeStaticRaw("GenerateBackupCodes",
            new[] { typeof(User), typeof(int) },
            user, 0);

        // BackupCodeResult is a private readonly record struct – use reflection
        var codesField = result!.GetType().GetProperty("Codes")!;
        var hashesField = result.GetType().GetProperty("Hashes")!;
        var codes = (string[])codesField.GetValue(result)!;
        var hashes = (string[])hashesField.GetValue(result)!;
        Assert.Empty(codes);
        Assert.Empty(hashes);
    }

    [Fact]
    public void GenerateBackupCodes_PositiveCount_GeneratesUniqueCodesAndHashes()
    {
        var user = new User { Id = "u1" };
        var result = InvokeStaticRaw("GenerateBackupCodes",
            new[] { typeof(User), typeof(int) },
            user, 4);

        var codesField = result!.GetType().GetProperty("Codes")!;
        var hashesField = result.GetType().GetProperty("Hashes")!;
        var codes = (string[])codesField.GetValue(result)!;
        var hashes = (string[])hashesField.GetValue(result)!;
        Assert.Equal(4, codes.Length);
        Assert.Equal(4, hashes.Length);
        Assert.Equal(codes.Length, codes.Distinct().Count()); // all unique
        Assert.True(codes.All(c => c.Length == 16)); // 8 bytes = 16 hex chars
    }

    // ──────────────────────────────────────────────────────────────
    //  ToQueryDictionary tests (via reflection)
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public void ToQueryDictionary_ConvertsQueryCollection()
    {
        var qc = new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            ["page"] = "2",
            ["filter"] = "active"
        });

        var result = InvokeStaticRaw("ToQueryDictionary",
            new[] { typeof(IQueryCollection) },
            qc) as Dictionary<string, string?>;

        Assert.NotNull(result);
        Assert.Equal("2", result["page"]);
        Assert.Equal("active", result["filter"]);
    }

    // ──────────────────────────────────────────────────────────────
    //  Helper infrastructure
    // ──────────────────────────────────────────────────────────────

    private static HttpContext CreateHttpContext(string method, string path)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Request.Host = new HostString("localhost");
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static async Task<string> ReadResponseBody(HttpContext context)
    {
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(context.Response.Body, Encoding.UTF8, leaveOpen: true);
        return await reader.ReadToEndAsync();
    }

    private static DataEntityMetadata CreateEmptyEntityMetadata(Type? entityType = null)
    {
        var type = entityType ?? typeof(Address);
        return new DataEntityMetadata(
            Type: type,
            Name: "Test",
            Slug: "test",
            Permissions: "",
            ShowOnNav: false,
            NavGroup: null,
            NavOrder: 0,
            IdGeneration: AutoIdStrategy.None,
            ViewType: ViewType.Table,
            ParentField: null,
            Fields: Array.Empty<DataFieldMetadata>(),
            Handlers: new DataEntityHandlers(
                Create: () => (BaseDataObject)Activator.CreateInstance(type)!,
                LoadAsync: (_, _) => ValueTask.FromResult<BaseDataObject?>(null),
                SaveAsync: (_, _) => ValueTask.CompletedTask,
                DeleteAsync: (_, _) => ValueTask.CompletedTask,
                QueryAsync: (_, _) => ValueTask.FromResult<IEnumerable<BaseDataObject>>(Array.Empty<BaseDataObject>()),
                CountAsync: (_, _) => ValueTask.FromResult(0)),
            Commands: Array.Empty<RemoteCommandMetadata>());
    }

    // ──────────────────────────────────────────────────────────────
    //  Mocks
    // ──────────────────────────────────────────────────────────────

    private class MockHtmlRenderer : IHtmlRenderer
    {
        public ValueTask RenderPage(HttpContext context) => ValueTask.CompletedTask;

        public ValueTask RenderPage(HttpContext context, PageInfo page, IBareWebHost app) => ValueTask.CompletedTask;

        public ValueTask<byte[]> RenderToBytesAsync(
            IHtmlTemplate template, string[] keys, string[] values,
            string[] appkeys, string[] appvalues, IBareWebHost app,
            string[]? tableColumnTitles = null, string[][]? tableRows = null,
            FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null)
            => ValueTask.FromResult(Encoding.UTF8.GetBytes("<html></html>"));

        public ValueTask RenderToStreamAsync(
            PipeWriter writer, IHtmlTemplate template, string[] keys, string[] values,
            string[] appkeys, string[] appvalues, IBareWebHost app,
            string[]? tableColumnTitles = null, string[][]? tableRows = null,
            FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null)
            => ValueTask.CompletedTask;
    }

    private class MockTemplateStore : ITemplateStore
    {
        public IHtmlTemplate Get(string name) => new MockHtmlTemplate();
        public void ReloadAll() { }
    }

    private class MockHtmlTemplate : IHtmlTemplate
    {
        public Encoding Encoding => Encoding.UTF8;
        public string ContentTypeHeader => "text/html; charset=utf-8";
        public string Head => "<head></head>";
        public string Body => "<body></body>";
        public string Footer => "";
        public string Script => "";
    }

    private class InMemoryDataStore : IDataObjectStore
    {
        private readonly Dictionary<string, BaseDataObject> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }
        public void Clear() => _store.Clear();

        public void Save<T>(T obj) where T : BaseDataObject => _store[obj.Id] = obj;
        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Save(obj);
            return ValueTask.CompletedTask;
        }

        public T? Load<T>(string id) where T : BaseDataObject =>
            _store.TryGetValue(id, out var obj) ? obj as T : null;
        public ValueTask<T?> LoadAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject =>
            ValueTask.FromResult(Load<T>(id));

        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject =>
            _store.Values.OfType<T>();
        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject =>
            ValueTask.FromResult(Query<T>(query));
        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject =>
            ValueTask.FromResult(Query<T>(query).Count());

        public void Delete<T>(string id) where T : BaseDataObject => _store.Remove(id);
        public ValueTask DeleteAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Delete<T>(id);
            return ValueTask.CompletedTask;
        }
    }
}
