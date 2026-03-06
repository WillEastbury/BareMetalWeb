using System.Reflection;
using System.Threading;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Rendering;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Tests for authorization logic in BareMetalWebServer.IsAuthorized method.
/// These tests validate that empty permissions allow public access (fix for blank permissions issue).
/// </summary>
[Collection("SharedState")]
public class AuthorizationTests : IClassFixture<DataStoreFixture>
{
    private readonly DataStoreFixture _fixture;

    public AuthorizationTests(DataStoreFixture fixture)
    {
        _fixture = fixture;
    }
    [Fact]
    public void IsAuthorized_NullPageInfo_ReturnsTrue()
    {
        // Arrange
        PageInfo? pageInfo = null;
        var context = CreateMockHttpContext();

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "Null PageInfo should allow access");
    }

    [Fact]
    public void IsAuthorized_EmptyPermissions_AnonymousUser_ReturnsTrue()
    {
        // Arrange - Empty string permissions should mean public access
        var pageInfo = CreatePageInfo(permissionsNeeded: "");
        var context = CreateMockHttpContext(user: null); // Anonymous user

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "Empty permissions should allow anonymous access");
    }

    [Fact]
    public void IsAuthorized_EmptyPermissions_AuthenticatedUser_ReturnsTrue()
    {
        // Arrange - Empty string permissions should mean public access
        var pageInfo = CreatePageInfo(permissionsNeeded: "");
        var user = CreateUser(1, new[] { "Admin" });
        var context = CreateMockHttpContext(user: user);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "Empty permissions should allow authenticated user access");
    }

    [Fact]
    public void IsAuthorized_WhitespacePermissions_ReturnsTrue()
    {
        // Arrange - Whitespace permissions should be treated as empty
        var pageInfo = CreatePageInfo(permissionsNeeded: "   ");
        var context = CreateMockHttpContext(user: null);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "Whitespace permissions should allow access");
    }

    [Fact]
    public void IsAuthorized_PublicPermission_AnonymousUser_ReturnsTrue()
    {
        // Arrange
        var pageInfo = CreatePageInfo(permissionsNeeded: "Public");
        var context = CreateMockHttpContext(user: null);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "Public permission should allow anonymous access");
    }

    [Fact]
    public void IsAuthorized_PublicPermission_AuthenticatedUser_ReturnsTrue()
    {
        // Arrange
        var pageInfo = CreatePageInfo(permissionsNeeded: "Public");
        var user = CreateUser(1, Array.Empty<string>());
        var context = CreateMockHttpContext(user: user);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "Public permission should allow authenticated user access");
    }

    [Fact]
    public void IsAuthorized_AnonymousOnlyPermission_AnonymousUser_ReturnsTrue()
    {
        // Arrange
        var pageInfo = CreatePageInfo(permissionsNeeded: "AnonymousOnly");
        var context = CreateMockHttpContext(user: null);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "AnonymousOnly permission should allow anonymous access");
    }

    [Fact]
    public void IsAuthorized_AnonymousOnlyPermission_AuthenticatedUser_ReturnsFalse()
    {
        // Arrange
        var pageInfo = CreatePageInfo(permissionsNeeded: "AnonymousOnly");
        var user = CreateUser(1, Array.Empty<string>());
        var context = CreateMockHttpContext(user: user);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.False(result, "AnonymousOnly permission should deny authenticated user access");
    }

    [Fact]
    public void IsAuthorized_AuthenticatedPermission_AnonymousUser_ReturnsFalse()
    {
        // Arrange
        var pageInfo = CreatePageInfo(permissionsNeeded: "Authenticated");
        var context = CreateMockHttpContext(user: null);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.False(result, "Authenticated permission should deny anonymous access");
    }

    [Fact]
    public void IsAuthorized_AuthenticatedPermission_AuthenticatedUser_ReturnsTrue()
    {
        // Arrange
        var pageInfo = CreatePageInfo(permissionsNeeded: "Authenticated");
        var user = CreateUser(1, Array.Empty<string>());
        var context = CreateMockHttpContext(user: user);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "Authenticated permission should allow any authenticated user");
    }

    [Fact]
    public void IsAuthorized_SpecificPermission_UserWithPermission_ReturnsTrue()
    {
        // Arrange
        var pageInfo = CreatePageInfo(permissionsNeeded: "Admin");
        var user = CreateUser(1, new[] { "Admin", "Editor" });
        var context = CreateMockHttpContext(user: user);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "User with required permission should be authorized");
    }

    [Fact]
    public void IsAuthorized_SpecificPermission_UserWithoutPermission_ReturnsFalse()
    {
        // Arrange
        var pageInfo = CreatePageInfo(permissionsNeeded: "Admin");
        var user = CreateUser(1, new[] { "Editor", "Viewer" });
        var context = CreateMockHttpContext(user: user);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.False(result, "User without required permission should be denied");
    }

    [Fact]
    public void IsAuthorized_SpecificPermission_AnonymousUser_ReturnsFalse()
    {
        // Arrange
        var pageInfo = CreatePageInfo(permissionsNeeded: "Admin");
        var context = CreateMockHttpContext(user: null);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.False(result, "Anonymous user should be denied when specific permission is required");
    }

    [Fact]
    public void IsAuthorized_MultiplePermissions_UserWithAllPermissions_ReturnsTrue()
    {
        // Arrange
        var pageInfo = CreatePageInfo(permissionsNeeded: "Admin, Editor");
        var user = CreateUser(1, new[] { "Admin", "Editor", "Viewer" });
        var context = CreateMockHttpContext(user: user);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "User with all required permissions should be authorized");
    }

    [Fact]
    public void IsAuthorized_MultiplePermissions_UserWithSomePermissions_ReturnsFalse()
    {
        // Arrange
        var pageInfo = CreatePageInfo(permissionsNeeded: "Admin, Editor");
        var user = CreateUser(1, new[] { "Admin", "Viewer" }); // Missing Editor
        var context = CreateMockHttpContext(user: user);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.False(result, "User missing any required permission should be denied");
    }

    [Fact]
    public void IsAuthorized_PermissionsCaseInsensitive_ReturnsTrue()
    {
        // Arrange
        var pageInfo = CreatePageInfo(permissionsNeeded: "ADMIN");
        var user = CreateUser(1, new[] { "admin" }); // Lowercase
        var context = CreateMockHttpContext(user: user);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "Permission comparison should be case-insensitive");
    }

    [Fact]
    public void IsAuthorized_PermissionsWithWhitespace_ReturnsTrue()
    {
        // Arrange - Permissions split with whitespace should be trimmed
        var pageInfo = CreatePageInfo(permissionsNeeded: "Admin , Editor , Viewer");
        var user = CreateUser(1, new[] { "Admin", "Editor", "Viewer" });
        var context = CreateMockHttpContext(user: user);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "Permissions with whitespace should be trimmed and matched");
    }

    [Fact]
    public void IsAuthorized_OnlyCommasNoPermissions_ReturnsTrue()
    {
        // Arrange - After splitting and trimming, no actual permissions remain
        var pageInfo = CreatePageInfo(permissionsNeeded: ", , ,");
        var context = CreateMockHttpContext(user: null);

        // Act
        var result = InvokeIsAuthorized(pageInfo, context);

        // Assert
        Assert.True(result, "Permissions that resolve to empty after splitting should allow access");
    }

    // Helper methods

    private static bool InvokeIsAuthorized(PageInfo? pageInfo, HttpContext context)
    {
        var method = typeof(BareMetalWebServer).GetMethod("IsAuthorizedAsync",
            BindingFlags.NonPublic | BindingFlags.Static);
        
        if (method == null)
            throw new InvalidOperationException("Could not find IsAuthorizedAsync method via reflection");

        var bmwCtx = BmwContext.CreateFrom(context, null!);
        var task = (ValueTask<bool>)method.Invoke(null, new object?[] { pageInfo, bmwCtx, CancellationToken.None })!;
        return task.AsTask().GetAwaiter().GetResult();
    }

    private static PageInfo CreatePageInfo(string permissionsNeeded)
    {
        var template = new MockHtmlTemplate();
        var metadata = new PageMetaData(
            Template: template,
            StatusCode: 200,
            PermissionsNeeded: permissionsNeeded
        );
        
        var pageContext = new PageContext(
            PageMetaDataKeys: Array.Empty<string>(),
            PageMetaDataValues: Array.Empty<string>()
        );
        
        return new PageInfo(metadata, pageContext);
    }

    private HttpContext CreateMockHttpContext(User? user = null)
    {
        // Ensure our fixture's store is active (guards against parallel test swaps)
        DataStoreProvider.Current = _fixture.Store;

        var context = new DefaultHttpContext();
        
        if (user != null)
        {
            // Create a session and set it up properly
            // Save the user to the data store
            DataStoreProvider.Current.Save(user);
            
            // Create a session for the user
            var session = new UserSession
            {
                UserId = user.Key.ToString(),
                IssuedUtc = DateTime.UtcNow,
                LastSeenUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddHours(8),
                IsRevoked = false
            };
            DataStoreProvider.Current.Save(session);
            
            // Set the session cookie
            var protectedSessionId = CookieProtection.Protect(session.Key.ToString());
            context.Request.Headers.Cookie = $"{UserAuth.SessionCookieName}={protectedSessionId}";
        }
        
        return context;
    }

    private static User CreateUser(uint key, string[] permissions)
    {
        return new User
        {
            Key = key,
            UserName = $"user_{key}",
            DisplayName = $"User {key}",
            Email = $"{key}@example.com",
            Permissions = permissions,
            IsActive = true
        };
    }

    // Mock template for testing
    private class MockHtmlTemplate : BareMetalWeb.Interfaces.IHtmlTemplate
    {
        public System.Text.Encoding Encoding => System.Text.Encoding.UTF8;
        public string ContentTypeHeader => "text/html; charset=utf-8";
        public string Head => "<head><title>Mock</title></head>";
        public string Body => "<body>Mock</body>";
        public string Footer => "<footer>Mock</footer>";
        public string Script => "<script>/* mock */</script>";
    }
}

/// <summary>
/// xUnit fixture to initialize the DataStoreProvider once for all AuthorizationTests.
/// Uses an InMemoryDataStore to avoid race conditions with other test classes
/// that also swap DataStoreProvider.Current during parallel execution.
/// </summary>
public class DataStoreFixture : IDisposable
{
    private readonly IDataObjectStore _originalStore;
    public IDataObjectStore Store { get; }

    public DataStoreFixture()
    {
        _originalStore = DataStoreProvider.Current;
        Store = new InMemoryDataStore();
        DataStoreProvider.Current = Store;
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
    }

    private class InMemoryDataStore : IDataObjectStore
    {
        private readonly Dictionary<(Type, uint), BaseDataObject> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();

        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        public void Save<T>(T obj) where T : BaseDataObject
        {
            _store[(typeof(T), obj.Key)] = obj;
        }

        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Save(obj);
            return ValueTask.CompletedTask;
        }

        public T? Load<T>(uint key) where T : BaseDataObject
        {
            return _store.TryGetValue((typeof(T), key), out var obj) ? obj as T : null;
        }

        public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            return ValueTask.FromResult(Load<T>(key));
        }

        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
        {
            foreach (var obj in _store.Values)
            {
                if (obj is T typedObj)
                    yield return typedObj;
            }
        }

        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            return ValueTask.FromResult(Query<T>(query));
        }

        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            return ValueTask.FromResult(Query<T>(query).Count());
        }

        public void Delete<T>(uint key) where T : BaseDataObject
        {
            _store.Remove((typeof(T), key));
        }

        public ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Delete<T>(key);
            return ValueTask.CompletedTask;
        }
    }
}
