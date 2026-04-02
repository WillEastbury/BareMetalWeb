using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Host;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host.Tests;

[Collection("SharedState")]
public class UserAuthTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;
    private readonly IDataObjectStore _testStore;

    public UserAuthTests()
    {
        _originalStore = DataStoreProvider.Current;
        _testStore = new InMemoryDataStore();
        DataStoreProvider.Current = _testStore;
    }

    [Fact]
    public async Task GetRequestUserAsync_BearerTokenHeader_ResolvesApiKey()
    {
        // Arrange
        EnsureStore();
        var rawKey = "test-bearer-key-12345";
        var principal = SystemEntitySchemas.SystemPrincipal.CreateRecord();
        principal.SetFieldValue(UserFields.UserName, "chatgpt");
        principal.SetFieldValue(UserFields.DisplayName, "ChatGPT");
        principal.SetFieldValue(UserFields.IsActive, true);
        SystemPrincipalHelper.AddApiKey(principal, rawKey, iterations: 1);
        await DataStoreProvider.Current.SaveAsync(principal.EntityTypeName, principal);

        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = $"Bearer {rawKey}";
        context.Request.Path = "/api/to-do";

        // Act
        var user = await UserAuth.GetRequestUserAsync(context.ToBmw());

        // Assert
        Assert.NotNull(user);
        Assert.Equal("chatgpt", user.GetFieldValue(UserFields.UserName)?.ToString());
    }

    [Fact]
    public async Task HasValidApiKeyAsync_ValidBearerToken_ReturnsTrue()
    {
        // Arrange
        EnsureStore();
        var rawKey = "bearer-valid-key-abc";
        var principal = SystemEntitySchemas.SystemPrincipal.CreateRecord();
        principal.SetFieldValue(UserFields.UserName, "external-client");
        principal.SetFieldValue(UserFields.DisplayName, "External Client");
        principal.SetFieldValue(UserFields.IsActive, true);
        SystemPrincipalHelper.AddApiKey(principal, rawKey, iterations: 1);
        await DataStoreProvider.Current.SaveAsync(principal.EntityTypeName, principal);

        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = $"Bearer {rawKey}";
        context.Request.Path = "/api/to-do";

        // Act
        var result = await UserAuth.HasValidApiKeyAsync(context.ToBmw());

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task HasValidApiKeyAsync_InvalidBearerToken_ReturnsFalse()
    {
        // Arrange
        EnsureStore();
        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = "Bearer invalid-key-xyz";
        context.Request.Path = "/api/to-do";

        // Act
        var result = await UserAuth.HasValidApiKeyAsync(context.ToBmw());

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task HasValidApiKeyAsync_NoAuthHeader_ReturnsFalse()
    {
        // Arrange
        EnsureStore();
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/to-do";

        // Act
        var result = await UserAuth.HasValidApiKeyAsync(context.ToBmw());

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task HasValidApiKeyAsync_ValidApiKeyHeader_ReturnsTrue()
    {
        // Arrange
        EnsureStore();
        var rawKey = "apikey-header-test-999";
        var principal = SystemEntitySchemas.SystemPrincipal.CreateRecord();
        principal.SetFieldValue(UserFields.UserName, "cli-client");
        principal.SetFieldValue(UserFields.DisplayName, "CLI Client");
        principal.SetFieldValue(UserFields.IsActive, true);
        SystemPrincipalHelper.AddApiKey(principal, rawKey, iterations: 1);
        await DataStoreProvider.Current.SaveAsync(principal.EntityTypeName, principal);

        var context = new DefaultHttpContext();
        context.Request.Headers["ApiKey"] = rawKey;
        context.Request.Path = "/api/to-do";

        // Act
        var result = await UserAuth.HasValidApiKeyAsync(context.ToBmw());

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task HasValidApiKeyAsync_InactiveApiKeyPrincipal_ReturnsFalse()
    {
        // Arrange
        EnsureStore();
        var rawKey = "inactive-principal-key";
        var principal = SystemEntitySchemas.SystemPrincipal.CreateRecord();
        principal.SetFieldValue(UserFields.UserName, "inactive-client");
        principal.SetFieldValue(UserFields.DisplayName, "Inactive Client");
        principal.SetFieldValue(UserFields.IsActive, false);
        SystemPrincipalHelper.AddApiKey(principal, rawKey, iterations: 1);
        await DataStoreProvider.Current.SaveAsync(principal.EntityTypeName, principal);

        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = $"Bearer {rawKey}";
        context.Request.Path = "/api/to-do";

        // Act
        var result = await UserAuth.HasValidApiKeyAsync(context.ToBmw());

        // Assert
        Assert.False(result);
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
    }

    private void EnsureStore()
    {
        DataStoreProvider.Current = _testStore;
    }

    [Fact]
    public async Task GetSessionAsync_ActiveSession_ExtendsExpirationTime()
    {
        // Arrange
        EnsureStore();
        var now = DateTime.UtcNow;
        var session = SystemEntitySchemas.UserSession.CreateRecord();
        UserSessionHelper.SetUserId(session, "user123");
        UserSessionHelper.SetUserName(session, "testuser");
        UserSessionHelper.SetDisplayName(session, "Test User");
        UserSessionHelper.SetPermissions(session, Array.Empty<string>());
        UserSessionHelper.SetIssuedUtc(session, now.AddHours(-2));
        UserSessionHelper.SetLastSeenUtc(session, now.AddHours(-1));
        UserSessionHelper.SetExpiresUtc(session, now.AddHours(6)); // 8 hours from issue - 2 hours ago = 6 hours left
        UserSessionHelper.SetRememberMe(session, false);
        UserSessionHelper.SetIsRevoked(session, false);
        session.CreatedBy = "testuser";
        session.UpdatedBy = "testuser";

        await DataStoreProvider.Current.SaveAsync(session.EntityTypeName, session);

        var context = CreateHttpContext(session.Key.ToString());
        var originalExpiresUtc = UserSessionHelper.GetExpiresUtc(session);
        var originalLastSeenUtc = UserSessionHelper.GetLastSeenUtc(session);

        // Act
        var result = await UserAuth.GetSessionAsync(context.ToBmw());

        // Assert
        Assert.NotNull(result);
        Assert.Equal(session.Key, result.Key);

        // Reload session to check if it was updated
        var updatedSession = await DataStoreProvider.Current.LoadAsync("UserSession", session.Key);
        Assert.NotNull(updatedSession);
        
        // LastSeenUtc should be updated to now (or very close)
        Assert.True(UserSessionHelper.GetLastSeenUtc(updatedSession) > originalLastSeenUtc);
        Assert.True((DateTime.UtcNow - UserSessionHelper.GetLastSeenUtc(updatedSession)).TotalSeconds < 2); // within 2 seconds
        
        // ExpiresUtc should be extended (8 hours from LastSeenUtc for non-RememberMe)
        Assert.True(UserSessionHelper.GetExpiresUtc(updatedSession) > originalExpiresUtc);
        var expectedExpiration = UserSessionHelper.GetLastSeenUtc(updatedSession).AddHours(8);
        Assert.True((UserSessionHelper.GetExpiresUtc(updatedSession) - expectedExpiration).Duration().TotalSeconds < 2); // within 2 seconds
    }

    [Fact]
    public async Task GetSessionAsync_RememberMeSession_ExtendsWithRememberMeLifetime()
    {
        // Arrange
        EnsureStore();
        var now = DateTime.UtcNow;
        var session = SystemEntitySchemas.UserSession.CreateRecord();
        UserSessionHelper.SetUserId(session, "user123");
        UserSessionHelper.SetUserName(session, "testuser");
        UserSessionHelper.SetDisplayName(session, "Test User");
        UserSessionHelper.SetPermissions(session, Array.Empty<string>());
        UserSessionHelper.SetIssuedUtc(session, now.AddDays(-5));
        UserSessionHelper.SetLastSeenUtc(session, now.AddDays(-1));
        UserSessionHelper.SetExpiresUtc(session, now.AddDays(25)); // 30 days from issue - 5 days ago = 25 days left
        UserSessionHelper.SetRememberMe(session, true);
        UserSessionHelper.SetIsRevoked(session, false);
        session.CreatedBy = "testuser";
        session.UpdatedBy = "testuser";

        await DataStoreProvider.Current.SaveAsync(session.EntityTypeName, session);

        var context = CreateHttpContext(session.Key.ToString());
        var originalExpiresUtc = UserSessionHelper.GetExpiresUtc(session);

        // Act
        var result = await UserAuth.GetSessionAsync(context.ToBmw());

        // Assert
        Assert.NotNull(result);

        // Reload session to check if it was updated
        var updatedSession = await DataStoreProvider.Current.LoadAsync("UserSession", session.Key);
        Assert.NotNull(updatedSession);
        
        // ExpiresUtc should be extended (30 days from LastSeenUtc for RememberMe)
        Assert.True(UserSessionHelper.GetExpiresUtc(updatedSession) > originalExpiresUtc);
        var expectedExpiration = UserSessionHelper.GetLastSeenUtc(updatedSession).AddDays(30);
        Assert.True((UserSessionHelper.GetExpiresUtc(updatedSession) - expectedExpiration).Duration().TotalSeconds < 2); // within 2 seconds
    }

    [Fact]
    public void GetSession_ActiveSession_ExtendsExpirationTime()
    {
        // Arrange
        EnsureStore();
        var now = DateTime.UtcNow;
        var session = SystemEntitySchemas.UserSession.CreateRecord();
        UserSessionHelper.SetUserId(session, "user123");
        UserSessionHelper.SetUserName(session, "testuser");
        UserSessionHelper.SetDisplayName(session, "Test User");
        UserSessionHelper.SetPermissions(session, Array.Empty<string>());
        UserSessionHelper.SetIssuedUtc(session, now.AddHours(-2));
        UserSessionHelper.SetLastSeenUtc(session, now.AddHours(-1));
        UserSessionHelper.SetExpiresUtc(session, now.AddHours(6));
        UserSessionHelper.SetRememberMe(session, false);
        UserSessionHelper.SetIsRevoked(session, false);
        session.CreatedBy = "testuser";
        session.UpdatedBy = "testuser";

        DataStoreProvider.Current.Save(session.EntityTypeName, session);

        var context = CreateHttpContext(session.Key.ToString());
        var originalExpiresUtc = UserSessionHelper.GetExpiresUtc(session);
        var originalLastSeenUtc = UserSessionHelper.GetLastSeenUtc(session);

        // Act
        var result = UserAuth.GetSession(context.ToBmw());

        // Assert
        Assert.NotNull(result);
        Assert.Equal(session.Key, result.Key);

        // Reload session to check if it was updated
        var updatedSession = DataStoreProvider.Current.Load("UserSession", session.Key);
        Assert.NotNull(updatedSession);
        
        // LastSeenUtc should be updated
        Assert.True(UserSessionHelper.GetLastSeenUtc(updatedSession) > originalLastSeenUtc);
        
        // ExpiresUtc should be extended
        Assert.True(UserSessionHelper.GetExpiresUtc(updatedSession) > originalExpiresUtc);
    }

    [Fact]
    public async Task GetSessionAsync_ExpiredSession_ReturnsNull()
    {
        // Arrange
        EnsureStore();
        var now = DateTime.UtcNow;
        var session = SystemEntitySchemas.UserSession.CreateRecord();
        UserSessionHelper.SetUserId(session, "user123");
        UserSessionHelper.SetUserName(session, "testuser");
        UserSessionHelper.SetDisplayName(session, "Test User");
        UserSessionHelper.SetPermissions(session, Array.Empty<string>());
        UserSessionHelper.SetIssuedUtc(session, now.AddHours(-10));
        UserSessionHelper.SetLastSeenUtc(session, now.AddHours(-9));
        UserSessionHelper.SetExpiresUtc(session, now.AddHours(-1)); // Expired 1 hour ago
        UserSessionHelper.SetRememberMe(session, false);
        UserSessionHelper.SetIsRevoked(session, false);
        session.CreatedBy = "testuser";
        session.UpdatedBy = "testuser";

        await DataStoreProvider.Current.SaveAsync(session.EntityTypeName, session);

        var context = CreateHttpContext(session.Key.ToString());

        // Act
        var result = await UserAuth.GetSessionAsync(context.ToBmw());

        // Assert
        Assert.Null(result);

        // Session should be marked as revoked
        var updatedSession = await DataStoreProvider.Current.LoadAsync("UserSession", session.Key);
        Assert.NotNull(updatedSession);
        Assert.True(UserSessionHelper.IsRevoked(updatedSession));
    }

    [Fact]
    public async Task GetSessionAsync_NoSession_ReturnsNull()
    {
        // Arrange
        EnsureStore();
        var context = CreateHttpContext(null);

        // Act
        var result = await UserAuth.GetSessionAsync(context.ToBmw());

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetSessionAsync_RecentlyExtendedSession_SkipsSave()
    {
        // Arrange
        EnsureStore();
        var now = DateTime.UtcNow;
        // Session was just created: ExpiresUtc is essentially now + 8h (< 1 minute elapsed since last extension)
        var session = SystemEntitySchemas.UserSession.CreateRecord();
        UserSessionHelper.SetUserId(session, "user123");
        UserSessionHelper.SetUserName(session, "testuser");
        UserSessionHelper.SetDisplayName(session, "Test User");
        UserSessionHelper.SetPermissions(session, Array.Empty<string>());
        UserSessionHelper.SetIssuedUtc(session, now);
        UserSessionHelper.SetLastSeenUtc(session, now);
        UserSessionHelper.SetExpiresUtc(session, now.AddHours(8)); // Just extended; newExpiry - ExpiresUtc ≈ 0 < 1 minute
        UserSessionHelper.SetRememberMe(session, false);
        UserSessionHelper.SetIsRevoked(session, false);
        session.CreatedBy = "testuser";
        session.UpdatedBy = "testuser";

        await DataStoreProvider.Current.SaveAsync(session.EntityTypeName, session);

        var context = CreateHttpContext(session.Key.ToString());
        var originalExpiresUtc = UserSessionHelper.GetExpiresUtc(session);

        // Act
        var result = await UserAuth.GetSessionAsync(context.ToBmw());

        // Assert — session returned successfully
        Assert.NotNull(result);
        Assert.Equal(session.Key, result.Key);

        // Session should NOT have been re-saved because the extension gain is < 1 minute
        var storedSession = await DataStoreProvider.Current.LoadAsync("UserSession", session.Key);
        Assert.NotNull(storedSession);
        Assert.Equal(originalExpiresUtc, UserSessionHelper.GetExpiresUtc(storedSession));
    }

    [Fact]
    public void GetSession_RecentlyExtendedSession_SkipsSave()
    {
        // Arrange
        EnsureStore();
        var now = DateTime.UtcNow;
        var session = SystemEntitySchemas.UserSession.CreateRecord();
        UserSessionHelper.SetUserId(session, "user123");
        UserSessionHelper.SetUserName(session, "testuser");
        UserSessionHelper.SetDisplayName(session, "Test User");
        UserSessionHelper.SetPermissions(session, Array.Empty<string>());
        UserSessionHelper.SetIssuedUtc(session, now);
        UserSessionHelper.SetLastSeenUtc(session, now);
        UserSessionHelper.SetExpiresUtc(session, now.AddHours(8));
        UserSessionHelper.SetRememberMe(session, false);
        UserSessionHelper.SetIsRevoked(session, false);
        session.CreatedBy = "testuser";
        session.UpdatedBy = "testuser";

        DataStoreProvider.Current.Save(session.EntityTypeName, session);

        var context = CreateHttpContext(session.Key.ToString());
        var originalExpiresUtc = UserSessionHelper.GetExpiresUtc(session);

        // Act
        var result = UserAuth.GetSession(context.ToBmw());

        // Assert — session returned successfully
        Assert.NotNull(result);

        // Session should NOT have been re-saved because the extension gain is < 1 minute
        var storedSession = DataStoreProvider.Current.Load("UserSession", session.Key);
        Assert.NotNull(storedSession);
        Assert.Equal(originalExpiresUtc, UserSessionHelper.GetExpiresUtc(storedSession));
    }

    [Fact]
    public async Task FindByEmailOrUserNameAsync_MultipleUsers_ReturnsCorrectUserByUsername()
    {
        // Arrange — two users with distinct credentials
        EnsureStore();
        var root = SystemEntitySchemas.User.CreateRecord();
        root.Key = 1;
        root.SetFieldValue(UserFields.UserName, "root");
        root.SetFieldValue(UserFields.DisplayName, "Root User");
        root.SetFieldValue(UserFields.Email, "root@example.com");
        root.SetFieldValue(UserFields.Permissions, new[] { "admin", "monitoring" });
        root.SetFieldValue(UserFields.IsActive, true);
        UserAuth.SetPassword(root, "rootpass");
        await DataStoreProvider.Current.SaveAsync(root.EntityTypeName, root);

        var secondUser = SystemEntitySchemas.User.CreateRecord();
        secondUser.Key = 2;
        secondUser.SetFieldValue(UserFields.UserName, "son");
        secondUser.SetFieldValue(UserFields.DisplayName, "Son User");
        secondUser.SetFieldValue(UserFields.Email, "son@example.com");
        secondUser.SetFieldValue(UserFields.Permissions, new[] { "user" });
        secondUser.SetFieldValue(UserFields.IsActive, true);
        UserAuth.SetPassword(secondUser, "sonpass");
        await DataStoreProvider.Current.SaveAsync(secondUser.EntityTypeName, secondUser);

        // Act — look up by username
        var foundRoot = await UserAuthHelper.FindUserByEmailOrUserNameAsync("root");
        var foundSon = await UserAuthHelper.FindUserByEmailOrUserNameAsync("son");

        // Assert — each lookup returns the correct user
        Assert.NotNull(foundRoot);
        Assert.Equal(root.Key, foundRoot.Key);
        Assert.Equal("root", foundRoot.GetFieldValue(UserFields.UserName)?.ToString());

        Assert.NotNull(foundSon);
        Assert.Equal(secondUser.Key, foundSon.Key);
        Assert.Equal("son", foundSon.GetFieldValue(UserFields.UserName)?.ToString());
    }

    [Fact]
    public async Task FindByEmailOrUserNameAsync_MultipleUsers_ReturnsCorrectUserByEmail()
    {
        // Arrange — two users with distinct credentials
        EnsureStore();
        var root = SystemEntitySchemas.User.CreateRecord();
        root.Key = 1;
        root.SetFieldValue(UserFields.UserName, "root");
        root.SetFieldValue(UserFields.DisplayName, "Root User");
        root.SetFieldValue(UserFields.Email, "root@example.com");
        root.SetFieldValue(UserFields.Permissions, new[] { "admin", "monitoring" });
        root.SetFieldValue(UserFields.IsActive, true);
        UserAuth.SetPassword(root, "rootpass");
        await DataStoreProvider.Current.SaveAsync(root.EntityTypeName, root);

        var secondUser = SystemEntitySchemas.User.CreateRecord();
        secondUser.Key = 2;
        secondUser.SetFieldValue(UserFields.UserName, "son");
        secondUser.SetFieldValue(UserFields.DisplayName, "Son User");
        secondUser.SetFieldValue(UserFields.Email, "son@example.com");
        secondUser.SetFieldValue(UserFields.Permissions, new[] { "user" });
        secondUser.SetFieldValue(UserFields.IsActive, true);
        UserAuth.SetPassword(secondUser, "sonpass");
        await DataStoreProvider.Current.SaveAsync(secondUser.EntityTypeName, secondUser);

        // Act — look up by email
        var foundRoot = await UserAuthHelper.FindUserByEmailOrUserNameAsync("root@example.com");
        var foundSon = await UserAuthHelper.FindUserByEmailOrUserNameAsync("son@example.com");

        // Assert — each lookup returns the correct user
        Assert.NotNull(foundRoot);
        Assert.Equal(root.Key, foundRoot.Key);

        Assert.NotNull(foundSon);
        Assert.Equal(secondUser.Key, foundSon.Key);
    }

    [Fact]
    public async Task FindByEmailOrUserNameAsync_SecondUserPresent_RootLoginNotAffected()
    {
        // Arrange — simulates the reported bug:
        // a second user is added; root must still be found by its own credentials
        EnsureStore();
        var root = SystemEntitySchemas.User.CreateRecord();
        root.Key = 1;
        root.SetFieldValue(UserFields.UserName, "admin");
        root.SetFieldValue(UserFields.DisplayName, "Administrator");
        root.SetFieldValue(UserFields.Email, "admin@example.com");
        root.SetFieldValue(UserFields.Permissions, new[] { "admin", "monitoring" });
        root.SetFieldValue(UserFields.IsActive, true);
        UserAuth.SetPassword(root, "AdminPass1!");
        await DataStoreProvider.Current.SaveAsync(root.EntityTypeName, root);

        var secondUser = SystemEntitySchemas.User.CreateRecord();
        secondUser.Key = 2;
        secondUser.SetFieldValue(UserFields.UserName, "son");
        secondUser.SetFieldValue(UserFields.DisplayName, "Son");
        secondUser.SetFieldValue(UserFields.Email, "son@example.com");
        secondUser.SetFieldValue(UserFields.Permissions, new[] { "user" });
        secondUser.SetFieldValue(UserFields.IsActive, true);
        UserAuth.SetPassword(secondUser, "SonPass1!");
        await DataStoreProvider.Current.SaveAsync(secondUser.EntityTypeName, secondUser);

        // Act — root login lookup after second user exists
        var found = await UserAuthHelper.FindUserByEmailOrUserNameAsync("admin");

        // Assert — root is found and its password still verifies correctly
        Assert.NotNull(found);
        Assert.Equal(root.Key, found.Key);
        Assert.True(UserAuth.VerifyPassword(found, "AdminPass1!"), "Root password should verify correctly");
        Assert.False(UserAuth.VerifyPassword(found, "SonPass1!"), "Second user password must not match root");
    }

    [Fact]
    public async Task FindByUserNameAsync_ReturnsNullForMissingUsername()
    {
        // Arrange
        EnsureStore();
        var user = SystemEntitySchemas.User.CreateRecord();
        user.SetFieldValue(UserFields.UserName, "existing");
        user.SetFieldValue(UserFields.Email, "existing@example.com");
        user.SetFieldValue(UserFields.IsActive, true);
        await DataStoreProvider.Current.SaveAsync(user.EntityTypeName, user);

        // Act
        var found = await UserAuthHelper.FindUserByUserNameAsync("nonexistent");

        // Assert
        Assert.Null(found);
    }

    [Fact]
    public async Task FindByEmailAsync_ReturnsNullForMissingEmail()
    {
        // Arrange
        EnsureStore();
        var user = SystemEntitySchemas.User.CreateRecord();
        user.SetFieldValue(UserFields.UserName, "test");
        user.SetFieldValue(UserFields.Email, "test@example.com");
        user.SetFieldValue(UserFields.IsActive, true);
        await DataStoreProvider.Current.SaveAsync(user.EntityTypeName, user);

        // Act
        var found = await UserAuthHelper.FindUserByEmailAsync("nobody@example.com");

        // Assert
        Assert.Null(found);
    }

    // ──────────────────────────────────────────────────────────────
    //  Clone uniqueness guard – regression for "Users TABLE STILL BROKEN"
    // ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task ExistsByEmailOrUserNameAsync_DuplicateUsername_ReturnsTrue()
    {
        // Arrange – simulate the state the clone operation would create
        EnsureStore();
        var original = SystemEntitySchemas.User.CreateRecord();
        original.SetFieldValue(UserFields.UserName, "admin");
        original.SetFieldValue(UserFields.Email, "admin@example.com");
        original.SetFieldValue(UserFields.IsActive, true);
        UserAuth.SetPassword(original, "AdminPass1!");
        await DataStoreProvider.Current.SaveAsync(original.EntityTypeName, original);

        // Act – the same username already exists; uniqueness check must catch it
        var exists = await UserAuthHelper.ExistsByEmailOrUserNameAsync("admin");

        // Assert – the guard should detect the conflict so no clone is saved
        Assert.True(exists);
    }

    [Fact]
    public async Task ExistsByEmailOrUserNameAsync_DuplicateEmail_ReturnsTrue()
    {
        // Arrange
        EnsureStore();
        var original = SystemEntitySchemas.User.CreateRecord();
        original.SetFieldValue(UserFields.UserName, "alice");
        original.SetFieldValue(UserFields.Email, "alice@example.com");
        original.SetFieldValue(UserFields.IsActive, true);
        UserAuth.SetPassword(original, "AlicePass1!");
        await DataStoreProvider.Current.SaveAsync(original.EntityTypeName, original);

        // Act
        var exists = await UserAuthHelper.ExistsByEmailOrUserNameAsync("alice@example.com");

        // Assert
        Assert.True(exists);
    }

    [Fact]
    public async Task FindByUserNameAsync_AfterSave_PasswordVerifiesCorrectly()
    {
        // Arrange – a saved user must be retrievable and its password must verify;
        // this guards against regressions where a phantom duplicate (e.g. from a bad clone)
        // could shadow the real record and cause login to fail.
        EnsureStore();
        var original = SystemEntitySchemas.User.CreateRecord();
        original.SetFieldValue(UserFields.UserName, "admin");
        original.SetFieldValue(UserFields.Email, "admin@example.com");
        original.SetFieldValue(UserFields.IsActive, true);
        UserAuth.SetPassword(original, "CorrectPass1!");
        await DataStoreProvider.Current.SaveAsync(original.EntityTypeName, original);

        // Act – lookup must return the record whose password verifies
        var found = await UserAuthHelper.FindUserByUserNameAsync("admin");

        // Assert
        Assert.NotNull(found);
        Assert.Equal(original.Key, found.Key);
        Assert.True(UserAuth.VerifyPassword(found, "CorrectPass1!"), "Original user password must verify correctly.");
    }

    private static HttpContext CreateHttpContext(string? sessionId)
    {
        var context = new DefaultHttpContext();
        
        if (!string.IsNullOrEmpty(sessionId))
        {
            // Simulate protected cookie value as it would appear in a real HTTP request
            // CookieProtection.Protect encrypts the session ID before storing it in the cookie
            var protectedSessionId = CookieProtection.Protect(sessionId);
            context.Request.Headers.Cookie = $"{UserAuth.SessionCookieName}={protectedSessionId}";
        }

        return context;
    }

    private class InMemoryDataStore : IDataObjectStore
    {
        private readonly Dictionary<(string, uint), DataRecord> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();

        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        // ── String-based CRUD ──────────────────────────────────────────
        public void Save(string entityTypeName, DataRecord obj)
        {
            _store[(entityTypeName, obj.Key)] = obj;
        }

        public ValueTask SaveAsync(string entityTypeName, DataRecord obj, CancellationToken cancellationToken = default)
        {
            Save(entityTypeName, obj);
            return ValueTask.CompletedTask;
        }

        public DataRecord? Load(string entityTypeName, uint key)
        {
            return _store.TryGetValue((entityTypeName, key), out var obj) ? obj : null;
        }

        public ValueTask<DataRecord?> LoadAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(Load(entityTypeName, key));
        }

        public IEnumerable<DataRecord> Query(string entityTypeName, QueryDefinition? query = null)
        {
            foreach (var kv in _store)
            {
                if (kv.Key.Item1 == entityTypeName)
                    yield return kv.Value;
            }
        }

        public ValueTask<IEnumerable<DataRecord>> QueryAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(Query(entityTypeName, query));
        }

        public ValueTask<int> CountAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(Query(entityTypeName, query).Count());
        }

        public void Delete(string entityTypeName, uint key)
        {
            _store.Remove((entityTypeName, key));
        }

        public ValueTask DeleteAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default)
        {
            Delete(entityTypeName, key);
            return ValueTask.CompletedTask;
        }

        // ── Ordinal-based (delegate to string-based) ───────────────────
        public void Save(int o, DataRecord obj) => Save(obj.EntityTypeName, obj);
        public DataRecord? Load(int o, uint k) => throw new NotSupportedException("Ordinal Load not supported in test store");
        public IEnumerable<DataRecord> Query(int o, QueryDefinition? q = null) => throw new NotSupportedException("Ordinal Query not supported in test store");
        public void Delete(int o, uint k) => throw new NotSupportedException("Ordinal Delete not supported in test store");
        public ValueTask SaveAsync(int o, DataRecord obj, CancellationToken ct = default) { Save(o, obj); return ValueTask.CompletedTask; }
        public ValueTask<DataRecord?> LoadAsync(int o, uint k, CancellationToken ct = default) => throw new NotSupportedException("Ordinal LoadAsync not supported in test store");
        public ValueTask<IEnumerable<DataRecord>> QueryAsync(int o, QueryDefinition? q = null, CancellationToken ct = default) => throw new NotSupportedException("Ordinal QueryAsync not supported in test store");
        public ValueTask<int> CountAsync(int o, QueryDefinition? q = null, CancellationToken ct = default) => throw new NotSupportedException("Ordinal CountAsync not supported in test store");
        public ValueTask DeleteAsync(int o, uint k, CancellationToken ct = default) => throw new NotSupportedException("Ordinal DeleteAsync not supported in test store");
    }
}
