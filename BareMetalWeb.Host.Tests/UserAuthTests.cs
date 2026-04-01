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
        var principal = new SystemPrincipal
        {
            UserName = "chatgpt",
            DisplayName = "ChatGPT",
            IsActive = true
        };
        principal.AddApiKey(rawKey, iterations: 1);
        await DataStoreProvider.Current.SaveAsync(principal.EntityTypeName, principal);

        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = $"Bearer {rawKey}";
        context.Request.Path = "/api/to-do";

        // Act
        var user = await UserAuth.GetRequestUserAsync(context.ToBmw());

        // Assert
        Assert.NotNull(user);
        // DataScaffold metadata isn't registered in unit tests, so use the typed property
        var resolved = Assert.IsType<SystemPrincipal>(user);
        Assert.Equal("chatgpt", resolved.UserName);
    }

    [Fact]
    public async Task HasValidApiKeyAsync_ValidBearerToken_ReturnsTrue()
    {
        // Arrange
        EnsureStore();
        var rawKey = "bearer-valid-key-abc";
        var principal = new SystemPrincipal
        {
            UserName = "external-client",
            DisplayName = "External Client",
            IsActive = true
        };
        principal.AddApiKey(rawKey, iterations: 1);
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
        var principal = new SystemPrincipal
        {
            UserName = "cli-client",
            DisplayName = "CLI Client",
            IsActive = true
        };
        principal.AddApiKey(rawKey, iterations: 1);
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
        var principal = new SystemPrincipal
        {
            UserName = "inactive-client",
            DisplayName = "Inactive Client",
            IsActive = false
        };
        principal.AddApiKey(rawKey, iterations: 1);
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
        var session = new UserSession
        {
            UserId = "user123",
            UserName = "testuser",
            DisplayName = "Test User",
            Permissions = Array.Empty<string>(),
            IssuedUtc = now.AddHours(-2),
            LastSeenUtc = now.AddHours(-1),
            ExpiresUtc = now.AddHours(6), // 8 hours from issue - 2 hours ago = 6 hours left
            RememberMe = false,
            IsRevoked = false,
            CreatedBy = "testuser",
            UpdatedBy = "testuser"
        };

        await DataStoreProvider.Current.SaveAsync(session.EntityTypeName, session);

        var context = CreateHttpContext(session.Key.ToString());
        var originalExpiresUtc = session.ExpiresUtc;
        var originalLastSeenUtc = session.LastSeenUtc;

        // Act
        var result = await UserAuth.GetSessionAsync(context.ToBmw());

        // Assert
        Assert.NotNull(result);
        Assert.Equal(session.Key, result.Key);

        // Reload session to check if it was updated
        var updatedSession = (UserSession?)(await DataStoreProvider.Current.LoadAsync("UserSession", session.Key));
        Assert.NotNull(updatedSession);
        
        // LastSeenUtc should be updated to now (or very close)
        Assert.True(updatedSession.LastSeenUtc > originalLastSeenUtc);
        Assert.True((DateTime.UtcNow - updatedSession.LastSeenUtc).TotalSeconds < 2); // within 2 seconds
        
        // ExpiresUtc should be extended (8 hours from LastSeenUtc for non-RememberMe)
        Assert.True(updatedSession.ExpiresUtc > originalExpiresUtc);
        var expectedExpiration = updatedSession.LastSeenUtc.AddHours(8);
        Assert.True((updatedSession.ExpiresUtc - expectedExpiration).Duration().TotalSeconds < 2); // within 2 seconds
    }

    [Fact]
    public async Task GetSessionAsync_RememberMeSession_ExtendsWithRememberMeLifetime()
    {
        // Arrange
        EnsureStore();
        var now = DateTime.UtcNow;
        var session = new UserSession
        {
            UserId = "user123",
            UserName = "testuser",
            DisplayName = "Test User",
            Permissions = Array.Empty<string>(),
            IssuedUtc = now.AddDays(-5),
            LastSeenUtc = now.AddDays(-1),
            ExpiresUtc = now.AddDays(25), // 30 days from issue - 5 days ago = 25 days left
            RememberMe = true,
            IsRevoked = false,
            CreatedBy = "testuser",
            UpdatedBy = "testuser"
        };

        await DataStoreProvider.Current.SaveAsync(session.EntityTypeName, session);

        var context = CreateHttpContext(session.Key.ToString());
        var originalExpiresUtc = session.ExpiresUtc;

        // Act
        var result = await UserAuth.GetSessionAsync(context.ToBmw());

        // Assert
        Assert.NotNull(result);

        // Reload session to check if it was updated
        var updatedSession = (UserSession?)(await DataStoreProvider.Current.LoadAsync("UserSession", session.Key));
        Assert.NotNull(updatedSession);
        
        // ExpiresUtc should be extended (30 days from LastSeenUtc for RememberMe)
        Assert.True(updatedSession.ExpiresUtc > originalExpiresUtc);
        var expectedExpiration = updatedSession.LastSeenUtc.AddDays(30);
        Assert.True((updatedSession.ExpiresUtc - expectedExpiration).Duration().TotalSeconds < 2); // within 2 seconds
    }

    [Fact]
    public void GetSession_ActiveSession_ExtendsExpirationTime()
    {
        // Arrange
        EnsureStore();
        var now = DateTime.UtcNow;
        var session = new UserSession
        {
            UserId = "user123",
            UserName = "testuser",
            DisplayName = "Test User",
            Permissions = Array.Empty<string>(),
            IssuedUtc = now.AddHours(-2),
            LastSeenUtc = now.AddHours(-1),
            ExpiresUtc = now.AddHours(6),
            RememberMe = false,
            IsRevoked = false,
            CreatedBy = "testuser",
            UpdatedBy = "testuser"
        };

        DataStoreProvider.Current.Save(session.EntityTypeName, session);

        var context = CreateHttpContext(session.Key.ToString());
        var originalExpiresUtc = session.ExpiresUtc;
        var originalLastSeenUtc = session.LastSeenUtc;

        // Act
        var result = UserAuth.GetSession(context.ToBmw());

        // Assert
        Assert.NotNull(result);
        Assert.Equal(session.Key, result.Key);

        // Reload session to check if it was updated
        var updatedSession = (UserSession?)DataStoreProvider.Current.Load("UserSession", session.Key);
        Assert.NotNull(updatedSession);
        
        // LastSeenUtc should be updated
        Assert.True(updatedSession.LastSeenUtc > originalLastSeenUtc);
        
        // ExpiresUtc should be extended
        Assert.True(updatedSession.ExpiresUtc > originalExpiresUtc);
    }

    [Fact]
    public async Task GetSessionAsync_ExpiredSession_ReturnsNull()
    {
        // Arrange
        EnsureStore();
        var now = DateTime.UtcNow;
        var session = new UserSession
        {
            UserId = "user123",
            UserName = "testuser",
            DisplayName = "Test User",
            Permissions = Array.Empty<string>(),
            IssuedUtc = now.AddHours(-10),
            LastSeenUtc = now.AddHours(-9),
            ExpiresUtc = now.AddHours(-1), // Expired 1 hour ago
            RememberMe = false,
            IsRevoked = false,
            CreatedBy = "testuser",
            UpdatedBy = "testuser"
        };

        await DataStoreProvider.Current.SaveAsync(session.EntityTypeName, session);

        var context = CreateHttpContext(session.Key.ToString());

        // Act
        var result = await UserAuth.GetSessionAsync(context.ToBmw());

        // Assert
        Assert.Null(result);

        // Session should be marked as revoked
        var updatedSession = (UserSession?)(await DataStoreProvider.Current.LoadAsync("UserSession", session.Key));
        Assert.NotNull(updatedSession);
        Assert.True(updatedSession.IsRevoked);
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
        var session = new UserSession
        {
            UserId = "user123",
            UserName = "testuser",
            DisplayName = "Test User",
            Permissions = Array.Empty<string>(),
            IssuedUtc = now,
            LastSeenUtc = now,
            ExpiresUtc = now.AddHours(8), // Just extended; newExpiry - ExpiresUtc ≈ 0 < 1 minute
            RememberMe = false,
            IsRevoked = false,
            CreatedBy = "testuser",
            UpdatedBy = "testuser"
        };

        await DataStoreProvider.Current.SaveAsync(session.EntityTypeName, session);

        var context = CreateHttpContext(session.Key.ToString());
        var originalExpiresUtc = session.ExpiresUtc;

        // Act
        var result = await UserAuth.GetSessionAsync(context.ToBmw());

        // Assert — session returned successfully
        Assert.NotNull(result);
        Assert.Equal(session.Key, result.Key);

        // Session should NOT have been re-saved because the extension gain is < 1 minute
        var storedSession = (UserSession?)(await DataStoreProvider.Current.LoadAsync("UserSession", session.Key));
        Assert.NotNull(storedSession);
        Assert.Equal(originalExpiresUtc, storedSession.ExpiresUtc);
    }

    [Fact]
    public void GetSession_RecentlyExtendedSession_SkipsSave()
    {
        // Arrange
        EnsureStore();
        var now = DateTime.UtcNow;
        var session = new UserSession
        {
            UserId = "user123",
            UserName = "testuser",
            DisplayName = "Test User",
            Permissions = Array.Empty<string>(),
            IssuedUtc = now,
            LastSeenUtc = now,
            ExpiresUtc = now.AddHours(8),
            RememberMe = false,
            IsRevoked = false,
            CreatedBy = "testuser",
            UpdatedBy = "testuser"
        };

        DataStoreProvider.Current.Save(session.EntityTypeName, session);

        var context = CreateHttpContext(session.Key.ToString());
        var originalExpiresUtc = session.ExpiresUtc;

        // Act
        var result = UserAuth.GetSession(context.ToBmw());

        // Assert — session returned successfully
        Assert.NotNull(result);

        // Session should NOT have been re-saved because the extension gain is < 1 minute
        var storedSession = (UserSession?)DataStoreProvider.Current.Load("UserSession", session.Key);
        Assert.NotNull(storedSession);
        Assert.Equal(originalExpiresUtc, storedSession.ExpiresUtc);
    }

    [Fact]
    public async Task FindByEmailOrUserNameAsync_MultipleUsers_ReturnsCorrectUserByUsername()
    {
        // Arrange — two users with distinct credentials
        EnsureStore();
        var root = new User
        {
            Key = 1,
            UserName = "root",
            DisplayName = "Root User",
            Email = "root@example.com",
            Permissions = new[] { "admin", "monitoring" },
            IsActive = true
        };
        root.SetPassword("rootpass");
        await DataStoreProvider.Current.SaveAsync(root.EntityTypeName, root);

        var secondUser = new User
        {
            Key = 2,
            UserName = "son",
            DisplayName = "Son User",
            Email = "son@example.com",
            Permissions = new[] { "user" },
            IsActive = true
        };
        secondUser.SetPassword("sonpass");
        await DataStoreProvider.Current.SaveAsync(secondUser.EntityTypeName, secondUser);

        // Act — look up by username
        var foundRoot = await Users.FindByEmailOrUserNameAsync("root");
        var foundSon = await Users.FindByEmailOrUserNameAsync("son");

        // Assert — each lookup returns the correct user
        Assert.NotNull(foundRoot);
        Assert.Equal(root.Key, foundRoot.Key);
        Assert.Equal("root", foundRoot.UserName);

        Assert.NotNull(foundSon);
        Assert.Equal(secondUser.Key, foundSon.Key);
        Assert.Equal("son", foundSon.UserName);
    }

    [Fact]
    public async Task FindByEmailOrUserNameAsync_MultipleUsers_ReturnsCorrectUserByEmail()
    {
        // Arrange — two users with distinct credentials
        EnsureStore();
        var root = new User
        {
            Key = 1,
            UserName = "root",
            DisplayName = "Root User",
            Email = "root@example.com",
            Permissions = new[] { "admin", "monitoring" },
            IsActive = true
        };
        root.SetPassword("rootpass");
        await DataStoreProvider.Current.SaveAsync(root.EntityTypeName, root);

        var secondUser = new User
        {
            Key = 2,
            UserName = "son",
            DisplayName = "Son User",
            Email = "son@example.com",
            Permissions = new[] { "user" },
            IsActive = true
        };
        secondUser.SetPassword("sonpass");
        await DataStoreProvider.Current.SaveAsync(secondUser.EntityTypeName, secondUser);

        // Act — look up by email
        var foundRoot = await Users.FindByEmailOrUserNameAsync("root@example.com");
        var foundSon = await Users.FindByEmailOrUserNameAsync("son@example.com");

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
        var root = new User
        {
            Key = 1,
            UserName = "admin",
            DisplayName = "Administrator",
            Email = "admin@example.com",
            Permissions = new[] { "admin", "monitoring" },
            IsActive = true
        };
        root.SetPassword("AdminPass1!");
        await DataStoreProvider.Current.SaveAsync(root.EntityTypeName, root);

        var secondUser = new User
        {
            Key = 2,
            UserName = "son",
            DisplayName = "Son",
            Email = "son@example.com",
            Permissions = new[] { "user" },
            IsActive = true
        };
        secondUser.SetPassword("SonPass1!");
        await DataStoreProvider.Current.SaveAsync(secondUser.EntityTypeName, secondUser);

        // Act — root login lookup after second user exists
        var found = await Users.FindByEmailOrUserNameAsync("admin");

        // Assert — root is found and its password still verifies correctly
        Assert.NotNull(found);
        Assert.Equal(root.Key, found.Key);
        Assert.True(found.VerifyPassword("AdminPass1!"), "Root password should verify correctly");
        Assert.False(found.VerifyPassword("SonPass1!"), "Second user password must not match root");
    }

    [Fact]
    public async Task FindByUserNameAsync_ReturnsNullForMissingUsername()
    {
        // Arrange
        EnsureStore();
        var user = new User
        {
            UserName = "existing",
            Email = "existing@example.com",
            IsActive = true
        };
        await DataStoreProvider.Current.SaveAsync(user.EntityTypeName, user);

        // Act
        var found = await Users.FindByUserNameAsync("nonexistent");

        // Assert
        Assert.Null(found);
    }

    [Fact]
    public async Task FindByEmailAsync_ReturnsNullForMissingEmail()
    {
        // Arrange
        EnsureStore();
        var user = new User
        {
            UserName = "test",
            Email = "test@example.com",
            IsActive = true
        };
        await DataStoreProvider.Current.SaveAsync(user.EntityTypeName, user);

        // Act
        var found = await Users.FindByEmailAsync("nobody@example.com");

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
        var original = new User
        {
            UserName = "admin",
            Email = "admin@example.com",
            IsActive = true
        };
        original.SetPassword("AdminPass1!");
        await DataStoreProvider.Current.SaveAsync(original.EntityTypeName, original);

        // Act – the same username already exists; uniqueness check must catch it
        var exists = await Users.ExistsByEmailOrUserNameAsync("admin");

        // Assert – the guard should detect the conflict so no clone is saved
        Assert.True(exists);
    }

    [Fact]
    public async Task ExistsByEmailOrUserNameAsync_DuplicateEmail_ReturnsTrue()
    {
        // Arrange
        EnsureStore();
        var original = new User
        {
            UserName = "alice",
            Email = "alice@example.com",
            IsActive = true
        };
        original.SetPassword("AlicePass1!");
        await DataStoreProvider.Current.SaveAsync(original.EntityTypeName, original);

        // Act
        var exists = await Users.ExistsByEmailOrUserNameAsync("alice@example.com");

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
        var original = new User
        {
            UserName = "admin",
            Email = "admin@example.com",
            IsActive = true
        };
        original.SetPassword("CorrectPass1!");
        await DataStoreProvider.Current.SaveAsync(original.EntityTypeName, original);

        // Act – lookup must return the record whose password verifies
        var found = await Users.FindByUserNameAsync("admin");

        // Assert
        Assert.NotNull(found);
        Assert.Equal(original.Key, found.Key);
        Assert.True(found.VerifyPassword("CorrectPass1!"), "Original user password must verify correctly.");
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
        private readonly Dictionary<(string, uint), BaseDataObject> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();

        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        // ── String-based CRUD ──────────────────────────────────────────
        public void Save(string entityTypeName, BaseDataObject obj)
        {
            _store[(entityTypeName, obj.Key)] = obj;
        }

        public ValueTask SaveAsync(string entityTypeName, BaseDataObject obj, CancellationToken cancellationToken = default)
        {
            Save(entityTypeName, obj);
            return ValueTask.CompletedTask;
        }

        public BaseDataObject? Load(string entityTypeName, uint key)
        {
            return _store.TryGetValue((entityTypeName, key), out var obj) ? obj : null;
        }

        public ValueTask<BaseDataObject?> LoadAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(Load(entityTypeName, key));
        }

        public IEnumerable<BaseDataObject> Query(string entityTypeName, QueryDefinition? query = null)
        {
            foreach (var kv in _store)
            {
                if (kv.Key.Item1 == entityTypeName)
                    yield return kv.Value;
            }
        }

        public ValueTask<IEnumerable<BaseDataObject>> QueryAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default)
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
        public void Save(int o, BaseDataObject obj) => Save(obj.EntityTypeName, obj);
        public BaseDataObject? Load(int o, uint k) => throw new NotSupportedException("Ordinal Load not supported in test store");
        public IEnumerable<BaseDataObject> Query(int o, QueryDefinition? q = null) => throw new NotSupportedException("Ordinal Query not supported in test store");
        public void Delete(int o, uint k) => throw new NotSupportedException("Ordinal Delete not supported in test store");
        public ValueTask SaveAsync(int o, BaseDataObject obj, CancellationToken ct = default) { Save(o, obj); return ValueTask.CompletedTask; }
        public ValueTask<BaseDataObject?> LoadAsync(int o, uint k, CancellationToken ct = default) => throw new NotSupportedException("Ordinal LoadAsync not supported in test store");
        public ValueTask<IEnumerable<BaseDataObject>> QueryAsync(int o, QueryDefinition? q = null, CancellationToken ct = default) => throw new NotSupportedException("Ordinal QueryAsync not supported in test store");
        public ValueTask<int> CountAsync(int o, QueryDefinition? q = null, CancellationToken ct = default) => throw new NotSupportedException("Ordinal CountAsync not supported in test store");
        public ValueTask DeleteAsync(int o, uint k, CancellationToken ct = default) => throw new NotSupportedException("Ordinal DeleteAsync not supported in test store");
    }
}
