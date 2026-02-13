using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Host;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host.Tests;

public class UserAuthTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;

    public UserAuthTests()
    {
        // Save original store to restore later
        _originalStore = DataStoreProvider.Current;
        // Set up a mock data store for testing
        DataStoreProvider.Current = new InMemoryDataStore();
    }

    public void Dispose()
    {
        // Restore original store
        DataStoreProvider.Current = _originalStore;
    }

    [Fact]
    public async Task GetSessionAsync_ActiveSession_ExtendsExpirationTime()
    {
        // Arrange
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

        await DataStoreProvider.Current.SaveAsync(session);

        var context = CreateHttpContext(session.Id);
        var originalExpiresUtc = session.ExpiresUtc;
        var originalLastSeenUtc = session.LastSeenUtc;

        // Act
        var result = await UserAuth.GetSessionAsync(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(session.Id, result.Id);

        // Reload session to check if it was updated
        var updatedSession = await DataStoreProvider.Current.LoadAsync<UserSession>(session.Id);
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

        await DataStoreProvider.Current.SaveAsync(session);

        var context = CreateHttpContext(session.Id);
        var originalExpiresUtc = session.ExpiresUtc;

        // Act
        var result = await UserAuth.GetSessionAsync(context);

        // Assert
        Assert.NotNull(result);

        // Reload session to check if it was updated
        var updatedSession = await DataStoreProvider.Current.LoadAsync<UserSession>(session.Id);
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

        DataStoreProvider.Current.Save(session);

        var context = CreateHttpContext(session.Id);
        var originalExpiresUtc = session.ExpiresUtc;
        var originalLastSeenUtc = session.LastSeenUtc;

        // Act
        var result = UserAuth.GetSession(context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(session.Id, result.Id);

        // Reload session to check if it was updated
        var updatedSession = DataStoreProvider.Current.Load<UserSession>(session.Id);
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

        await DataStoreProvider.Current.SaveAsync(session);

        var context = CreateHttpContext(session.Id);

        // Act
        var result = await UserAuth.GetSessionAsync(context);

        // Assert
        Assert.Null(result);

        // Session should be marked as revoked
        var updatedSession = await DataStoreProvider.Current.LoadAsync<UserSession>(session.Id);
        Assert.NotNull(updatedSession);
        Assert.True(updatedSession.IsRevoked);
    }

    [Fact]
    public async Task GetSessionAsync_NoSession_ReturnsNull()
    {
        // Arrange
        var context = CreateHttpContext(null);

        // Act
        var result = await UserAuth.GetSessionAsync(context);

        // Assert
        Assert.Null(result);
    }

    private static HttpContext CreateHttpContext(string? sessionId)
    {
        var context = new DefaultHttpContext();
        
        if (!string.IsNullOrEmpty(sessionId))
        {
            var protectedSessionId = CookieProtection.Protect(sessionId);
            context.Request.Headers.Cookie = $"{UserAuth.SessionCookieName}={protectedSessionId}";
        }

        return context;
    }

    // Simple in-memory data store for testing
    private class InMemoryDataStore : IDataObjectStore
    {
        private readonly Dictionary<string, BaseDataObject> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();

        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        public void Save<T>(T obj) where T : BaseDataObject
        {
            _store[obj.Id] = obj;
        }

        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Save(obj);
            return ValueTask.CompletedTask;
        }

        public T? Load<T>(string id) where T : BaseDataObject
        {
            return _store.TryGetValue(id, out var obj) ? obj as T : null;
        }

        public ValueTask<T?> LoadAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            return ValueTask.FromResult(Load<T>(id));
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

        public void Delete<T>(string id) where T : BaseDataObject
        {
            _store.Remove(id);
        }

        public ValueTask DeleteAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Delete<T>(id);
            return ValueTask.CompletedTask;
        }
    }
}
