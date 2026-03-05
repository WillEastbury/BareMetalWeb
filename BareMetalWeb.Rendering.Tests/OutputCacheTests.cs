using System;
using System.Text;
using System.Threading;
using BareMetalWeb.Core.Interfaces;
using Xunit;

namespace BareMetalWeb.Rendering.Tests;

public class OutputCacheTests
{
    [Fact]
    public void TryGet_EmptyCache_ReturnsFalse()
    {
        // Arrange
        var cache = new OutputCache();

        // Act
        var result = cache.TryGet("/test", out var response);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Store_ValidData_StoresInCache()
    {
        // Arrange
        var cache = new OutputCache();
        var path = "/test";
        var body = Encoding.UTF8.GetBytes("Test content");
        var contentType = "text/html";
        var statusCode = 200;

        // Act
        cache.Store(path, body, contentType, statusCode);

        // Assert
        var result = cache.TryGet(path, out var response);
        Assert.True(result);
        Assert.Equal(body, response.Body);
        Assert.Equal(contentType, response.ContentType);
        Assert.Equal(statusCode, response.StatusCode);
    }

    [Fact]
    public void TryGet_BeforeExpiry_ReturnsTrue()
    {
        // Arrange
        var cache = new OutputCache();
        var path = "/test";
        var body = Encoding.UTF8.GetBytes("Test content");

        // Act
        cache.Store(path, body, "text/html", 200, expiry: 5);
        var result = cache.TryGet(path, out var response);

        // Assert
        Assert.True(result);
        Assert.Equal(body, response.Body);
    }

    [Fact]
    public void TryGet_AfterExpiry_ReturnsFalse()
    {
        // Arrange
        var cache = new OutputCache();
        var path = "/test";
        var body = Encoding.UTF8.GetBytes("Test content");

        // Act
        cache.Store(path, body, "text/html", 200, expiry: 1);
        Thread.Sleep(1100); // Wait for expiry
        var result = cache.TryGet(path, out _);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Store_UpdatesExistingEntry()
    {
        // Arrange
        var cache = new OutputCache();
        var path = "/test";
        var body1 = Encoding.UTF8.GetBytes("First content");
        var body2 = Encoding.UTF8.GetBytes("Second content");

        // Act
        cache.Store(path, body1, "text/html", 200);
        cache.Store(path, body2, "text/plain", 201);
        var result = cache.TryGet(path, out var response);

        // Assert
        Assert.True(result);
        Assert.Equal(body2, response.Body);
        Assert.Equal("text/plain", response.ContentType);
        Assert.Equal(201, response.StatusCode);
    }

    [Fact]
    public void Store_DifferentPaths_StoresSeparately()
    {
        // Arrange
        var cache = new OutputCache();
        var path1 = "/test1";
        var path2 = "/test2";
        var body1 = Encoding.UTF8.GetBytes("Content 1");
        var body2 = Encoding.UTF8.GetBytes("Content 2");

        // Act
        cache.Store(path1, body1, "text/html", 200);
        cache.Store(path2, body2, "text/plain", 201);

        // Assert
        var result1 = cache.TryGet(path1, out var response1);
        var result2 = cache.TryGet(path2, out var response2);
        Assert.True(result1);
        Assert.True(result2);
        Assert.Equal(body1, response1.Body);
        Assert.Equal(body2, response2.Body);
    }

    [Fact]
    public void Store_CustomExpiry_RespectsExpiryTime()
    {
        // Arrange
        var cache = new OutputCache();
        var path = "/test";
        var body = Encoding.UTF8.GetBytes("Test content");

        // Act
        cache.Store(path, body, "text/html", 200, expiry: 2);
        
        // Assert - Should be valid immediately
        Assert.True(cache.TryGet(path, out _));
        
        // Wait and check again
        Thread.Sleep(2100);
        Assert.False(cache.TryGet(path, out _));
    }

    [Fact]
    public void Store_ZeroExpiry_ExpiresImmediately()
    {
        // Arrange
        var cache = new OutputCache();
        var path = "/test";
        var body = Encoding.UTF8.GetBytes("Test content");

        // Act
        cache.Store(path, body, "text/html", 200, expiry: 0);
        
        // Even with 0 expiry, it might be retrievable for a very short time
        // But after any wait, it should be expired
        Thread.Sleep(10);
        var result = cache.TryGet(path, out _);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Store_EmptyBody_StoresCorrectly()
    {
        // Arrange
        var cache = new OutputCache();
        var path = "/test";
        var body = Array.Empty<byte>();

        // Act
        cache.Store(path, body, "text/html", 200);
        var result = cache.TryGet(path, out var response);

        // Assert
        Assert.True(result);
        Assert.Equal(body, response.Body);
        Assert.Empty(response.Body);
    }

    [Fact]
    public void Store_LargeBody_StoresCorrectly()
    {
        // Arrange
        var cache = new OutputCache();
        var path = "/test";
        var body = new byte[1024 * 1024]; // 1 MB
        Random.Shared.NextBytes(body);

        // Act
        cache.Store(path, body, "application/octet-stream", 200);
        var result = cache.TryGet(path, out var response);

        // Assert
        Assert.True(result);
        Assert.Equal(body, response.Body);
    }

    [Fact]
    public void Store_DifferentStatusCodes_StoresCorrectly()
    {
        // Arrange
        var cache = new OutputCache();
        var path1 = "/success";
        var path2 = "/redirect";
        var path3 = "/error";

        // Act
        cache.Store(path1, Encoding.UTF8.GetBytes("OK"), "text/plain", 200);
        cache.Store(path2, Encoding.UTF8.GetBytes("Moved"), "text/plain", 301);
        cache.Store(path3, Encoding.UTF8.GetBytes("Not Found"), "text/plain", 404);

        // Assert
        Assert.True(cache.TryGet(path1, out var response1));
        Assert.Equal(200, response1.StatusCode);
        Assert.True(cache.TryGet(path2, out var response2));
        Assert.Equal(301, response2.StatusCode);
        Assert.True(cache.TryGet(path3, out var response3));
        Assert.Equal(404, response3.StatusCode);
    }

    [Fact]
    public void Store_SpecialCharactersInPath_WorksCorrectly()
    {
        // Arrange
        var cache = new OutputCache();
        var path = "/test?query=value&foo=bar";
        var body = Encoding.UTF8.GetBytes("Test content");

        // Act
        cache.Store(path, body, "text/html", 200);
        var result = cache.TryGet(path, out var response);

        // Assert
        Assert.True(result);
        Assert.Equal(body, response.Body);
    }

    [Fact]
    public void Store_CaseSensitivePaths_TreatsAsDifferent()
    {
        // Arrange
        var cache = new OutputCache();
        var path1 = "/Test";
        var path2 = "/test";
        var body1 = Encoding.UTF8.GetBytes("Upper");
        var body2 = Encoding.UTF8.GetBytes("Lower");

        // Act
        cache.Store(path1, body1, "text/html", 200);
        cache.Store(path2, body2, "text/html", 200);

        // Assert
        Assert.True(cache.TryGet(path1, out var response1));
        Assert.True(cache.TryGet(path2, out var response2));
        Assert.Equal(body1, response1.Body);
        Assert.Equal(body2, response2.Body);
    }

    [Fact]
    public async Task Store_MultipleConcurrentStores_HandlesCorrectly()
    {
        // Arrange
        var cache = new OutputCache();
        var path = "/concurrent";
        var tasks = new System.Threading.Tasks.Task[10];

        // Act
        for (int i = 0; i < tasks.Length; i++)
        {
            var index = i;
            tasks[i] = System.Threading.Tasks.Task.Run(() =>
            {
                var body = Encoding.UTF8.GetBytes($"Content {index}");
                cache.Store(path, body, "text/html", 200);
            });
        }
        await System.Threading.Tasks.Task.WhenAll(tasks);

        // Assert - Should have stored something without crashing
        var result = cache.TryGet(path, out var response);
        Assert.True(result);
        Assert.NotNull(response.Body);
    }

    [Fact]
    public void Response_ExpiresProperty_IsSetCorrectly()
    {
        // Arrange
        var cache = new OutputCache();
        var path = "/test";
        var body = Encoding.UTF8.GetBytes("Test content");
        var beforeStore = DateTime.UtcNow;

        // Act
        cache.Store(path, body, "text/html", 200, expiry: 10);
        cache.TryGet(path, out var response);
        var afterStore = DateTime.UtcNow;

        // Assert
        Assert.True(response.Expires > beforeStore.AddSeconds(9));
        Assert.True(response.Expires < afterStore.AddSeconds(11));
    }

    [Fact]
    public void Store_PrunesExpiredEntries_SoTheyDontAccumulate()
    {
        // Arrange: store several paths with a very short expiry then store a new one.
        var cache = new OutputCache();
        var expiredPaths = new[] { "/expired1", "/expired2", "/expired3" };
        var body = Encoding.UTF8.GetBytes("content");

        foreach (var p in expiredPaths)
            cache.Store(p, body, "text/html", 200, expiry: 0);

        // Wait long enough for all entries to expire.
        Thread.Sleep(50);

        // Act: store a new entry – this triggers PruneExpired internally.
        cache.Store("/new", body, "text/html", 200, expiry: 30);

        // Assert: the expired paths should no longer be retrievable.
        foreach (var p in expiredPaths)
            Assert.False(cache.TryGet(p, out _), $"Expected '{p}' to be pruned but it was still present.");

        // The new (non-expired) path should still be there.
        Assert.True(cache.TryGet("/new", out _));
    }
}
