using System;
using System.Linq;
using System.Threading;
using BareMetalWeb.Core.Interfaces;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class ClientRequestTrackerTests
{
    private class MockLogger : IBufferedLogger
    {
        public void LogInfo(string message) { }
        public void LogError(string message, Exception ex) { }
        public Task RunAsync(CancellationToken stoppingToken) => Task.CompletedTask;
        public void OnApplicationStopping(CancellationTokenSource appStoppingSource, Task runTask) { }
    }

    [Fact]
    public void ShouldThrottle_FirstRequest_ReturnsFalse()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger());
        var clientIp = "192.168.1.1";

        // Act
        var result = tracker.ShouldThrottle(clientIp, out var reason, out var retryAfter);

        // Assert
        Assert.False(result);
        Assert.Empty(reason);
        Assert.Null(retryAfter);
    }

    [Fact]
    public void ShouldThrottle_ExceedsNormalThreshold_ReturnsTrue()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger(), normalRpsThreshold: 5);
        var clientIp = "192.168.1.1";

        // Act - Make requests exceeding threshold in same second
        for (int i = 0; i < 6; i++)
        {
            tracker.ShouldThrottle(clientIp, out _, out _);
        }
        var result = tracker.ShouldThrottle(clientIp, out var reason, out var retryAfter);

        // Assert
        Assert.True(result);
        Assert.Equal("blocked", reason);
        Assert.NotNull(retryAfter);
        Assert.True(retryAfter > 0);
    }

    [Fact]
    public void ShouldThrottle_AllowListedIp_NeverThrottles()
    {
        // Arrange
        var allowList = new[] { "192.168.1.100" };
        var tracker = new ClientRequestTracker(new MockLogger(), normalRpsThreshold: 5, allowList: allowList);
        var clientIp = "192.168.1.100";

        // Act - Make many requests
        for (int i = 0; i < 100; i++)
        {
            var result = tracker.ShouldThrottle(clientIp, out var reason, out _);
            
            // Assert
            Assert.False(result);
            Assert.Empty(reason);
        }
    }

    [Fact]
    public void ShouldThrottle_DenyListedIp_AlwaysThrottles()
    {
        // Arrange
        var denyList = new[] { "192.168.1.200" };
        var tracker = new ClientRequestTracker(new MockLogger(), denyList: denyList);
        var clientIp = "192.168.1.200";

        // Act
        var result = tracker.ShouldThrottle(clientIp, out var reason, out _);

        // Assert
        Assert.True(result);
        Assert.Equal("deny-list", reason);
    }

    [Fact]
    public void ShouldThrottle_NullOrEmptyIp_UsesUnknown()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger());

        // Act
        var result1 = tracker.ShouldThrottle(null!, out _, out _);
        var result2 = tracker.ShouldThrottle("", out _, out _);
        var result3 = tracker.ShouldThrottle("   ", out _, out _);

        // Assert
        Assert.False(result1);
        Assert.False(result2);
        Assert.False(result3);
    }

    [Fact]
    public void ShouldThrottle_AfterBlockExpires_ClientIsMarkedSuspicious()
    {
        // Arrange
        var tracker = new ClientRequestTracker(
            new MockLogger(), 
            normalRpsThreshold: 5,
            blockDuration: TimeSpan.FromMilliseconds(50));
        var clientIp = "192.168.1.1";

        // Act - Trigger initial block
        for (int i = 0; i < 7; i++)
        {
            tracker.ShouldThrottle(clientIp, out _, out _);
        }
        
        // Verify blocked
        Assert.True(tracker.ShouldThrottle(clientIp, out var reason1, out _));
        Assert.Equal("blocked", reason1);
        
        // Wait for block to expire
        Thread.Sleep(100);

        // After block expires, client should be marked suspicious
        tracker.ShouldThrottle(clientIp, out _, out _);
        var snapshot = tracker.Snapshot();
        
        // Assert
        Assert.True(snapshot[clientIp].IsSuspicious);
    }

    [Fact]
    public void RecordRequest_ValidIp_RecordsRequest()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger());
        var clientIp = "192.168.1.1";

        // Act
        tracker.RecordRequest(clientIp);
        var snapshot = tracker.Snapshot();

        // Assert
        Assert.True(snapshot.ContainsKey(clientIp));
        Assert.Equal(1, snapshot[clientIp].Count);
    }

    [Fact]
    public void RecordRequest_MultipleRequests_IncrementsCount()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger());
        var clientIp = "192.168.1.1";

        // Act
        tracker.RecordRequest(clientIp);
        tracker.RecordRequest(clientIp);
        tracker.RecordRequest(clientIp);
        var snapshot = tracker.Snapshot();

        // Assert
        Assert.Equal(3, snapshot[clientIp].Count);
    }

    [Fact]
    public void Snapshot_ReturnsCurrentState()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger());
        tracker.RecordRequest("192.168.1.1");
        tracker.RecordRequest("192.168.1.2");
        tracker.RecordRequest("192.168.1.3");

        // Act
        var snapshot = tracker.Snapshot();

        // Assert
        Assert.Equal(3, snapshot.Count);
        Assert.True(snapshot.ContainsKey("192.168.1.1"));
        Assert.True(snapshot.ContainsKey("192.168.1.2"));
        Assert.True(snapshot.ContainsKey("192.168.1.3"));
    }

    [Fact]
    public void GetTopClients_ReturnsOrderedByCount()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger());
        tracker.RecordRequest("192.168.1.1");
        tracker.RecordRequest("192.168.1.2");
        tracker.RecordRequest("192.168.1.2");
        tracker.RecordRequest("192.168.1.3");
        tracker.RecordRequest("192.168.1.3");
        tracker.RecordRequest("192.168.1.3");

        // Act
        var top = tracker.GetTopClients(3);

        // Assert
        Assert.Equal(3, top.Count);
        Assert.Equal("192.168.1.3", top[0].Key);
        Assert.Equal(3, top[0].Value.Count);
        Assert.Equal("192.168.1.2", top[1].Key);
        Assert.Equal(2, top[1].Value.Count);
        Assert.Equal("192.168.1.1", top[2].Key);
        Assert.Equal(1, top[2].Value.Count);
    }

    [Fact]
    public void GetTopClients_LimitCount_ReturnsCorrectNumber()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger());
        for (int i = 1; i <= 10; i++)
        {
            tracker.RecordRequest($"192.168.1.{i}");
        }

        // Act
        var top = tracker.GetTopClients(5);

        // Assert
        Assert.Equal(5, top.Count);
    }

    [Fact]
    public void GetTopClientsTable_NoRequests_ReturnsEmptyMessage()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger());

        // Act
        tracker.GetTopClientsTable(10, out var columns, out var rows);

        // Assert
        Assert.Equal(3, columns.Length);
        Assert.Single(rows);
        Assert.Contains("No requests", rows[0][0]);
    }

    [Fact]
    public void GetTopClientsTable_WithRequests_ReturnsTableData()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger());
        tracker.RecordRequest("192.168.1.1");
        tracker.RecordRequest("192.168.1.2");

        // Act
        tracker.GetTopClientsTable(10, out var columns, out var rows);

        // Assert
        Assert.Equal(new[] { "IP Address", "Requests", "Last Seen (UTC)" }, columns);
        Assert.Equal(2, rows.Length);
    }

    [Fact]
    public void GetSuspiciousClients_NoSuspicious_ReturnsEmpty()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger());
        tracker.RecordRequest("192.168.1.1");

        // Act
        var suspicious = tracker.GetSuspiciousClients(10);

        // Assert
        Assert.Empty(suspicious);
    }

    [Fact]
    public void GetSuspiciousClients_WithBlocked_ReturnsSuspicious()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger(), normalRpsThreshold: 5);
        var clientIp = "192.168.1.1";
        
        // Trigger block
        for (int i = 0; i < 7; i++)
        {
            tracker.ShouldThrottle(clientIp, out _, out _);
        }

        // Act
        var suspicious = tracker.GetSuspiciousClients(10);

        // Assert
        Assert.Single(suspicious);
        Assert.Equal(clientIp, suspicious[0].Key);
    }

    [Fact]
    public void GetSuspiciousClientsTable_NoSuspicious_ReturnsEmptyMessage()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger());

        // Act
        tracker.GetSuspiciousClientsTable(10, out var columns, out var rows);

        // Assert
        Assert.Equal(3, columns.Length);
        Assert.Single(rows);
        Assert.Contains("No suspicious", rows[0][0]);
    }

    [Fact]
    public void ShouldThrottle_WindowReset_ResetsCount()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger(), normalRpsThreshold: 10);
        var clientIp = "192.168.1.1";

        // Act - Make requests in first window
        for (int i = 0; i < 5; i++)
        {
            tracker.ShouldThrottle(clientIp, out _, out _);
        }

        // Wait for window to reset
        Thread.Sleep(1100);

        // Make more requests in new window
        for (int i = 0; i < 5; i++)
        {
            tracker.ShouldThrottle(clientIp, out _, out _);
        }
        var result = tracker.ShouldThrottle(clientIp, out var reason, out _);

        // Assert - Should not be throttled because window reset
        Assert.False(result);
    }

    [Fact]
    public void ShouldThrottle_ZeroThreshold_DisablesThrottling()
    {
        // Arrange
        var tracker = new ClientRequestTracker(new MockLogger(), normalRpsThreshold: 0);
        var clientIp = "192.168.1.1";

        // Act - Make many requests
        bool wasThrottled = false;
        for (int i = 0; i < 100; i++)
        {
            if (tracker.ShouldThrottle(clientIp, out _, out _))
            {
                wasThrottled = true;
                break;
            }
        }

        // Assert
        Assert.False(wasThrottled);
    }

    [Fact]
    public void AllowList_CaseInsensitive()
    {
        // Arrange
        var allowList = new[] { "192.168.1.100" };
        var tracker = new ClientRequestTracker(new MockLogger(), allowList: allowList);

        // Act & Assert
        Assert.False(tracker.ShouldThrottle("192.168.1.100", out _, out _));
        Assert.False(tracker.ShouldThrottle("192.168.1.100", out _, out _));
    }

    [Fact]
    public void DenyList_CaseInsensitive()
    {
        // Arrange
        var denyList = new[] { "192.168.1.200" };
        var tracker = new ClientRequestTracker(new MockLogger(), denyList: denyList);

        // Act & Assert
        Assert.True(tracker.ShouldThrottle("192.168.1.200", out var reason, out _));
        Assert.Equal("deny-list", reason);
    }

    [Fact]
    public void ShouldThrottle_CustomBlockDuration_AppliesCorrectly()
    {
        // Arrange
        var tracker = new ClientRequestTracker(
            new MockLogger(), 
            normalRpsThreshold: 2,
            blockDuration: TimeSpan.FromMilliseconds(200));
        var clientIp = "192.168.1.1";

        // Act - Trigger block
        for (int i = 0; i < 4; i++)
        {
            tracker.ShouldThrottle(clientIp, out _, out _);
        }
        
        // Should still be blocked
        Assert.True(tracker.ShouldThrottle(clientIp, out _, out _));
        
        // Wait for block to expire
        Thread.Sleep(250);
        
        // Should no longer be blocked
        var result = tracker.ShouldThrottle(clientIp, out _, out _);

        // Assert
        Assert.False(result);
    }
}
