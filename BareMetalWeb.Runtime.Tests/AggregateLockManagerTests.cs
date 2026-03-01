using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using BareMetalWeb.Runtime;
using Xunit;

namespace BareMetalWeb.Runtime.Tests;

/// <summary>Tests for <see cref="AggregateLockManager"/>.</summary>
public class AggregateLockManagerTests
{
    private static AggregateLockManager MakeManager() => new();

    private static readonly TimeSpan ShortExpiry = TimeSpan.FromSeconds(10);

    [Fact]
    public void TryAcquire_FirstCaller_Succeeds()
    {
        var mgr = MakeManager();
        var ok = mgr.TryAcquire("agg-1", "tx-1", ShortExpiry);
        Assert.True(ok);
    }

    [Fact]
    public void TryAcquire_SameTxReentrant_Succeeds()
    {
        var mgr = MakeManager();
        mgr.TryAcquire("agg-1", "tx-1", ShortExpiry);
        var ok = mgr.TryAcquire("agg-1", "tx-1", ShortExpiry); // reentrant
        Assert.True(ok);
    }

    [Fact]
    public void TryAcquire_DifferentTx_Fails()
    {
        var mgr = MakeManager();
        mgr.TryAcquire("agg-1", "tx-1", ShortExpiry);
        var ok = mgr.TryAcquire("agg-1", "tx-2", ShortExpiry); // contended
        Assert.False(ok);
    }

    [Fact]
    public void Release_AllowsSubsequentAcquire()
    {
        var mgr = MakeManager();
        mgr.TryAcquire("agg-1", "tx-1", ShortExpiry);
        mgr.Release("agg-1", "tx-1");
        var ok = mgr.TryAcquire("agg-1", "tx-2", ShortExpiry);
        Assert.True(ok);
    }

    [Fact]
    public void Release_WrongOwner_DoesNotRelease()
    {
        var mgr = MakeManager();
        mgr.TryAcquire("agg-1", "tx-1", ShortExpiry);
        mgr.Release("agg-1", "tx-99"); // wrong owner — no-op
        var ok = mgr.TryAcquire("agg-1", "tx-2", ShortExpiry);
        Assert.False(ok); // still held by tx-1
    }

    [Fact]
    public void TryAcquireAll_AllSucceed_ReturnsTrue()
    {
        var mgr = MakeManager();
        var ok = mgr.TryAcquireAll(new[] { "agg-a", "agg-b", "agg-c" }, "tx-1", ShortExpiry);
        Assert.True(ok);
    }

    [Fact]
    public void TryAcquireAll_OneContended_ReturnsFalseAndReleasesRest()
    {
        var mgr = MakeManager();
        mgr.TryAcquire("agg-b", "tx-other", ShortExpiry); // pre-lock agg-b

        var ok = mgr.TryAcquireAll(new[] { "agg-a", "agg-b", "agg-c" }, "tx-1", ShortExpiry);
        Assert.False(ok);

        // agg-a and agg-c must have been released — tx-2 should be able to acquire them
        var okA = mgr.TryAcquire("agg-a", "tx-2", ShortExpiry);
        var okC = mgr.TryAcquire("agg-c", "tx-2", ShortExpiry);
        Assert.True(okA, "agg-a should have been released on failure");
        Assert.True(okC, "agg-c should have been released on failure");
    }

    [Fact]
    public void TryAcquireAll_DeduplicatesIds()
    {
        var mgr = MakeManager();
        // Duplicate IDs must not cause issues
        var ok = mgr.TryAcquireAll(new[] { "agg-x", "agg-x", "agg-x" }, "tx-1", ShortExpiry);
        Assert.True(ok);
    }

    [Fact]
    public void ReleaseAll_ReleasesEachLock()
    {
        var mgr = MakeManager();
        mgr.TryAcquireAll(new[] { "agg-1", "agg-2" }, "tx-1", ShortExpiry);
        mgr.ReleaseAll(new[] { "agg-1", "agg-2" }, "tx-1");

        var ok1 = mgr.TryAcquire("agg-1", "tx-2", ShortExpiry);
        var ok2 = mgr.TryAcquire("agg-2", "tx-2", ShortExpiry);
        Assert.True(ok1);
        Assert.True(ok2);
    }

    [Fact]
    public void ExpiredLock_IsReplaced_ByNewOwner()
    {
        var mgr = MakeManager();
        mgr.TryAcquire("agg-1", "tx-1", TimeSpan.FromMilliseconds(1)); // expires almost immediately
        Thread.Sleep(10); // let it expire
        var ok = mgr.TryAcquire("agg-1", "tx-2", ShortExpiry);
        Assert.True(ok, "Expired lock should be replaced by new owner");
    }

    [Fact]
    public void ActiveLockCount_ReflectsCurrentLocks()
    {
        var mgr = MakeManager();
        Assert.Equal(0, mgr.ActiveLockCount);
        mgr.TryAcquire("agg-1", "tx-1", ShortExpiry);
        mgr.TryAcquire("agg-2", "tx-1", ShortExpiry);
        Assert.Equal(2, mgr.ActiveLockCount);
        mgr.Release("agg-1", "tx-1");
        Assert.Equal(1, mgr.ActiveLockCount);
    }
}
