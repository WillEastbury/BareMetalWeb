using System;
using System.Threading;
using System.Threading.Tasks;

namespace BareMetalWeb.Host.Tests;

public class BackgroundJobServiceTests
{
    private static async Task WaitUntilAsync(Func<bool> condition, int timeoutMs = 5000, int intervalMs = 25)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (!condition() && sw.ElapsedMilliseconds < timeoutMs)
            await Task.Delay(intervalMs);
        Assert.True(condition(), $"Condition not met within {timeoutMs}ms");
    }

    // ── StartJob / TryGetJob ──────────────────────────────────────

    [Fact]
    public void StartJob_ReturnsNonEmptyJobId()
    {
        var svc = new BackgroundJobService();

        var jobId = svc.StartJob("TestOp", null, (_, _) => Task.CompletedTask);

        Assert.False(string.IsNullOrWhiteSpace(jobId));
    }

    [Fact]
    public void StartJob_TwoJobs_ReturnDistinctIds()
    {
        var svc = new BackgroundJobService();

        var id1 = svc.StartJob("Op1", null, (_, _) => Task.CompletedTask);
        var id2 = svc.StartJob("Op2", null, (_, _) => Task.CompletedTask);

        Assert.NotEqual(id1, id2);
    }

    [Fact]
    public void TryGetJob_UnknownId_ReturnsFalse()
    {
        var svc = new BackgroundJobService();

        var found = svc.TryGetJob("doesnotexist", out var snapshot);

        Assert.False(found);
        Assert.Null(snapshot);
    }

    [Fact]
    public void TryGetJob_KnownId_ReturnsSnapshot()
    {
        var svc = new BackgroundJobService();

        var jobId = svc.StartJob("OpX", "/result", (_, _) => Task.CompletedTask);
        var found = svc.TryGetJob(jobId, out var snapshot);

        Assert.True(found);
        Assert.NotNull(snapshot);
        Assert.Equal(jobId, snapshot!.JobId);
        Assert.Equal("OpX", snapshot.OperationName);
        Assert.Equal("/result", snapshot.ResultUrl);
    }

    // ── Job lifecycle (queued → running → succeeded) ──────────────

    [Fact]
    public async Task Job_CompletesSuccessfully_StatusBecomesSucceeded()
    {
        var svc = new BackgroundJobService();
        var tcs = new TaskCompletionSource();

        var jobId = svc.StartJob("Complete", null, async (progress, ct) =>
        {
            progress.Report(50, "half way");
            await Task.Yield();
            tcs.SetResult();
        });

        await tcs.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await WaitUntilAsync(() => { svc.TryGetJob(jobId, out var s); return s?.Status == BackgroundJobStatus.Succeeded; });

        svc.TryGetJob(jobId, out var snapshot);
        Assert.Equal(BackgroundJobStatus.Succeeded, snapshot!.Status);
        Assert.Equal(100, snapshot.PercentComplete);
    }

    [Fact]
    public async Task Job_Throws_StatusBecomesFailed()
    {
        var svc = new BackgroundJobService();
        var started = new SemaphoreSlim(0, 1);

        var jobId = svc.StartJob("Boom", null, async (_, _) =>
        {
            started.Release();
            await Task.Yield();
            throw new InvalidOperationException("test error");
        });

        await started.WaitAsync(TimeSpan.FromSeconds(5));
        await WaitUntilAsync(() => { svc.TryGetJob(jobId, out var s); return s?.Status == BackgroundJobStatus.Failed; });

        svc.TryGetJob(jobId, out var snapshot);
        Assert.Equal(BackgroundJobStatus.Failed, snapshot!.Status);
        Assert.Contains("test error", snapshot.Error);
    }

    // ── Progress reporting ────────────────────────────────────────

    [Fact]
    public async Task ProgressReporter_UpdatesSnapshot()
    {
        var svc = new BackgroundJobService();
        var ready = new SemaphoreSlim(0, 1);
        var proceed = new SemaphoreSlim(0, 1);

        var jobId = svc.StartJob("Progress", null, async (progress, ct) =>
        {
            progress.Report(33, "one-third done");
            ready.Release();
            await proceed.WaitAsync(ct);
        });

        await ready.WaitAsync(TimeSpan.FromSeconds(5));

        svc.TryGetJob(jobId, out var snapshot);
        Assert.Equal(33, snapshot!.PercentComplete);
        Assert.Equal("one-third done", snapshot.Description);

        proceed.Release();
    }

    [Fact]
    public async Task ProgressReporter_ClampsBelowZero()
    {
        var svc = new BackgroundJobService();
        var ready = new SemaphoreSlim(0, 1);
        var proceed = new SemaphoreSlim(0, 1);

        var jobId = svc.StartJob("Clamp", null, async (progress, ct) =>
        {
            progress.Report(-10, "negative");
            ready.Release();
            await proceed.WaitAsync(ct);
        });

        await ready.WaitAsync(TimeSpan.FromSeconds(5));
        svc.TryGetJob(jobId, out var snapshot);
        Assert.Equal(0, snapshot!.PercentComplete);

        proceed.Release();
    }

    [Fact]
    public async Task ProgressReporter_ClampsAbove100()
    {
        var svc = new BackgroundJobService();
        var ready = new SemaphoreSlim(0, 1);
        var proceed = new SemaphoreSlim(0, 1);

        var jobId = svc.StartJob("Clamp100", null, async (progress, ct) =>
        {
            progress.Report(150, "over");
            ready.Release();
            await proceed.WaitAsync(ct);
        });

        await ready.WaitAsync(TimeSpan.FromSeconds(5));
        svc.TryGetJob(jobId, out var snapshot);
        Assert.Equal(100, snapshot!.PercentComplete);

        proceed.Release();
    }

    // ── StartJob null guard ───────────────────────────────────────

    [Fact]
    public void StartJob_NullWork_Throws()
    {
        var svc = new BackgroundJobService();
        Assert.Throws<ArgumentNullException>(() =>
            svc.StartJob("op", null, null!));
    }

    // ── CompletedAt is set ────────────────────────────────────────

    [Fact]
    public async Task Job_OnCompletion_SetsCompletedAt()
    {
        var svc = new BackgroundJobService();
        var done = new TaskCompletionSource();

        var jobId = svc.StartJob("Timer", null, async (_, _) =>
        {
            await Task.Yield();
            done.SetResult();
        });

        await done.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await WaitUntilAsync(() => { svc.TryGetJob(jobId, out var s); return s?.CompletedAt != null; });

        svc.TryGetJob(jobId, out var snapshot);
        Assert.NotNull(snapshot!.CompletedAt);
    }

    // ── Pruning / CancellationTokenSource disposal ────────────────

    [Fact]
    public async Task PruneOldJobs_DisposesCompletedJobCts()
    {
        var svc = new BackgroundJobService();
        var done = new TaskCompletionSource();

        var jobId = svc.StartJob("Prunable", null, async (_, _) =>
        {
            await Task.Yield();
            done.SetResult();
        });

        await done.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await WaitUntilAsync(() => { svc.TryGetJob(jobId, out var s); return s?.Status == BackgroundJobStatus.Succeeded; });

        // Retrieve the raw entry via the internal Jobs dictionary.
        var jobsField = typeof(BackgroundJobService).GetField("_jobs",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        var jobs = (System.Collections.Concurrent.ConcurrentDictionary<string, BackgroundJobService.JobEntry>)jobsField.GetValue(svc)!;
        Assert.True(jobs.TryGetValue(jobId, out var entry));
        var cts = entry!.Cts;

        // Force CompletedAt to be old enough to be pruned.
        entry.CompletedAt = DateTime.UtcNow - BackgroundJobService.RetentionPeriod - TimeSpan.FromSeconds(1);

        // Start a new job – this triggers PruneOldJobs internally.
        svc.StartJob("Trigger", null, (_, _) => Task.CompletedTask);

        // The old job should be gone from the registry.
        Assert.False(svc.TryGetJob(jobId, out _));

        // The CTS should be disposed: accessing Token after disposal throws ObjectDisposedException.
        Assert.Throws<ObjectDisposedException>(() => { var _ = cts.Token; });
    }
}
