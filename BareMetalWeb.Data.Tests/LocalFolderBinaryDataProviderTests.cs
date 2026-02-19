using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class LocalFolderBinaryDataProviderTests : IDisposable
{
    private readonly string _testRoot;

    public LocalFolderBinaryDataProviderTests()
    {
        _testRoot = Path.Combine(Path.GetTempPath(), "BareMetalWeb_Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testRoot);
    }

    public void Dispose()
    {
        if (Directory.Exists(_testRoot))
        {
            try
            {
                Directory.Delete(_testRoot, recursive: true);
            }
            catch
            {
                // Best effort cleanup
            }
        }
    }

    [Fact]
    public void AcquireIndexLock_CanAcquireLock_Successfully()
    {
        // Arrange
        var provider = new LocalFolderBinaryDataProvider(_testRoot);
        
        // Act
        using var lockHandle = provider.AcquireIndexLock("TestEntity", "TestField");
        
        // Assert
        Assert.NotNull(lockHandle);
    }

    [Fact]
    public void AcquireIndexLock_ReleasesLock_AfterDispose()
    {
        // Arrange
        var provider = new LocalFolderBinaryDataProvider(_testRoot);
        
        // Act - First acquisition
        using (var lockHandle1 = provider.AcquireIndexLock("TestEntity", "TestField"))
        {
            Assert.NotNull(lockHandle1);
        }
        
        // Assert - Second acquisition should succeed after first is disposed
        using var lockHandle2 = provider.AcquireIndexLock("TestEntity", "TestField");
        Assert.NotNull(lockHandle2);
    }

    [Fact]
    public void AcquireIndexLock_RetryLogic_HandlesRapidSuccessiveAcquisitions()
    {
        // Arrange
        var provider = new LocalFolderBinaryDataProvider(_testRoot);
        
        // Act & Assert - Multiple rapid successive lock acquisitions should all succeed
        for (int i = 0; i < 10; i++)
        {
            using var lockHandle = provider.AcquireIndexLock("TestEntity", "TestField");
            Assert.NotNull(lockHandle);
        }
    }

    [Fact]
    public async Task AcquireIndexLock_ConcurrentAccess_OneSucceedsOthersRetry()
    {
        // Arrange
        var provider = new LocalFolderBinaryDataProvider(_testRoot);
        var acquiredCount = 0;
        var exceptionCount = 0;
        var completedCount = 0;
        var lockHeld = new ManualResetEventSlim(false);
        var startSignal = new ManualResetEventSlim(false);
        
        // Act - Simulate concurrent access from multiple threads
        var tasks = new Task[5];
        for (int i = 0; i < tasks.Length; i++)
        {
            var threadIndex = i;
            tasks[i] = Task.Run(() =>
            {
                try
                {
                    // Wait for all threads to be ready
                    startSignal.Wait();
                    
                    using var lockHandle = provider.AcquireIndexLock("TestEntity", "TestField");
                    Interlocked.Increment(ref acquiredCount);
                    
                    if (threadIndex == 0)
                    {
                        // First thread holds the lock briefly to force others to retry
                        Thread.Sleep(50);
                        lockHeld.Set();
                    }
                }
                catch (IOException)
                {
                    Interlocked.Increment(ref exceptionCount);
                }
                finally
                {
                    Interlocked.Increment(ref completedCount);
                }
            });
        }
        
        // Start all threads simultaneously
        startSignal.Set();
        
        // Wait for all tasks to complete
        await Task.WhenAll(tasks);
        
        // Assert - All threads should eventually succeed or handle contention gracefully
        // With retry logic, all should eventually acquire the lock
        Assert.Equal(tasks.Length, completedCount);
        Assert.True(acquiredCount >= tasks.Length - 1, $"Expected at least {tasks.Length - 1} acquisitions, got {acquiredCount}");
    }

    [Fact]
    public void AcquireIndexLock_ThrowsArgumentException_WhenEntityNameIsEmpty()
    {
        // Arrange
        var provider = new LocalFolderBinaryDataProvider(_testRoot);
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => provider.AcquireIndexLock("", "TestField"));
    }

    [Fact]
    public void AcquireIndexLock_ThrowsArgumentException_WhenFieldNameIsEmpty()
    {
        // Arrange
        var provider = new LocalFolderBinaryDataProvider(_testRoot);
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => provider.AcquireIndexLock("TestEntity", ""));
    }

    [Fact]
    public void AcquireIndexLock_CreatesLockFileInCorrectLocation()
    {
        // Arrange
        var provider = new LocalFolderBinaryDataProvider(_testRoot);
        
        // Act
        using (var lockHandle = provider.AcquireIndexLock("TestEntity", "TestField"))
        {
            // Assert - Lock file should exist while held
            var expectedLockPath = Path.Combine(_testRoot, "Index", "TestEntity", "TestField.log.lock");
            Assert.True(File.Exists(expectedLockPath), $"Lock file should exist at {expectedLockPath}");
        }
    }
}
