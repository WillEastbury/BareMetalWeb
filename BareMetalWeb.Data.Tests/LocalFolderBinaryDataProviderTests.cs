using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[Collection("SharedState")]
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

    // --- Secondary field index wiring tests (use User which has [DataIndex] on UserName and Email) ---

    [Fact]
    public void Save_WithIndexedField_BuildsFieldIndex()
    {
        // Arrange
        DataScaffold.RegisterEntity<User>();
        var provider = new LocalFolderBinaryDataProvider(_testRoot);
        var user = new User { Key = 1, UserName = "alice", Email = "alice@test.com" };

        // Act
        provider.Save(user);

        // Assert - field index paged file should exist for UserName
        var indexFile = Path.Combine(_testRoot, "Paged", "User", "UserName_index.page");
        Assert.True(File.Exists(indexFile), "Field index paged file should exist after Save");
    }

    [Fact]
    public void Query_WithIndexedFieldEquals_UsesFieldIndex()
    {
        // Arrange
        DataScaffold.RegisterEntity<User>();
        var provider = new LocalFolderBinaryDataProvider(_testRoot);
        var u1 = new User { Key = 1, UserName = "alice", Email = "alice@test.com" };
        var u2 = new User { Key = 2, UserName = "bob", Email = "bob@test.com" };
        var u3 = new User { Key = 3, UserName = "charlie", Email = "charlie@test.com" };
        provider.Save(u1);
        provider.Save(u2);
        provider.Save(u3);

        // Act - query by indexed field
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause> { new QueryClause { Field = "UserName", Operator = QueryOperator.Equals, Value = "alice" } }
        };
        var results = provider.Query<User>(query).ToList();

        // Assert - exactly 1 result
        Assert.Single(results);
        Assert.Equal("alice", results[0].UserName);
    }

    [Fact]
    public void Query_WithIndexedFieldEquals_NoResults_ReturnsEmpty()
    {
        // Arrange
        DataScaffold.RegisterEntity<User>();
        var provider = new LocalFolderBinaryDataProvider(_testRoot);
        var u1 = new User { Key = 1, UserName = "alice", Email = "alice@test.com" };
        provider.Save(u1);

        // Act
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause> { new QueryClause { Field = "UserName", Operator = QueryOperator.Equals, Value = "nonexistent" } }
        };
        var results = provider.Query<User>(query).ToList();

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void Delete_WithIndexedField_RemovesFromFieldIndex()
    {
        // Arrange
        DataScaffold.RegisterEntity<User>();
        var provider = new LocalFolderBinaryDataProvider(_testRoot);
        var user = new User { Key = 1, UserName = "todelete", Email = "del@test.com" };
        provider.Save(user);

        // Act
        provider.Delete<User>(1);

        // Assert - entity no longer found by index query
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause> { new QueryClause { Field = "UserName", Operator = QueryOperator.Equals, Value = "todelete" } }
        };
        var results = provider.Query<User>(query).ToList();
        Assert.Empty(results);
    }

    [Fact]
    public void Save_UpdateWithChangedIndexedField_UpdatesFieldIndex()
    {
        // Arrange
        DataScaffold.RegisterEntity<User>();
        var provider = new LocalFolderBinaryDataProvider(_testRoot);
        var user = new User { Key = 1, UserName = "original", Email = "orig@test.com" };
        provider.Save(user);

        // Act - change the indexed field value
        user.UserName = "updated";
        provider.Save(user);

        // Assert - old value no longer returns this entity
        var queryOld = new QueryDefinition
        {
            Clauses = new List<QueryClause> { new QueryClause { Field = "UserName", Operator = QueryOperator.Equals, Value = "original" } }
        };
        var oldResults = provider.Query<User>(queryOld).ToList();
        Assert.Empty(oldResults);

        // Assert - new value returns this entity
        var queryNew = new QueryDefinition
        {
            Clauses = new List<QueryClause> { new QueryClause { Field = "UserName", Operator = QueryOperator.Equals, Value = "updated" } }
        };
        var newResults = provider.Query<User>(queryNew).ToList();
        Assert.Single(newResults);
        Assert.Equal(1u, newResults[0].Key);
    }
}
