using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[Collection("DataStoreProvider")]
public sealed class AuditServiceTests : IDisposable
{
    private readonly string _testFolder;
    private readonly IDataObjectStore _store;
    private readonly AuditService _auditService;

    public AuditServiceTests()
    {
        _testFolder = Path.Combine(Path.GetTempPath(), $"audit-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testFolder);
        
        var provider = new LocalFolderBinaryDataProvider(_testFolder);
        _store = new DataObjectStore();
        _store.RegisterProvider(provider);
        DataStoreProvider.Current = _store;
        
        _auditService = new AuditService(_store) { RunSynchronously = true };
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_testFolder))
                Directory.Delete(_testFolder, true);
        }
        catch
        {
            // Ignore cleanup errors
        }
    }

    [Fact]
    public async Task AuditCreateAsync_CreatesAuditEntry()
    {
        // Arrange
        var testEntity = new TestEntity("testuser")
        {
            Key = 1,
            Name = "Test Entity",
            Value = 42
        };

        // Act
        await _auditService.AuditCreateAsync(testEntity, "testuser");
        
        // Assert
        var auditEntries = await _store.QueryAsync<AuditEntry>();
        var entry = auditEntries.FirstOrDefault(e => e.EntityKey == testEntity.Key);
        Assert.NotNull(entry);
        Assert.Equal(typeof(TestEntity).Name, entry.EntityType);
        Assert.Equal(testEntity.Key, entry.EntityKey);
        Assert.Equal(AuditOperation.Create, entry.Operation);
        Assert.Equal("testuser", entry.UserName);
    }

    [Fact]
    public async Task AuditUpdateAsync_DetectsFieldChanges()
    {
        // Arrange
        var oldEntity = new TestEntity("testuser")
        {
            Key = 2,
            Name = "Old Name",
            Value = 10
        };
        
        var newEntity = new TestEntity("testuser")
        {
            Key = oldEntity.Key,
            CreatedOnUtc = oldEntity.CreatedOnUtc,
            CreatedBy = oldEntity.CreatedBy,
            Name = "New Name",
            Value = 20
        };

        // Act
        await _auditService.AuditUpdateAsync(oldEntity, newEntity, "testuser");

        // Assert
        var auditEntries = (await _store.QueryAsync<AuditEntry>()).ToList();
        var entry = auditEntries.FirstOrDefault(e => e.EntityKey == oldEntity.Key && e.Operation == AuditOperation.Update);
        Assert.NotNull(entry);
        Assert.Equal(AuditOperation.Update, entry.Operation);
        Assert.Equal(2, entry.FieldChanges.Count);
        
        var nameChange = entry.FieldChanges.FirstOrDefault(c => c.FieldName == nameof(TestEntity.Name));
        Assert.NotNull(nameChange);
        Assert.Equal("Old Name", nameChange.OldValue);
        Assert.Equal("New Name", nameChange.NewValue);
        
        var valueChange = entry.FieldChanges.FirstOrDefault(c => c.FieldName == nameof(TestEntity.Value));
        Assert.NotNull(valueChange);
        Assert.Equal("10", valueChange.OldValue);
        Assert.Equal("20", valueChange.NewValue);
    }

    [Fact]
    public async Task AuditUpdateAsync_SkipsWhenNoMeaningfulChanges()
    {
        // Arrange
        var oldEntity = new TestEntity("testuser")
        {
            Key = 3,
            Name = "Same Name",
            Value = 42
        };
        
        var newEntity = new TestEntity("testuser")
        {
            Key = oldEntity.Key,
            CreatedOnUtc = oldEntity.CreatedOnUtc,
            CreatedBy = oldEntity.CreatedBy,
            Name = "Same Name",
            Value = 42
        };
        newEntity.Touch("testuser"); // Only metadata changed

        // Act
        await _auditService.AuditUpdateAsync(oldEntity, newEntity, "testuser");

        // Assert - no audit entry should be created since only metadata changed
        var auditEntries = await _store.QueryAsync<AuditEntry>();
        var entry = auditEntries.FirstOrDefault(e => e.EntityKey == oldEntity.Key);
        
        Assert.Null(entry); // No audit entry for metadata-only changes
    }

    [Fact]
    public async Task AuditDeleteAsync_CreatesAuditEntry()
    {
        // Arrange
        var entityKey = (uint)Random.Shared.Next(1, int.MaxValue);

        // Act
        await _auditService.AuditDeleteAsync<TestEntity>(entityKey, "testuser");

        // Assert
        var auditEntries = await _store.QueryAsync<AuditEntry>();
        var entry = auditEntries.FirstOrDefault(e => e.EntityKey == entityKey);
        
        Assert.NotNull(entry);
        Assert.Equal(typeof(TestEntity).Name, entry.EntityType);
        Assert.Equal(AuditOperation.Delete, entry.Operation);
        Assert.Equal("testuser", entry.UserName);
    }

    [Fact]
    public async Task AuditRemoteCommandAsync_CreatesAuditEntry()
    {
        // Arrange
        var testEntity = new TestEntity("testuser")
        {
            Key = 4,
            Name = "Test Entity",
            Value = 42
        };
        var result = RemoteCommandResult.Ok("Command executed successfully");

        // Act
        await _auditService.AuditRemoteCommandAsync(testEntity, "TestCommand", "testuser", null, result);

        // Assert
        var auditEntries = await _store.QueryAsync<AuditEntry>();
        var entry = auditEntries.FirstOrDefault(e => e.EntityKey == testEntity.Key);
        
        Assert.NotNull(entry);
        Assert.Equal(AuditOperation.RemoteCommand, entry.Operation);
        Assert.Equal("TestCommand", entry.CommandName);
        Assert.Contains("Success: True", entry.CommandResult);
    }

    [Fact]
    public async Task GetEntityHistoryAsync_ReturnsAuditEntriesForEntity()
    {
        // Arrange
        var testEntity = new TestEntity("testuser") { Key = 5, Name = "Test", Value = 1 };
        
        await _auditService.AuditCreateAsync(testEntity, "testuser");
        
        var updatedEntity = new TestEntity("testuser") { Key = testEntity.Key, CreatedOnUtc = testEntity.CreatedOnUtc, CreatedBy = testEntity.CreatedBy, Name = "Updated", Value = 2 };
        await _auditService.AuditUpdateAsync(testEntity, updatedEntity, "testuser");
        
        await _auditService.AuditDeleteAsync<TestEntity>(testEntity.Key, "testuser");

        // Act
        var allEntries = await _store.QueryAsync<AuditEntry>();
        var history = allEntries.Where(e => e.EntityKey == testEntity.Key && e.EntityType == "TestEntity").ToList();

        // Assert
        Assert.Equal(3, history.Count);
        Assert.Contains(history, e => e.Operation == AuditOperation.Create);
        Assert.Contains(history, e => e.Operation == AuditOperation.Update);
        Assert.Contains(history, e => e.Operation == AuditOperation.Delete);
    }
    
    // Test entity class for audit testing
    [DataEntity("Test Entity", Slug = "testentity")]
    private sealed class TestEntity : BaseDataObject
    {
        public TestEntity() : base()
        {
        }

        public TestEntity(string createdBy) : base(createdBy)
        {
        }

        [DataField(Label = "Name")]
        public string Name { get; set; } = string.Empty;

        [DataField(Label = "Value")]
        public int Value { get; set; }
    }
}
