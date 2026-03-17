using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[Collection("SharedState")]
public sealed class AuditServiceTests : IDisposable
{
    private readonly string _testFolder;
    private readonly IDataObjectStore _store;
    private readonly AuditService _auditService;

    public AuditServiceTests()
    {
        _testFolder = Path.Combine(Path.GetTempPath(), $"audit-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testFolder);
        
        var provider = new WalDataProvider(_testFolder);
        _store = new DataObjectStore();
        _store.RegisterProvider(provider);
        DataStoreProvider.Current = _store;

        DataScaffold.RegisterEntity<AuditEntry>();
        DataScaffold.RegisterEntity<AuditTestEntity>();
        
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
    public async Task AuditUpdateAsync_SkipsWhenNoMeaningfulChanges()
    {
        // Arrange
        var oldEntity = new AuditTestEntity("testuser")
        {
            Key = 3,
            Name = "Same Name",
            Value = 42
        };
        
        var newEntity = new AuditTestEntity("testuser")
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

    
    // Test entity class for audit testing
    [DataEntity("Audit Test Entity", Slug = "audit-test-entity")]
    public sealed class AuditTestEntity : BaseDataObject
    {
        private const int Ord_Name = BaseFieldCount + 0;
        private const int Ord_Value = BaseFieldCount + 1;
        internal new const int TotalFieldCount = BaseFieldCount + 2;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Name", Ord_Name),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Value", Ord_Value),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public AuditTestEntity() : base(TotalFieldCount) { }
        public AuditTestEntity(string createdBy) : base(TotalFieldCount, createdBy) { }



        [DataField(Label = "Name")]
        public string Name
        {
            get => (string?)_values[Ord_Name] ?? string.Empty;
            set => _values[Ord_Name] = value;
        }



        [DataField(Label = "Value")]
        public int Value
        {
            get => (int)(_values[Ord_Value] ?? 0);
            set => _values[Ord_Value] = value;
        }
    }
}
