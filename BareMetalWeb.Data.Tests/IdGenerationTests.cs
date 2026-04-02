using System;
using System.Collections.Generic;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[Collection("SharedState")]
public class IdGenerationTests
{
    [Fact]
    public void DefaultIdGenerator_Sequential_GeneratesSequentialKeys()
    {
        // Arrange
        var generator = new DefaultIdGenerator();
        var entityType = typeof(TestEntity);

        // Act
        var key1 = generator.GenerateKey(entityType);
        var key2 = generator.GenerateKey(entityType);
        var key3 = generator.GenerateKey(entityType);

        // Assert
        Assert.True(key1 > 0);
        Assert.True(key2 > key1);
        Assert.True(key3 > key2);
    }

    [Fact]
    public void DefaultIdGenerator_Sequential_IsolatesSequencesPerType()
    {
        // Arrange
        var generator = new DefaultIdGenerator();
        var type1 = typeof(TestEntity);
        var type2 = typeof(AnotherTestEntity);

        // Act
        var type1_key1 = generator.GenerateKey(type1);
        var type2_key1 = generator.GenerateKey(type2);
        var type1_key2 = generator.GenerateKey(type1);

        // Assert - Each type has its own sequence
        Assert.True(type1_key2 > type1_key1);
        Assert.Equal(type1_key1 + 1, type1_key2);
    }

    // Test entities
    private class TestEntity : DataRecord
    {
        internal new const int TotalFieldCount = BaseFieldCount;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TestEntity() : base(TotalFieldCount) { }
        public TestEntity(string createdBy) : base(TotalFieldCount, createdBy) { }
    }

    private class AnotherTestEntity : DataRecord
    {
        internal new const int TotalFieldCount = BaseFieldCount;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public AnotherTestEntity() : base(TotalFieldCount) { }
        public AnotherTestEntity(string createdBy) : base(TotalFieldCount, createdBy) { }
    }

    [DataEntity("TestEntitiesWithAutoId")]
    private class TestEntityWithAutoId : DataRecord
    {
        public override string EntityTypeName => "TestEntitiesWithAutoId";
        private const int Ord_Name = BaseFieldCount + 0;
        internal new const int TotalFieldCount = BaseFieldCount + 1;

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
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TestEntityWithAutoId() : base(TotalFieldCount) { }
        public TestEntityWithAutoId(string createdBy) : base(TotalFieldCount, createdBy) { }



        [DataField(Label = "Name", Order = 1, Required = true)]
        public string Name
        {
            get => (string?)_values[Ord_Name] ?? string.Empty;
            set => _values[Ord_Name] = value;
        }
    }

    [DataEntity("TestEntitiesWithSequentialId")]
    private class TestEntityWithSequentialId : DataRecord
    {
        public override string EntityTypeName => "TestEntitiesWithSequentialId";
        private const int Ord_Name = BaseFieldCount + 0;
        internal new const int TotalFieldCount = BaseFieldCount + 1;

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
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TestEntityWithSequentialId() : base(TotalFieldCount) { }
        public TestEntityWithSequentialId(string createdBy) : base(TotalFieldCount, createdBy) { }



        [DataField(Label = "Name", Order = 1, Required = true)]
        public string Name
        {
            get => (string?)_values[Ord_Name] ?? string.Empty;
            set => _values[Ord_Name] = value;
        }
    }
}
