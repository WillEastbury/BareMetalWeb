using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

// Test entity with a singleton flag property
[DataEntity("Singleton Test Items", Slug = "singleton-test-items")]
public class SingletonTestItem : BaseDataObject
{
    public override string EntityTypeName => "Singleton Test Items";
    private const int Ord_IsDefault = BaseFieldCount + 0;
    private const int Ord_Name = BaseFieldCount + 1;
    internal new const int TotalFieldCount = BaseFieldCount + 2;

    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("IsDefault", Ord_IsDefault),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Name", Ord_Name),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public SingletonTestItem() : base(TotalFieldCount) { }
    public SingletonTestItem(string createdBy) : base(TotalFieldCount, createdBy) { }


    [DataField(Label = "Name")]
    public string Name
    {
        get => (string?)_values[Ord_Name] ?? string.Empty;
        set => _values[Ord_Name] = value;
    }



    [DataField(Label = "Is Default")]
    [SingletonFlag]
    public bool IsDefault
    {
        get => (bool)(_values[Ord_IsDefault] ?? false);
        set => _values[Ord_IsDefault] = value;
    }
}

// Test entity with multiple singleton flag properties
[DataEntity("Multi Singleton Test Items", Slug = "multi-singleton-test-items")]
public class MultiSingletonTestItem : BaseDataObject
{
    public override string EntityTypeName => "Multi Singleton Test Items";
    private const int Ord_IsPrimary = BaseFieldCount + 0;
    private const int Ord_IsSecondary = BaseFieldCount + 1;
    private const int Ord_Name = BaseFieldCount + 2;
    internal new const int TotalFieldCount = BaseFieldCount + 3;

    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("IsPrimary", Ord_IsPrimary),
        new FieldSlot("IsSecondary", Ord_IsSecondary),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Name", Ord_Name),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public MultiSingletonTestItem() : base(TotalFieldCount) { }
    public MultiSingletonTestItem(string createdBy) : base(TotalFieldCount, createdBy) { }


    [DataField(Label = "Name")]
    public string Name
    {
        get => (string?)_values[Ord_Name] ?? string.Empty;
        set => _values[Ord_Name] = value;
    }



    [DataField(Label = "Is Primary")]
    [SingletonFlag]
    public bool IsPrimary
    {
        get => (bool)(_values[Ord_IsPrimary] ?? false);
        set => _values[Ord_IsPrimary] = value;
    }



    [DataField(Label = "Is Secondary")]
    [SingletonFlag]
    public bool IsSecondary
    {
        get => (bool)(_values[Ord_IsSecondary] ?? false);
        set => _values[Ord_IsSecondary] = value;
    }
}

public class SingletonFlagTests : IDisposable
{
    private readonly string _testRoot;
    private readonly WalDataProvider _provider;

    public SingletonFlagTests()
    {
        _testRoot = Path.Combine(Path.GetTempPath(), "BareMetalWeb_SingletonTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testRoot);
        DataScaffold.RegisterEntity<SingletonTestItem>();
        DataScaffold.RegisterEntity<MultiSingletonTestItem>();
        _provider = new WalDataProvider(_testRoot);
    }

    public void Dispose()
    {
        _provider.Dispose();
        if (Directory.Exists(_testRoot))
        {
            try { Directory.Delete(_testRoot, recursive: true); }
            catch { /* best effort cleanup */ }
        }
    }

    [Fact]
    public void SingletonFlagAttribute_IsApplied_ToTestItemIsDefault()
    {
        // Verify that the SingletonTestItem.IsDefault property has the [SingletonFlag] attribute applied
        var prop = typeof(SingletonTestItem).GetProperty(nameof(SingletonTestItem.IsDefault));
        Assert.NotNull(prop);
        var attr = prop!.GetCustomAttributes(typeof(SingletonFlagAttribute), inherit: true);
        Assert.NotEmpty(attr);
    }
}
