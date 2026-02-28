using System.Collections;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests that BuildFormFields works for entities with [DataLookup] attributes.
/// Regression test for the create-route 500 bug caused by QueryByType attempting
/// an invalid cast from ValueTask&lt;IEnumerable&lt;T&gt;&gt; to ValueTask&lt;IEnumerable&gt;.
/// </summary>
[Collection("DataStoreProvider")]
public class DataScaffoldLookupTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;

    public DataScaffoldLookupTests()
    {
        _originalStore = DataStoreProvider.Current;
        DataStoreProvider.Current = new InMemoryDataStore();

        // Force UserClasses assembly to load before scanning
        _ = typeof(Product).Assembly;
        DataEntityRegistry.RegisterAllEntities();
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
    }

    [Fact]
    public void BuildFormFields_ForCreate_WithLookupFields_DoesNotThrow()
    {
        // Product has [DataLookup] on UnitOfMeasureId and CurrencyId
        var meta = DataScaffold.GetEntityByType(typeof(Product));
        Assert.NotNull(meta);

        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);
        Assert.NotNull(fields);
        Assert.True(fields.Count > 0, "Expected at least one form field for Product create");
    }

    [Fact]
    public void BuildFormFields_ForCreate_WithLookupFields_ReturnsLookupListType()
    {
        var meta = DataScaffold.GetEntityByType(typeof(Product));
        Assert.NotNull(meta);

        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);

        // UnitOfMeasureId and CurrencyId should be LookupList fields
        var uomField = fields.FirstOrDefault(f => f.Name == "UnitOfMeasureId");
        Assert.NotNull(uomField);
        Assert.Equal(Rendering.Models.FormFieldType.LookupList, uomField.FieldType);

        var currencyField = fields.FirstOrDefault(f => f.Name == "CurrencyId");
        Assert.NotNull(currencyField);
        Assert.Equal(Rendering.Models.FormFieldType.LookupList, currencyField.FieldType);
    }

    [Fact]
    public void BuildFormFields_ForCreate_WithLookupFields_PopulatesLookupOptions()
    {
        // Seed some lookup data
        var uom = new UnitOfMeasure { Key = 1, Name = "Each" };
        DataStoreProvider.Current.Save(uom);

        var currency = new Currency { Key = 1 };
        // Set IsoCode via reflection (it's a property)
        typeof(Currency).GetProperty("IsoCode")?.SetValue(currency, "USD");

        DataStoreProvider.Current.Save(currency);

        // Clear lookup cache to force re-query
        ClearLookupCache();

        var meta = DataScaffold.GetEntityByType(typeof(Product));
        Assert.NotNull(meta);

        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);

        var uomField = fields.FirstOrDefault(f => f.Name == "UnitOfMeasureId");
        Assert.NotNull(uomField);
        Assert.NotNull(uomField.LookupOptions);
        Assert.Contains(uomField.LookupOptions, o => o.Key == "1" && o.Value == "Each");
    }

    [Fact]
    public void BuildFormFields_ForCreate_Order_WithCustomerLookup_DoesNotThrow()
    {
        // Order has [DataLookup] on CustomerId and CurrencyId
        var meta = DataScaffold.GetEntityByType(typeof(Order));
        Assert.NotNull(meta);

        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);
        Assert.NotNull(fields);
        Assert.True(fields.Count > 0);
    }

    [Fact]
    public void BuildFormFields_ForEdit_WithLookupFields_DoesNotThrow()
    {
        var product = new Product
        {
            Key = 1,
            Name = "Widget",
            Sku = "W001",
            UnitOfMeasureId = "1",
            CurrencyId = "1",
            Price = 9.99m
        };

        var meta = DataScaffold.GetEntityByType(typeof(Product));
        Assert.NotNull(meta);

        var fields = DataScaffold.BuildFormFields(meta, product, forCreate: false);
        Assert.NotNull(fields);
        Assert.True(fields.Count > 0);
    }

    private static void ClearLookupCache()
    {
        // Use reflection to clear the private lookup cache
        var cacheField = typeof(DataScaffold).GetField("LookupCache",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        if (cacheField?.GetValue(null) is IDictionary cache)
            cache.Clear();
    }

    /// <summary>
    /// Minimal in-memory IDataObjectStore for testing.
    /// </summary>
    private class InMemoryDataStore : IDataObjectStore
    {
        private readonly Dictionary<(Type, uint), BaseDataObject> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        public void Save<T>(T obj) where T : BaseDataObject
            => _store[(typeof(T), obj.Key)] = obj;

        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        { Save(obj); return ValueTask.CompletedTask; }

        public T? Load<T>(uint key) where T : BaseDataObject
            => _store.TryGetValue((typeof(T), key), out var obj) ? obj as T : null;

        public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Load<T>(key));

        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
            => _store.Values.OfType<T>();

        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Query<T>(query));

        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Query<T>(query).Count());

        public void Delete<T>(uint key) where T : BaseDataObject
            => _store.Remove((typeof(T), key));

        public ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
        { Delete<T>(key); return ValueTask.CompletedTask; }
    }

    [DataEntity("Upload test entities", Slug = "upload-test-entities")]
    private sealed class UploadTestEntity : BaseDataObject
    {
        [ImageField(Label = "Photo", Order = 1, MaxFileSizeBytes = 1234, AllowedMimeTypes = new[] { "image/png" }, MaxWidth = 800, MaxHeight = 600)]
        public StoredFileData? Photo { get; set; }
    }

    [Fact]
    public void RegisterEntity_WithImageFieldAttribute_BuildsUploadMetadata()
    {
        // Arrange
        DataScaffold.RegisterEntity<UploadTestEntity>();
        var meta = DataScaffold.GetEntityByType(typeof(UploadTestEntity));

        // Act
        var photoField = meta?.Fields.FirstOrDefault(f => f.Name == nameof(UploadTestEntity.Photo));

        // Assert
        Assert.NotNull(photoField);
        Assert.Equal(Rendering.Models.FormFieldType.Image, photoField!.FieldType);
        Assert.NotNull(photoField.Upload);
        Assert.Equal(1234, photoField.Upload!.MaxFileSizeBytes);
        Assert.Equal("image/png", photoField.Upload.AllowedMimeTypes[0]);
        Assert.Equal(800, photoField.Upload.MaxImageWidth);
        Assert.Equal(600, photoField.Upload.MaxImageHeight);
    }

    [Fact]
    public void BuildFormFields_WithStoredImageValue_PopulatesExistingFileMetadata()
    {
        // Arrange
        DataScaffold.RegisterEntity<UploadTestEntity>();
        var meta = DataScaffold.GetEntityByType(typeof(UploadTestEntity));
        Assert.NotNull(meta);
        var instance = new UploadTestEntity
        {
            Key = 1,
            Photo = new StoredFileData { FileName = "avatar.png", StorageKey = "x/y.png", ContentType = "image/png", IsImage = true }
        };

        // Act
        var fields = DataScaffold.BuildFormFields(meta!, instance, forCreate: false);
        var photoField = fields.FirstOrDefault(f => f.Name == nameof(UploadTestEntity.Photo));

        // Assert
        Assert.NotNull(photoField);
        Assert.Equal("avatar.png", photoField!.ExistingFileName);
        Assert.Equal("/api/upload-test-entities/1/files/Photo", photoField.ExistingFileUrl);
        Assert.Equal("image/png", photoField.Accept);
    }

    [Fact]
    public void BuildFormFields_ForEdit_WithCountryField_SetsSelectedValue()
    {
        // Arrange
        var address = new Address
        {
            Key = 1,
            Label = "Main",
            Line1 = "123 Example Street",
            City = "London",
            Country = "GB" // United Kingdom
        };

        var meta = DataScaffold.GetEntityByType(typeof(Address));
        Assert.NotNull(meta);

        // Act
        var fields = DataScaffold.BuildFormFields(meta, address, forCreate: false);
        var countryField = fields.FirstOrDefault(f => f.Name == nameof(Address.Country));

        // Assert
        Assert.NotNull(countryField);
        Assert.Equal(Rendering.Models.FormFieldType.Country, countryField!.FieldType);
        Assert.Equal("GB", countryField.SelectedValue); // This should be set for proper dropdown binding
    }

    /// <summary>
    /// Regression test: BuildListRows must not throw when the lookup data store contains
    /// items with duplicate IDs (e.g. after repeated sample-data generation without clear).
    /// </summary>
    [Fact]
    public void BuildListRows_WithDuplicateLookupIds_DoesNotThrow()
    {
        // Arrange: two Address objects with the same Id (simulates corrupted/duplicated store data)
        DataStoreProvider.Current = new DuplicateIdDataStore();
        ClearLookupCache();

        var meta = DataScaffold.GetEntityByType(typeof(Customer));
        Assert.NotNull(meta);

        var customer = new Customer
        {
            Key = 1,
            Name = "Test Customer",
            Email = "test@example.com",
            AddressId = "1"
        };

        // Act – must not throw ArgumentException ("An item with the same key has already been added")
        var rows = DataScaffold.BuildListRows(meta!, new[] { customer }, "/admin/data/customers", includeActions: false);

        // Assert
        Assert.NotNull(rows);
        Assert.Single(rows);
    }

    /// <summary>
    /// Regression test: BuildFormFields for an entity with an Enum field must populate
    /// LookupOptions and SelectedValue so the VNext edit form can pre-select the saved value.
    /// </summary>
    [Fact]
    public void BuildFormFields_ForEdit_WithEnumField_PopulatesOptionsAndSelectedValue()
    {
        // Arrange: a TimeTablePlan with Day = Tuesday
        var plan = new TimeTablePlan
        {
            Key = 1,
            SubjectId = "subj-1",
            Day = BareMetalWeb.Data.DataObjects.DayOfWeek.Tuesday,
            StartTime = new TimeOnly(12, 0)
        };

        var meta = DataScaffold.GetEntityByType(typeof(TimeTablePlan));
        Assert.NotNull(meta);

        // Act
        var fields = DataScaffold.BuildFormFields(meta, plan, forCreate: false);
        var dayField = fields.FirstOrDefault(f => f.Name == nameof(TimeTablePlan.Day));

        // Assert
        Assert.NotNull(dayField);
        Assert.Equal(Rendering.Models.FormFieldType.Enum, dayField!.FieldType);
        Assert.NotNull(dayField.LookupOptions);
        Assert.True(dayField.LookupOptions!.Count > 0, "Enum options must be populated");
        Assert.Contains(dayField.LookupOptions, o => o.Key == "Tuesday");
        Assert.Equal("Tuesday", dayField.SelectedValue);
    }

    /// <summary>
    /// A data store that deliberately returns two Address items with the same Id,
    /// replicating what can happen after repeated sample-data generation.
    /// </summary>
    private sealed class DuplicateIdDataStore : IDataObjectStore
    {
        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        public void Save<T>(T obj) where T : BaseDataObject { }
        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.CompletedTask;

        public T? Load<T>(uint key) where T : BaseDataObject => null;
        public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult((T?)null);

        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
        {
            if (typeof(T) == typeof(Address))
            {
                // Return two Address objects sharing the same Id – the duplicated-data scenario
                return (IEnumerable<T>)(IEnumerable<Address>)new[]
                {
                    new Address { Key = 1, Label = "First copy",  Line1 = "1 Main St", City = "Springfield", Country = "US" },
                    new Address { Key = 1, Label = "Second copy", Line1 = "2 Main St", City = "Springfield", Country = "US" }
                };
            }

            return Enumerable.Empty<T>();
        }

        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Query<T>(query));

        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(0);

        public void Delete<T>(uint key) where T : BaseDataObject { }
        public ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.CompletedTask;
    }
}
