using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class DataObjectStoreTests
{
    private class TestProduct : BaseDataObject
    {
        private const int Ord_Name = BaseFieldCount + 0;
        private const int Ord_Price = BaseFieldCount + 1;
        internal new const int TotalFieldCount = BaseFieldCount + 2;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Name", Ord_Name),
            new FieldSlot("Price", Ord_Price),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TestProduct() : base(TotalFieldCount) { }
        public TestProduct(string createdBy) : base(TotalFieldCount, createdBy) { }

        public string Name
        {
            get => (string?)_values[Ord_Name] ?? string.Empty;
            set => _values[Ord_Name] = value;
        }

        public decimal Price
        {
            get => (decimal)(_values[Ord_Price] ?? 0m);
            set => _values[Ord_Price] = value;
        }
    }

    private class TestCustomer : BaseDataObject
    {
        private const int Ord_CompanyName = BaseFieldCount + 0;
        private const int Ord_Email = BaseFieldCount + 1;
        internal new const int TotalFieldCount = BaseFieldCount + 2;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CompanyName", Ord_CompanyName),
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Email", Ord_Email),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TestCustomer() : base(TotalFieldCount) { }
        public TestCustomer(string createdBy) : base(TotalFieldCount, createdBy) { }

        public string CompanyName
        {
            get => (string?)_values[Ord_CompanyName] ?? string.Empty;
            set => _values[Ord_CompanyName] = value;
        }

        public string Email
        {
            get => (string?)_values[Ord_Email] ?? string.Empty;
            set => _values[Ord_Email] = value;
        }
    }

    private class InMemoryDataProvider : IDataProvider
    {
        private readonly Dictionary<(string, uint), BaseDataObject> _store = new();

        public string Name => "InMemory";
        public string IndexRootPath => string.Empty;
        public string IndexFolderName => string.Empty;
        public string IndexLogExtension => string.Empty;
        public string IndexSnapshotExtension => string.Empty;
        public string IndexTempExtension => string.Empty;

        public void Save(string entityTypeName, BaseDataObject obj)
        {
            if (obj is null) throw new ArgumentNullException(nameof(obj));
            _store[(entityTypeName, obj.Key)] = obj;
        }

        public ValueTask SaveAsync(string entityTypeName, BaseDataObject obj, CancellationToken cancellationToken = default)
        {
            Save(entityTypeName, obj);
            return ValueTask.CompletedTask;
        }

        public BaseDataObject? Load(string entityTypeName, uint key)
        {
            return _store.TryGetValue((entityTypeName, key), out var obj) ? obj : null;
        }

        public ValueTask<BaseDataObject?> LoadAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(Load(entityTypeName, key));
        }

        public IEnumerable<BaseDataObject> Query(string entityTypeName, QueryDefinition? query = null)
        {
            return _store.Where(kv => kv.Key.Item1 == entityTypeName).Select(kv => kv.Value);
        }

        public ValueTask<IEnumerable<BaseDataObject>> QueryAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(Query(entityTypeName, query));
        }

        public int Count(string entityTypeName, QueryDefinition? query = null)
        {
            return Query(entityTypeName, query).Count();
        }

        public ValueTask<int> CountAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(Count(entityTypeName, query));
        }

        public void Delete(string entityTypeName, uint key)
        {
            _store.Remove((entityTypeName, key));
        }

        public ValueTask DeleteAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default)
        {
            Delete(entityTypeName, key);
            return ValueTask.CompletedTask;
        }

        public IDisposable AcquireIndexLock(string entityName, string fieldName) => new DummyDisposable();
        public bool IndexFileExists(string entityName, string fieldName, IndexFileKind kind) => false;
        public Stream OpenIndexRead(string entityName, string fieldName, IndexFileKind kind) => throw new NotImplementedException();
        public Stream OpenIndexAppend(string entityName, string fieldName, IndexFileKind kind) => throw new NotImplementedException();
        public Stream OpenIndexWriteTemp(string entityName, string fieldName, IndexFileKind kind, out string tempToken) => throw new NotImplementedException();
        public void CommitIndexTemp(string entityName, string fieldName, IndexFileKind kind, string tempToken) => throw new NotImplementedException();
        public bool PagedFileExists(string entityName, string fileName) => false;
        public IPagedFile OpenPagedFile(string entityName, string fileName, int pageSize, FileAccess access) => throw new NotImplementedException();
        public ValueTask DeletePagedFileAsync(string entityName, string fileName, CancellationToken cancellationToken = default) => throw new NotImplementedException();
        public void RenamePagedFile(string entityName, string oldFileName, string newFileName) => throw new NotImplementedException();

        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, uint> _seqCounters = new(StringComparer.OrdinalIgnoreCase);
        public uint NextSequentialKey(string entityName)
        {
            var next = _seqCounters.AddOrUpdate(entityName, 1u, (_, cur) => cur + 1);
            return (uint)next;
        }
        public void SeedSequentialKey(string entityName, uint floor)
        {
            _seqCounters.AddOrUpdate(entityName, floor, (_, cur) => Math.Max(cur, floor));
        }

        private class DummyDisposable : IDisposable
        {
            public void Dispose() { }
        }
    }

    [Fact]
    public void Save_ValidObject_SavesSuccessfully()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        var product = new TestProduct { Key = 1, Name = "Test Product", Price = 99.99m };

        // Act
        store.Save("TestProduct", product);

        // Assert
        var loaded = (TestProduct?)store.Load("TestProduct", product.Key);
        Assert.NotNull(loaded);
        Assert.Equal("Test Product", loaded.Name);
        Assert.Equal(99.99m, loaded.Price);
    }

    [Fact]
    public void Save_NullObject_ThrowsArgumentNullException()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => store.Save("TestProduct", (BaseDataObject)null!));
    }

    [Fact]
    public async Task SaveAsync_ValidObject_SavesSuccessfully()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        var product = new TestProduct { Key = 1, Name = "Async Product", Price = 49.99m };

        // Act
        await store.SaveAsync("TestProduct", product);

        // Assert
        var loaded = (TestProduct?)(await store.LoadAsync("TestProduct", product.Key));
        Assert.NotNull(loaded);
        Assert.Equal("Async Product", loaded.Name);
        Assert.Equal(49.99m, loaded.Price);
    }

    [Fact]
    public async Task SaveAsync_NullObject_ThrowsArgumentNullException()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(() => store.SaveAsync("TestProduct", (BaseDataObject)null!).AsTask());
    }

    [Fact]
    public void Load_ExistingId_ReturnsObject()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        var product = new TestProduct { Key = 123, Name = "Loaded Product", Price = 199.99m };
        store.Save("TestProduct", product);

        // Act
        var loaded = (TestProduct?)store.Load("TestProduct", 123);

        // Assert
        Assert.NotNull(loaded);
        Assert.Equal(123u, loaded.Key);
        Assert.Equal("Loaded Product", loaded.Name);
    }

    [Fact]
    public void Load_NonExistentId_ReturnsNull()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        // Act
        var loaded = (TestProduct?)store.Load("TestProduct", 999);

        // Assert
        Assert.Null(loaded);
    }

    [Fact]
    public void Load_ZeroKey_ThrowsArgumentException()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        // Act & Assert
        Assert.Throws<ArgumentException>(() => (TestProduct?)store.Load("TestProduct", 0));
    }

    [Fact]
    public async Task LoadAsync_ExistingId_ReturnsObject()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        var product = new TestProduct { Key = 456, Name = "Async Loaded", Price = 299.99m };
        await store.SaveAsync("TestProduct", product);

        // Act
        var loaded = (TestProduct?)(await store.LoadAsync("TestProduct", 456));

        // Assert
        Assert.NotNull(loaded);
        Assert.Equal(456u, loaded.Key);
        Assert.Equal("Async Loaded", loaded.Name);
    }

    [Fact]
    public async Task LoadAsync_NonExistentId_ReturnsNull()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        // Act
        var loaded = (TestProduct?)(await store.LoadAsync("TestProduct", 999));

        // Assert
        Assert.Null(loaded);
    }

    [Fact]
    public async Task LoadAsync_ZeroKey_ThrowsArgumentException()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() => store.LoadAsync("TestProduct", 0).AsTask());
    }

    [Fact]
    public void Query_MultipleObjects_ReturnsAll()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        var product1 = new TestProduct { Key = 1, Name = "Product 1", Price = 10m };
        var product2 = new TestProduct { Key = 2, Name = "Product 2", Price = 20m };
        var product3 = new TestProduct { Key = 3, Name = "Product 3", Price = 30m };

        store.Save("TestProduct", product1);
        store.Save("TestProduct", product2);
        store.Save("TestProduct", product3);

        // Act
        var results = store.Query("TestProduct").Cast<TestProduct>().ToList();

        // Assert
        Assert.Equal(3, results.Count);
        Assert.Contains(results, p => p.Name == "Product 1");
        Assert.Contains(results, p => p.Name == "Product 2");
        Assert.Contains(results, p => p.Name == "Product 3");
    }

    [Fact]
    public void Query_NoObjects_ReturnsEmpty()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        // Act
        var results = store.Query("TestProduct").Cast<TestProduct>().ToList();

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void Query_DifferentTypes_IsolatesTypes()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        var product = new TestProduct { Key = 1, Name = "Product", Price = 100m };
        var customer = new TestCustomer { Key = 1, CompanyName = "Acme Corp", Email = "test@acme.com" };

        store.Save("TestProduct", product);
        store.Save("TestCustomer", customer);

        // Act
        var products = store.Query("TestProduct").Cast<TestProduct>().ToList();
        var customers = store.Query("TestCustomer").Cast<TestCustomer>().ToList();

        // Assert
        Assert.Single(products);
        Assert.Single(customers);
        Assert.Equal("Product", products[0].Name);
        Assert.Equal("Acme Corp", customers[0].CompanyName);
    }

    [Fact]
    public async Task QueryAsync_MultipleObjects_ReturnsAll()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        var product1 = new TestProduct { Key = 1, Name = "Async 1", Price = 10m };
        var product2 = new TestProduct { Key = 2, Name = "Async 2", Price = 20m };

        await store.SaveAsync("TestProduct", product1);
        await store.SaveAsync("TestProduct", product2);

        // Act
        var results = (await store.QueryAsync("TestProduct")).Cast<TestProduct>().ToList();

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(results, p => p.Name == "Async 1");
        Assert.Contains(results, p => p.Name == "Async 2");
    }

    [Fact]
    public async Task CountAsync_MultipleObjects_ReturnsCorrectCount()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        await store.SaveAsync("TestProduct", new TestProduct { Key = 1, Name = "P1", Price = 10m });
        await store.SaveAsync("TestProduct", new TestProduct { Key = 2, Name = "P2", Price = 20m });
        await store.SaveAsync("TestProduct", new TestProduct { Key = 3, Name = "P3", Price = 30m });

        // Act
        var count = await store.CountAsync("TestProduct");

        // Assert
        Assert.Equal(3, count);
    }

    [Fact]
    public async Task CountAsync_NoObjects_ReturnsZero()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        // Act
        var count = await store.CountAsync("TestProduct");

        // Assert
        Assert.Equal(0, count);
    }

    [Fact]
    public void Delete_ExistingId_RemovesObject()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        var product = new TestProduct { Key = 100, Name = "To Delete", Price = 50m };
        store.Save("TestProduct", product);

        // Act
        store.Delete("TestProduct", 100);

        // Assert
        var loaded = (TestProduct?)store.Load("TestProduct", 100);
        Assert.Null(loaded);
    }

    [Fact]
    public void Delete_NonExistentId_DoesNotThrow()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        // Act & Assert (should not throw)
        store.Delete("TestProduct", 999);
    }

    [Fact]
    public void Delete_ZeroKey_ThrowsArgumentException()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        // Act & Assert
        Assert.Throws<ArgumentException>(() => store.Delete("TestProduct", 0));
    }

    [Fact]
    public async Task DeleteAsync_ExistingId_RemovesObject()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        var product = new TestProduct { Key = 200, Name = "Async Delete", Price = 75m };
        await store.SaveAsync("TestProduct", product);

        // Act
        await store.DeleteAsync("TestProduct", 200);

        // Assert
        var loaded = (TestProduct?)(await store.LoadAsync("TestProduct", 200));
        Assert.Null(loaded);
    }

    [Fact]
    public async Task DeleteAsync_NonExistentId_DoesNotThrow()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        // Act & Assert (should not throw)
        await store.DeleteAsync("TestProduct", 999);
    }

    [Fact]
    public async Task DeleteAsync_ZeroKey_ThrowsArgumentException()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() => store.DeleteAsync("TestProduct", 0).AsTask());
    }

    [Fact]
    public void Save_DuplicateId_OverwritesExisting()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider = new InMemoryDataProvider();
        store.RegisterProvider(provider);

        var product1 = new TestProduct { Key = 300, Name = "Original", Price = 100m };
        var product2 = new TestProduct { Key = 300, Name = "Updated", Price = 200m };

        // Act
        store.Save("TestProduct", product1);
        store.Save("TestProduct", product2);

        // Assert
        var loaded = (TestProduct?)store.Load("TestProduct", 300);
        Assert.NotNull(loaded);
        Assert.Equal("Updated", loaded.Name);
        Assert.Equal(200m, loaded.Price);
    }

    [Fact]
    public void RegisterProvider_Append_AddsToEnd()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider1 = new InMemoryDataProvider();
        var provider2 = new InMemoryDataProvider();

        // Act
        store.RegisterProvider(provider1, prepend: false);
        store.RegisterProvider(provider2, prepend: false);

        // Assert
        Assert.Equal(2, store.Providers.Count);
        Assert.Same(provider1, store.Providers[0]);
        Assert.Same(provider2, store.Providers[1]);
    }

    [Fact]
    public void RegisterProvider_Prepend_AddsToStart()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider1 = new InMemoryDataProvider();
        var provider2 = new InMemoryDataProvider();

        // Act
        store.RegisterProvider(provider1, prepend: false);
        store.RegisterProvider(provider2, prepend: true);

        // Assert
        Assert.Equal(2, store.Providers.Count);
        Assert.Same(provider2, store.Providers[0]);
        Assert.Same(provider1, store.Providers[1]);
    }

    [Fact]
    public void RegisterProvider_NullProvider_ThrowsArgumentNullException()
    {
        // Arrange
        var store = new DataObjectStore();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => store.RegisterProvider(null!));
    }

    [Fact]
    public void RegisterFallbackProvider_ValidProvider_SetsFallback()
    {
        // Arrange
        var store = new DataObjectStore();
        var fallback = new InMemoryDataProvider();

        // Act
        store.RegisterFallbackProvider(fallback);
        var product = new TestProduct { Key = 1, Name = "Fallback Test", Price = 99m };
        store.Save("TestProduct", product);

        // Assert
        var loaded = (TestProduct?)store.Load("TestProduct", product.Key);
        Assert.NotNull(loaded);
        Assert.Equal("Fallback Test", ((TestProduct)loaded).Name);
    }

    [Fact]
    public void RegisterFallbackProvider_NullProvider_ThrowsArgumentNullException()
    {
        // Arrange
        var store = new DataObjectStore();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => store.RegisterFallbackProvider(null!));
    }

    [Fact]
    public void ClearProviders_RemovesAllProviders()
    {
        // Arrange
        var store = new DataObjectStore();
        store.RegisterProvider(new InMemoryDataProvider());
        store.RegisterProvider(new InMemoryDataProvider());

        // Act
        store.ClearProviders();

        // Assert
        Assert.Empty(store.Providers);
    }

    [Fact]
    public void ResolveProvider_NoProviderRegistered_ThrowsInvalidOperationException()
    {
        // Arrange
        var store = new DataObjectStore();
        var product = new TestProduct { Key = 1, Name = "No Provider", Price = 99m };

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() => store.Save("TestProduct", product));
        Assert.Contains("No IDataProvider registered", ex.Message);
        Assert.Contains("no fallback provider configured", ex.Message);
    }

    [Fact]
    public void ResolveProvider_MultipleProviders_UsesFirstMatchingCanHandle()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider1 = new InMemoryDataProvider();
        var provider2 = new InMemoryDataProvider();

        store.RegisterProvider(provider1);
        store.RegisterProvider(provider2);

        var product = new TestProduct { Key = 1, Name = "Product", Price = 100m };
        var customer = new TestCustomer { Key = 1, CompanyName = "Customer Co", Email = "test@customer.com" };

        // Act
        store.Save("TestProduct", product);
        store.Save("TestCustomer", customer);

        // Assert
        var loadedProduct = (TestProduct?)store.Load("TestProduct", product.Key);
        var loadedCustomer = (TestCustomer?)store.Load("TestCustomer", customer.Key);

        Assert.NotNull(loadedProduct);
        Assert.NotNull(loadedCustomer);
        Assert.Equal("Product", loadedProduct.Name);
        Assert.Equal("Customer Co", loadedCustomer.CompanyName);
    }

    [Fact]
    public void ResolveProvider_NoMatchingProvider_UsesFallback()
    {
        // Arrange
        var store = new DataObjectStore();
        // No primary providers — only fallback
        var fallbackProvider = new InMemoryDataProvider();

        store.RegisterFallbackProvider(fallbackProvider);

        var product = new TestProduct { Key = 1, Name = "Fallback Product", Price = 50m };

        // Act
        store.Save("TestProduct", product);

        // Assert
        var loaded = (TestProduct?)store.Load("TestProduct", product.Key);
        Assert.NotNull(loaded);
        Assert.Equal("Fallback Product", loaded.Name);
    }

    [Fact]
    public void MultiProvider_QueryAcrossProviders_OnlyQueriesMatchingProvider()
    {
        // Arrange
        var store = new DataObjectStore();
        var provider1 = new InMemoryDataProvider();
        var provider2 = new InMemoryDataProvider();

        store.RegisterProvider(provider1);
        store.RegisterProvider(provider2);

        store.Save("TestProduct", new TestProduct { Key = 1, Name = "P1", Price = 10m });
        store.Save("TestProduct", new TestProduct { Key = 2, Name = "P2", Price = 20m });
        store.Save("TestCustomer", new TestCustomer { Key = 1, CompanyName = "C1", Email = "c1@test.com" });

        // Act
        var products = store.Query("TestProduct").Cast<TestProduct>().ToList();
        var customers = store.Query("TestCustomer").Cast<TestCustomer>().ToList();

        // Assert
        Assert.Equal(2, products.Count);
        Assert.Single(customers);
    }
}
