using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Rendering.Models;
using BareMetalWeb.UserClasses.DataObjects;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[Collection("DataStoreProvider")]
public class LookupFieldButtonTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;

    public LookupFieldButtonTests()
    {
        _originalStore = DataStoreProvider.Current;
        DataStoreProvider.Current = new InMemoryDataStore();

        // Force UserClasses assembly to load before scanning
        _ = typeof(Employee).Assembly;
        DataEntityRegistry.RegisterAllEntities();
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
    }

    [Fact]
    public void BuildFormFields_LookupField_IncludesTargetMetadata()
    {
        // Arrange
        var metadata = DataScaffold.GetEntityByType(typeof(Employee));
        Assert.NotNull(metadata);

        // Act
        var fields = DataScaffold.BuildFormFields(metadata, null, forCreate: true);

        // Assert - Find the ManagerId field which has a lookup
        var managerField = fields.FirstOrDefault(f => f.Name == "ManagerId");
        Assert.NotNull(managerField);
        Assert.Equal(FormFieldType.LookupList, managerField.FieldType);
        
        // Verify lookup metadata is populated
        Assert.NotNull(managerField.LookupTargetType);
        Assert.Equal("Employee", managerField.LookupTargetType);
        Assert.NotNull(managerField.LookupTargetSlug);
        Assert.Equal("employees", managerField.LookupTargetSlug);
    }

    [Fact]
    public void BuildFormFields_NonLookupField_DoesNotIncludeLookupTargetMetadata()
    {
        // Arrange
        var metadata = DataScaffold.GetEntityByType(typeof(Employee));
        Assert.NotNull(metadata);

        // Act
        var fields = DataScaffold.BuildFormFields(metadata, null, forCreate: true);

        // Assert - Find the Department field which is a string, not a lookup
        var deptField = fields.FirstOrDefault(f => f.Name == "Department");
        Assert.NotNull(deptField);
        Assert.Equal(FormFieldType.String, deptField.FieldType);
        
        // Verify lookup metadata is NOT populated for non-lookup fields
        Assert.Null(deptField.LookupTargetType);
        Assert.Null(deptField.LookupTargetSlug);
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
}
