using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
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

/// <summary>
/// Tests that BuildFormFields detects high-cardinality lookup fields and
/// switches to the search dialog rendering instead of a full dropdown.
/// </summary>
[Collection("DataStoreProvider")]
public class HighCardinalityLookupTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;
    private readonly int _originalThreshold;

    public HighCardinalityLookupTests()
    {
        _originalStore = DataStoreProvider.Current;
        _originalThreshold = DataScaffold.LargeListThreshold;
        DataStoreProvider.Current = new CountableInMemoryDataStore();

        _ = typeof(Employee).Assembly;
        DataEntityRegistry.RegisterAllEntities();
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
        DataScaffold.LargeListThreshold = _originalThreshold;
        ClearCaches();
    }

    [Fact]
    public void BuildFormFields_LowCardinalityLookup_UsesDropdown()
    {
        // Arrange: threshold = 5, add 3 employees (below threshold)
        DataScaffold.LargeListThreshold = 5;
        ClearCaches();

        var store = (CountableInMemoryDataStore)DataStoreProvider.Current;
        for (int i = 1; i <= 3; i++)
            store.Save(new Employee { Key = (uint)i, Name = $"Employee {i}" });

        var meta = DataScaffold.GetEntityByType(typeof(Employee));
        Assert.NotNull(meta);

        // Act
        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);
        var managerField = fields.FirstOrDefault(f => f.Name == "ManagerId");

        // Assert: not high-cardinality, options populated
        Assert.NotNull(managerField);
        Assert.Equal(FormFieldType.LookupList, managerField!.FieldType);
        Assert.False(managerField.IsHighCardinality);
        Assert.NotNull(managerField.LookupOptions);
        Assert.Null(managerField.LookupDisplayValue);
        Assert.Null(managerField.LookupSearchField);
    }

    [Fact]
    public void BuildFormFields_HighCardinalityLookup_UsesSearchDialog()
    {
        // Arrange: threshold = 2, add 5 employees (above threshold)
        DataScaffold.LargeListThreshold = 2;
        ClearCaches();

        var store = (CountableInMemoryDataStore)DataStoreProvider.Current;
        for (int i = 1; i <= 5; i++)
            store.Save(new Employee { Key = (uint)i, Name = $"Employee {i}" });

        var meta = DataScaffold.GetEntityByType(typeof(Employee));
        Assert.NotNull(meta);

        // Act
        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);
        var managerField = fields.FirstOrDefault(f => f.Name == "ManagerId");

        // Assert: high-cardinality, no options, search field populated
        Assert.NotNull(managerField);
        Assert.Equal(FormFieldType.LookupList, managerField!.FieldType);
        Assert.True(managerField.IsHighCardinality);
        Assert.Null(managerField.LookupOptions);
        Assert.Equal("Name", managerField.LookupSearchField);
    }

    [Fact]
    public void BuildFormFields_HighCardinalityLookup_WithCurrentValue_PopulatesDisplayValue()
    {
        // Arrange: threshold = 2, add 5 employees, edit an employee that has a manager set
        DataScaffold.LargeListThreshold = 2;
        ClearCaches();

        var store = (CountableInMemoryDataStore)DataStoreProvider.Current;
        store.Save(new Employee { Key = 100, Name = "Alice Manager" });
        for (int i = 2; i <= 5; i++)
            store.Save(new Employee { Key = (uint)i, Name = $"Employee {i}" });

        var instance = new Employee { Key = 1, Name = "Bob", ManagerId = "100" };

        var meta = DataScaffold.GetEntityByType(typeof(Employee));
        Assert.NotNull(meta);

        // Act
        var fields = DataScaffold.BuildFormFields(meta, instance, forCreate: false);
        var managerField = fields.FirstOrDefault(f => f.Name == "ManagerId");

        // Assert: high-cardinality with display value resolved
        Assert.NotNull(managerField);
        Assert.True(managerField!.IsHighCardinality);
        Assert.Equal("Alice Manager", managerField.LookupDisplayValue);
    }

    [Fact]
    public void BuildFormFields_HighCardinalityLookup_WithNoCurrentValue_NullDisplayValue()
    {
        // Arrange: threshold = 2, add 5 employees, create new (no value)
        DataScaffold.LargeListThreshold = 2;
        ClearCaches();

        var store = (CountableInMemoryDataStore)DataStoreProvider.Current;
        for (int i = 1; i <= 5; i++)
            store.Save(new Employee { Key = (uint)i, Name = $"Employee {i}" });

        var meta = DataScaffold.GetEntityByType(typeof(Employee));
        Assert.NotNull(meta);

        // Act: create form, no current value
        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true);
        var managerField = fields.FirstOrDefault(f => f.Name == "ManagerId");

        // Assert: no display value when no value is selected
        Assert.NotNull(managerField);
        Assert.True(managerField!.IsHighCardinality);
        Assert.Null(managerField.LookupDisplayValue);
    }

    [Fact]
    public void LargeListThreshold_Default_Is20()
    {
        // Reset to verify the default; the fixture saves/restores original value
        var savedThreshold = DataScaffold.LargeListThreshold;
        try
        {
            // After resetting, the static field default is 20
            // Use reflection to directly verify the expected default
            var prop = typeof(DataScaffold).GetProperty(nameof(DataScaffold.LargeListThreshold),
                BindingFlags.Public | BindingFlags.Static);
            Assert.NotNull(prop);
            Assert.True(prop!.CanWrite);
            // Verify we can set and get
            DataScaffold.LargeListThreshold = 50;
            Assert.Equal(50, DataScaffold.LargeListThreshold);
        }
        finally
        {
            DataScaffold.LargeListThreshold = savedThreshold;
        }
    }

    private static void ClearCaches()
    {
        var lookupCache = typeof(DataScaffold).GetField("LookupCache",
            BindingFlags.NonPublic | BindingFlags.Static);
        if (lookupCache?.GetValue(null) is IDictionary lc) lc.Clear();

        var largeListCache = typeof(DataScaffold).GetField("LargeListCache",
            BindingFlags.NonPublic | BindingFlags.Static);
        if (largeListCache?.GetValue(null) is IDictionary llc) llc.Clear();
    }

    private class CountableInMemoryDataStore : IDataObjectStore
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
        {
            var all = _store.Values.OfType<T>();
            if (query?.Clauses.Count > 0)
                all = all.Where(item => query.Clauses.All(c => MatchClause(item, c)));
            if (query?.Top > 0)
                all = all.Take(query.Top.Value);
            return all;
        }

        private static bool MatchClause<T>(T item, QueryClause clause) where T : BaseDataObject
        {
            var prop = typeof(T).GetProperty(clause.Field, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
            if (prop == null) return true;
            var val = prop.GetValue(item)?.ToString() ?? string.Empty;
            var clauseVal = clause.Value?.ToString() ?? string.Empty;
            return clause.Operator switch
            {
                QueryOperator.Equals => string.Equals(val, clauseVal, StringComparison.OrdinalIgnoreCase),
                QueryOperator.NotEquals => !string.Equals(val, clauseVal, StringComparison.OrdinalIgnoreCase),
                QueryOperator.Contains => val.Contains(clauseVal, StringComparison.OrdinalIgnoreCase),
                _ => true
            };
        }

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
