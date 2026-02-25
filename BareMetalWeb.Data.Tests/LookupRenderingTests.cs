using System.Collections;
using System.Net;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for lookup field rendering in list views and detail views.
/// Covers edge cases: null FK, empty FK, missing target entity, and resolved display names.
/// </summary>
[Collection("DataStoreProvider")]
public class LookupRenderingTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;
    private readonly InMemoryDataStore _store;

    public LookupRenderingTests()
    {
        _originalStore = DataStoreProvider.Current;
        _store = new InMemoryDataStore();
        DataStoreProvider.Current = _store;

        _ = typeof(Customer).Assembly;
        DataEntityRegistry.RegisterAllEntities();
        ClearLookupCache();
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
    }

    // ─── FormatLookupDisplay tests (via BuildListRows) ──────────────────────

    [Fact]
    public void BuildListRows_LookupField_ResolvesDisplayName()
    {
        // Arrange: an Address exists and a Customer references it
        _store.Save(new Address { Id = "addr-1", Label = "Home Office", Line1 = "1 Main St", City = "London", Country = "GB" });
        ClearLookupCache();

        var meta = DataScaffold.GetEntityByType(typeof(Customer));
        Assert.NotNull(meta);
        var customer = new Customer { Id = "cust-1", Name = "Jane", Email = "j@x.com", AddressId = "addr-1" };

        // Act
        var rows = DataScaffold.BuildListRows(meta!, new[] { customer }, "/data/customers", includeActions: false);

        // Assert: the address cell should contain "Home Office" (the display name), not "addr-1"
        Assert.Single(rows);
        var addressCell = rows[0].FirstOrDefault(c => c.Contains("Home Office"));
        Assert.NotNull(addressCell);
        Assert.DoesNotContain(">addr-1<", addressCell);
    }

    [Fact]
    public void BuildListRows_LookupField_NullValue_ShowsDash()
    {
        // Arrange: a Customer with null AddressId
        ClearLookupCache();
        var meta = DataScaffold.GetEntityByType(typeof(Customer));
        Assert.NotNull(meta);
        var customer = new Customer { Id = "cust-2", Name = "Null Addr", Email = "n@x.com", AddressId = "" };

        // Act
        var rows = DataScaffold.BuildListRows(meta!, new[] { customer }, "/data/customers", includeActions: false);

        // Assert: empty lookup key should show dash placeholder, not raw empty string
        Assert.Single(rows);
        var allCells = string.Join("|", rows[0]);
        // Should contain the "—" dash from FormatLookupDisplay for empty keys
        Assert.Contains("\u2014", allCells);
    }

    [Fact]
    public void BuildListRows_LookupField_MissingTarget_ShowsRawId()
    {
        // Arrange: Customer references an Address that doesn't exist
        ClearLookupCache();
        var meta = DataScaffold.GetEntityByType(typeof(Customer));
        Assert.NotNull(meta);
        var customer = new Customer { Id = "cust-3", Name = "Orphan", Email = "o@x.com", AddressId = "addr-gone" };

        // Act
        var rows = DataScaffold.BuildListRows(meta!, new[] { customer }, "/data/customers", includeActions: false);

        // Assert: should gracefully show raw ID when target entity is missing
        Assert.Single(rows);
        var allCells = string.Join("|", rows[0]);
        Assert.Contains("addr-gone", allCells);
    }

    // ─── BuildViewRowsHtml tests ─────────────────────────────────────────────

    [Fact]
    public void BuildViewRowsHtml_LookupField_ResolvesDisplayName()
    {
        // Arrange
        _store.Save(new Address { Id = "addr-v1", Label = "View Test Address", Line1 = "42 View St", City = "Oxford", Country = "GB" });
        ClearLookupCache();

        var meta = DataScaffold.GetEntityByType(typeof(Customer));
        Assert.NotNull(meta);
        var customer = new Customer { Id = "cust-v1", Name = "View Test", Email = "v@x.com", AddressId = "addr-v1" };

        // Act
        var rows = DataScaffold.BuildViewRowsHtml(meta!, customer);

        // Assert: address row should contain resolved display name
        var addressRow = rows.FirstOrDefault(r => r.Label.Contains("Address"));
        Assert.NotNull(addressRow);
        Assert.Contains("View Test Address", addressRow.Value);
    }

    [Fact]
    public void BuildViewRowsHtml_LookupField_EmptyValue_ShowsDash()
    {
        // Arrange
        ClearLookupCache();
        var meta = DataScaffold.GetEntityByType(typeof(Customer));
        Assert.NotNull(meta);
        var customer = new Customer { Id = "cust-v2", Name = "Empty Lookup", Email = "e@x.com", AddressId = "" };

        // Act
        var rows = DataScaffold.BuildViewRowsHtml(meta!, customer);

        // Assert: empty lookup should produce dash placeholder
        var addressRow = rows.FirstOrDefault(r => r.Label.Contains("Address"));
        Assert.NotNull(addressRow);
        var decoded = WebUtility.HtmlDecode(addressRow.Value);
        Assert.Contains("—", decoded);
    }

    [Fact]
    public void BuildViewRowsHtml_LookupField_DeletedTarget_ShowsRawId()
    {
        // Arrange: Customer references non-existent address
        ClearLookupCache();
        var meta = DataScaffold.GetEntityByType(typeof(Customer));
        Assert.NotNull(meta);
        var customer = new Customer { Id = "cust-v3", Name = "Deleted Ref", Email = "d@x.com", AddressId = "addr-deleted" };

        // Act
        var rows = DataScaffold.BuildViewRowsHtml(meta!, customer);

        // Assert: should show raw ID as fallback
        var addressRow = rows.FirstOrDefault(r => r.Label.Contains("Address"));
        Assert.NotNull(addressRow);
        Assert.Contains("addr-deleted", addressRow.Value);
    }

    // ─── Order → Customer lookup chain ───────────────────────────────────────

    [Fact]
    public void BuildListRows_OrderCustomerLookup_ResolvesCustomerName()
    {
        // Arrange
        _store.Save(new Customer { Id = "cust-ord", Name = "Acme Corp", Email = "a@acme.com" });
        ClearLookupCache();

        var meta = DataScaffold.GetEntityByType(typeof(Order));
        Assert.NotNull(meta);
        var order = new Order
        {
            Id = "ord-1",
            OrderNumber = "ORD-001",
            CustomerId = "cust-ord",
            Status = "Open",
            OrderDate = DateOnly.FromDateTime(DateTime.UtcNow)
        };

        // Act
        var rows = DataScaffold.BuildListRows(meta!, new[] { order }, "/data/orders", includeActions: false);

        // Assert
        Assert.Single(rows);
        var allCells = string.Join("|", rows[0]);
        Assert.Contains("Acme Corp", allCells);
    }

    // ─── Multiple items with mixed lookup states ─────────────────────────────

    [Fact]
    public void BuildListRows_MixedLookupStates_HandlesAllGracefully()
    {
        // Arrange: some addresses exist, some don't
        _store.Save(new Address { Id = "addr-exists", Label = "Valid Address", Line1 = "1 Test", City = "Test", Country = "GB" });
        ClearLookupCache();

        var meta = DataScaffold.GetEntityByType(typeof(Customer));
        Assert.NotNull(meta);
        var customers = new[]
        {
            new Customer { Id = "c1", Name = "Has Address", Email = "a@x.com", AddressId = "addr-exists" },
            new Customer { Id = "c2", Name = "No Address", Email = "b@x.com", AddressId = "" },
            new Customer { Id = "c3", Name = "Bad Address", Email = "c@x.com", AddressId = "addr-missing" },
        };

        // Act
        var rows = DataScaffold.BuildListRows(meta!, customers, "/data/customers", includeActions: false);

        // Assert
        Assert.Equal(3, rows.Count);
        var row0 = string.Join("|", rows[0]);
        var row1 = string.Join("|", rows[1]);
        var row2 = string.Join("|", rows[2]);

        Assert.Contains("Valid Address", row0);    // Resolved display name
        Assert.Contains("\u2014", row1);            // Dash for empty
        Assert.Contains("addr-missing", row2);      // Fallback to raw ID
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private static void ClearLookupCache()
    {
        var cacheField = typeof(DataScaffold).GetField("LookupCache",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        if (cacheField?.GetValue(null) is IDictionary cache)
            cache.Clear();
    }

    private class InMemoryDataStore : IDataObjectStore
    {
        private readonly Dictionary<(Type, string), BaseDataObject> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        public void Save<T>(T obj) where T : BaseDataObject
            => _store[(typeof(T), obj.Id)] = obj;

        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        { Save(obj); return ValueTask.CompletedTask; }

        public T? Load<T>(string id) where T : BaseDataObject
            => _store.TryGetValue((typeof(T), id), out var obj) ? obj as T : null;

        public ValueTask<T?> LoadAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Load<T>(id));

        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
            => _store.Values.OfType<T>();

        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Query<T>(query));

        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Query<T>(query).Count());

        public void Delete<T>(string id) where T : BaseDataObject
            => _store.Remove((typeof(T), id));

        public ValueTask DeleteAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
        { Delete<T>(id); return ValueTask.CompletedTask; }
    }
}
