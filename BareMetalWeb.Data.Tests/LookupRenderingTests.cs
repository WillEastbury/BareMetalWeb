using System.Collections;
using System.Net;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for lookup field rendering in list views and detail views.
/// Covers edge cases: null FK, empty FK, missing target entity, and resolved display names.
/// </summary>
[Collection("SharedState")]
public class LookupRenderingTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;
    private readonly InMemoryDataStore _store;

    public LookupRenderingTests()
    {
        _originalStore = DataStoreProvider.Current;
        _store = new InMemoryDataStore();
        DataStoreProvider.Current = _store;

        _ = GalleryTestFixture.State;
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
        Assert.True(DataScaffold.TryGetEntity("addresses", out var addrMeta));
        var addr = addrMeta.Handlers.Create();
        addr.Key = 1;
        addrMeta.FindField("Label")!.SetValueFn(addr, "Home Office");
        addrMeta.FindField("Line1")!.SetValueFn(addr, "1 Main St");
        addrMeta.FindField("City")!.SetValueFn(addr, "London");
        addrMeta.FindField("Country")!.SetValueFn(addr, "GB");
        addrMeta.Handlers.SaveAsync(addr, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        ClearLookupCache();

        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));
        var customer = meta.Handlers.Create();
        customer.Key = 1;
        meta.FindField("Name")!.SetValueFn(customer, "Jane");
        meta.FindField("Email")!.SetValueFn(customer, "j@x.com");
        meta.FindField("AddressId")!.SetValueFn(customer, "1");

        // Act
        var rows = DataScaffold.BuildListRows(meta, new[] { customer }, "/data/customers", includeActions: false);

        // Assert: the address cell should contain "Home Office" (the display name), not "addr-1"
        Assert.Single(rows);
        var addressCell = rows[0].FirstOrDefault(c => c.Contains("Home Office"));
        Assert.NotNull(addressCell);
        Assert.DoesNotContain(">1<", addressCell);
    }

    [Fact]
    public void BuildListRows_LookupField_NullValue_ShowsDash()
    {
        // Arrange: a Customer with null AddressId
        ClearLookupCache();
        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));
        var customer = meta.Handlers.Create();
        customer.Key = 2;
        meta.FindField("Name")!.SetValueFn(customer, "Null Addr");
        meta.FindField("Email")!.SetValueFn(customer, "n@x.com");
        meta.FindField("AddressId")!.SetValueFn(customer, "");

        // Act
        var rows = DataScaffold.BuildListRows(meta, new[] { customer }, "/data/customers", includeActions: false);

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
        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));
        var customer = meta.Handlers.Create();
        customer.Key = 3;
        meta.FindField("Name")!.SetValueFn(customer, "Orphan");
        meta.FindField("Email")!.SetValueFn(customer, "o@x.com");
        meta.FindField("AddressId")!.SetValueFn(customer, "addr-gone");

        // Act
        var rows = DataScaffold.BuildListRows(meta, new[] { customer }, "/data/customers", includeActions: false);

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
        Assert.True(DataScaffold.TryGetEntity("addresses", out var addrMeta));
        var addr = addrMeta.Handlers.Create();
        addr.Key = 2;
        addrMeta.FindField("Label")!.SetValueFn(addr, "View Test Address");
        addrMeta.FindField("Line1")!.SetValueFn(addr, "42 View St");
        addrMeta.FindField("City")!.SetValueFn(addr, "Oxford");
        addrMeta.FindField("Country")!.SetValueFn(addr, "GB");
        addrMeta.Handlers.SaveAsync(addr, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        ClearLookupCache();

        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));
        var customer = meta.Handlers.Create();
        customer.Key = 4;
        meta.FindField("Name")!.SetValueFn(customer, "View Test");
        meta.FindField("Email")!.SetValueFn(customer, "v@x.com");
        meta.FindField("AddressId")!.SetValueFn(customer, "2");

        // Act
        var rows = DataScaffold.BuildViewRowsHtml(meta, customer);

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
        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));
        var customer = meta.Handlers.Create();
        customer.Key = 5;
        meta.FindField("Name")!.SetValueFn(customer, "Empty Lookup");
        meta.FindField("Email")!.SetValueFn(customer, "e@x.com");
        meta.FindField("AddressId")!.SetValueFn(customer, "");

        // Act
        var rows = DataScaffold.BuildViewRowsHtml(meta, customer);

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
        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));
        var customer = meta.Handlers.Create();
        customer.Key = 6;
        meta.FindField("Name")!.SetValueFn(customer, "Deleted Ref");
        meta.FindField("Email")!.SetValueFn(customer, "d@x.com");
        meta.FindField("AddressId")!.SetValueFn(customer, "addr-deleted");

        // Act
        var rows = DataScaffold.BuildViewRowsHtml(meta, customer);

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
        Assert.True(DataScaffold.TryGetEntity("customers", out var custMeta));
        var cust = custMeta.Handlers.Create();
        cust.Key = 7;
        custMeta.FindField("Name")!.SetValueFn(cust, "Acme Corp");
        custMeta.FindField("Email")!.SetValueFn(cust, "a@acme.com");
        custMeta.Handlers.SaveAsync(cust, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        ClearLookupCache();

        Assert.True(DataScaffold.TryGetEntity("orders", out var meta));
        var order = meta.Handlers.Create();
        order.Key = 1;
        meta.FindField("OrderNumber")!.SetValueFn(order, "ORD-001");
        meta.FindField("CustomerId")!.SetValueFn(order, "7");
        meta.FindField("Status")!.SetValueFn(order, "Open");
        meta.FindField("OrderDate")!.SetValueFn(order, DateOnly.FromDateTime(DateTime.UtcNow));

        // Act
        var rows = DataScaffold.BuildListRows(meta, new[] { order }, "/data/orders", includeActions: false);

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
        Assert.True(DataScaffold.TryGetEntity("addresses", out var addrMeta));
        var addr = addrMeta.Handlers.Create();
        addr.Key = 3;
        addrMeta.FindField("Label")!.SetValueFn(addr, "Valid Address");
        addrMeta.FindField("Line1")!.SetValueFn(addr, "1 Test");
        addrMeta.FindField("City")!.SetValueFn(addr, "Test");
        addrMeta.FindField("Country")!.SetValueFn(addr, "GB");
        addrMeta.Handlers.SaveAsync(addr, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        ClearLookupCache();

        Assert.True(DataScaffold.TryGetEntity("customers", out var meta));
        var c1 = meta.Handlers.Create();
        c1.Key = 8;
        meta.FindField("Name")!.SetValueFn(c1, "Has Address");
        meta.FindField("Email")!.SetValueFn(c1, "a@x.com");
        meta.FindField("AddressId")!.SetValueFn(c1, "3");

        var c2 = meta.Handlers.Create();
        c2.Key = 9;
        meta.FindField("Name")!.SetValueFn(c2, "No Address");
        meta.FindField("Email")!.SetValueFn(c2, "b@x.com");
        meta.FindField("AddressId")!.SetValueFn(c2, "");

        var c3 = meta.Handlers.Create();
        c3.Key = 10;
        meta.FindField("Name")!.SetValueFn(c3, "Bad Address");
        meta.FindField("Email")!.SetValueFn(c3, "c@x.com");
        meta.FindField("AddressId")!.SetValueFn(c3, "addr-missing");

        var customers = new[] { c1, c2, c3 };

        // Act
        var rows = DataScaffold.BuildListRows(meta, customers, "/data/customers", includeActions: false);

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
