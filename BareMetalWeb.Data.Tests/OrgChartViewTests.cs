using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Data.DataObjects;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for BuildOrgChartHtml to ensure proper hierarchical structure rendering
/// </summary>
[Collection("DataStoreProvider")]
public class OrgChartViewTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;

    public OrgChartViewTests()
    {
        _originalStore = DataStoreProvider.Current;
        DataStoreProvider.Current = new InMemoryDataStore();

        // Force UserClasses assembly to load
        _ = typeof(BareMetalWeb.UserClasses.DataObjects.Employee).Assembly;
        DataEntityRegistry.RegisterAllEntities();
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
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

    [Fact]
    public void BuildOrgChartHtml_WithHierarchy_RendersCorrectStructure()
    {
        // Arrange: Create a simple hierarchy: Idit -> Jaime -> William
        var ceo = new BareMetalWeb.UserClasses.DataObjects.Employee
        {
            Key = 1,
            Name = "Idit",
            Title = "Manager",
            ManagerId = null // CEO has no manager
        };

        var manager = new BareMetalWeb.UserClasses.DataObjects.Employee
        {
            Key = 2,
            Name = "Jaime",
            Title = "Manager",
            ManagerId = "1"
        };

        var engineer = new BareMetalWeb.UserClasses.DataObjects.Employee
        {
            Key = 3,
            Name = "Mr William Eastbury",
            Title = "Solution Engineer",
            ManagerId = "2"
        };

        var items = new List<BaseDataObject> { ceo, manager, engineer };
        var metadata = DataScaffold.GetEntityByType(typeof(BareMetalWeb.UserClasses.DataObjects.Employee));
        Assert.NotNull(metadata);
        Assert.NotNull(metadata.ParentField);

        // Act
        var html = DataScaffold.BuildOrgChartHtml(metadata, items, selectedId: null, basePath: "/admin/data/employees");

        // Assert: Verify the structure does NOT wrap each node in bm-orgchart-level
        // The root node should NOT be wrapped in bm-orgchart-level
        // Only sibling groups should be wrapped in bm-orgchart-level
        
        // Root node (Idit) should be directly in a bm-orgchart-node, not in a bm-orgchart-level first
        var indexOfFirstNode = html.IndexOf("bm-orgchart-node");
        var indexOfFirstLevel = html.IndexOf("bm-orgchart-level");
        
        // The first bm-orgchart-node should appear BEFORE the first bm-orgchart-level
        // (because the root node is rendered as a node, then connector, then level for children)
        Assert.True(indexOfFirstNode < indexOfFirstLevel, 
            "Root node should be rendered as bm-orgchart-node before any bm-orgchart-level wrapper");

        // Verify each employee name appears once
        Assert.Contains("Idit", html);
        Assert.Contains("Jaime", html);
        Assert.Contains("Mr William Eastbury", html);

        // Verify connector appears (connects levels)
        Assert.Contains("bm-orgchart-connector", html);
    }

    [Fact]
    public void BuildOrgChartHtml_NoParentField_ReturnsWarning()
    {
        // Arrange: Use an entity without a parent field (Customer has no self-reference)
        var metadata = DataScaffold.GetEntityByType(typeof(Customer));
        Assert.NotNull(metadata);

        var items = new List<BaseDataObject>();

        // Act
        var html = DataScaffold.BuildOrgChartHtml(metadata, items, selectedId: null, basePath: "/admin/data/customers");

        // Assert
        Assert.Contains("Org chart view requires a self-referencing parent field", html);
    }

    [Fact]
    public void BuildOrgChartHtml_SelectedNode_HighlightsCard()
    {
        // Arrange
        var employee = new BareMetalWeb.UserClasses.DataObjects.Employee
        {
            Key = 4,
            Name = "Test User",
            Title = "Engineer",
            ManagerId = null
        };

        var items = new List<BaseDataObject> { employee };
        var metadata = DataScaffold.GetEntityByType(typeof(BareMetalWeb.UserClasses.DataObjects.Employee));
        Assert.NotNull(metadata);

        // Act
        var html = DataScaffold.BuildOrgChartHtml(metadata, items, selectedId: "4", basePath: "/admin/data/employees");

        // Assert
        Assert.Contains("bm-orgchart-card-selected", html);
    }

    [Fact]
    public void BuildOrgChartHtml_MultipleSiblings_AllInSameLevel()
    {
        // Arrange: One parent with two children
        var parent = new BareMetalWeb.UserClasses.DataObjects.Employee
        {
            Key = 5,
            Name = "Parent",
            Title = "Manager",
            ManagerId = null
        };

        var child1 = new BareMetalWeb.UserClasses.DataObjects.Employee
        {
            Key = 6,
            Name = "Child One",
            Title = "Engineer",
            ManagerId = "5"
        };

        var child2 = new BareMetalWeb.UserClasses.DataObjects.Employee
        {
            Key = 7,
            Name = "Child Two",
            Title = "Engineer",
            ManagerId = "5"
        };

        var items = new List<BaseDataObject> { parent, child1, child2 };
        var metadata = DataScaffold.GetEntityByType(typeof(BareMetalWeb.UserClasses.DataObjects.Employee));
        Assert.NotNull(metadata);

        // Act
        var html = DataScaffold.BuildOrgChartHtml(metadata, items, selectedId: null, basePath: "/admin/data/employees");

        // Assert: Both children should appear
        Assert.Contains("Child One", html);
        Assert.Contains("Child Two", html);

        // There should be exactly 2 bm-orgchart-node divs for children (plus 1 for parent = 3 total)
        var nodeCount = CountOccurrences(html, "class=\"bm-orgchart-node\"");
        Assert.Equal(3, nodeCount);
    }

    private static int CountOccurrences(string source, string substring)
    {
        int count = 0;
        int index = 0;
        while ((index = source.IndexOf(substring, index)) != -1)
        {
            count++;
            index += substring.Length;
        }
        return count;
    }
}
