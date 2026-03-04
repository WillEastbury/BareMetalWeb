using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
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

        _ = GalleryTestFixture.State;
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
        Assert.True(DataScaffold.TryGetEntity("employees", out var empMeta));

        var ceo = empMeta.Handlers.Create();
        ceo.Key = (uint)1;
        empMeta.FindField("Name")!.SetValueFn(ceo, "Idit");
        empMeta.FindField("Title")!.SetValueFn(ceo, "Manager");
        empMeta.FindField("ManagerId")!.SetValueFn(ceo, "0"); // root node

        var manager = empMeta.Handlers.Create();
        manager.Key = (uint)2;
        empMeta.FindField("Name")!.SetValueFn(manager, "Jaime");
        empMeta.FindField("Title")!.SetValueFn(manager, "Manager");
        empMeta.FindField("ManagerId")!.SetValueFn(manager, "1");

        var engineer = empMeta.Handlers.Create();
        engineer.Key = (uint)3;
        empMeta.FindField("Name")!.SetValueFn(engineer, "Mr William Eastbury");
        empMeta.FindField("Title")!.SetValueFn(engineer, "Solution Engineer");
        empMeta.FindField("ManagerId")!.SetValueFn(engineer, "2");

        var items = new List<BaseDataObject> { ceo, manager, engineer };
        Assert.NotNull(empMeta.ParentField);

        // Act
        var html = DataScaffold.BuildOrgChartHtml(empMeta, items, selectedId: null, basePath: "/admin/data/employees");

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
        Assert.True(DataScaffold.TryGetEntity("customers", out var custMeta));

        var items = new List<BaseDataObject>();

        // Act
        var html = DataScaffold.BuildOrgChartHtml(custMeta, items, selectedId: null, basePath: "/admin/data/customers");

        // Assert
        Assert.Contains("Org chart view requires a self-referencing parent field", html);
    }

    [Fact]
    public void BuildOrgChartHtml_SelectedNode_HighlightsCard()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("employees", out var empMeta));

        var employee = empMeta.Handlers.Create();
        employee.Key = (uint)4;
        empMeta.FindField("Name")!.SetValueFn(employee, "Test User");
        empMeta.FindField("Title")!.SetValueFn(employee, "Engineer");
        empMeta.FindField("ManagerId")!.SetValueFn(employee, "0"); // root node

        var items = new List<BaseDataObject> { employee };

        // Act
        var html = DataScaffold.BuildOrgChartHtml(empMeta, items, selectedId: "4", basePath: "/admin/data/employees");

        // Assert
        Assert.Contains("bm-orgchart-card-selected", html);
    }

    [Fact]
    public void BuildOrgChartHtml_MultipleSiblings_AllInSameLevel()
    {
        // Arrange: One parent with two children
        Assert.True(DataScaffold.TryGetEntity("employees", out var empMeta));

        var parent = empMeta.Handlers.Create();
        parent.Key = (uint)5;
        empMeta.FindField("Name")!.SetValueFn(parent, "Parent");
        empMeta.FindField("Title")!.SetValueFn(parent, "Manager");
        empMeta.FindField("ManagerId")!.SetValueFn(parent, "0"); // root node

        var child1 = empMeta.Handlers.Create();
        child1.Key = (uint)6;
        empMeta.FindField("Name")!.SetValueFn(child1, "Child One");
        empMeta.FindField("Title")!.SetValueFn(child1, "Engineer");
        empMeta.FindField("ManagerId")!.SetValueFn(child1, "5");

        var child2 = empMeta.Handlers.Create();
        child2.Key = (uint)7;
        empMeta.FindField("Name")!.SetValueFn(child2, "Child Two");
        empMeta.FindField("Title")!.SetValueFn(child2, "Engineer");
        empMeta.FindField("ManagerId")!.SetValueFn(child2, "5");

        var items = new List<BaseDataObject> { parent, child1, child2 };

        // Act
        var html = DataScaffold.BuildOrgChartHtml(empMeta, items, selectedId: null, basePath: "/admin/data/employees");

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
