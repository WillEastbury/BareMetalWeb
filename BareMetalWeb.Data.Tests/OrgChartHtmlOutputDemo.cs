using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Demo program to output the org chart HTML for visual inspection
/// </summary>
[Collection("DataStoreProvider")]
public class OrgChartHtmlOutputDemo
{
    [Fact(Skip = "Demo only - outputs HTML to console")]
    public void OutputOrgChartHtml()
    {
        var originalStore = DataStoreProvider.Current;
        try
        {
            DataStoreProvider.Current = new InMemoryDataStore();
            _ = GalleryTestFixture.State;

            Assert.True(DataScaffold.TryGetEntity("employees", out var metadata));

            var emp1 = metadata.Handlers.Create();
            emp1.Key = 1;
            metadata.FindField("Name")!.SetValueFn(emp1, "Idit");
            metadata.FindField("Title")!.SetValueFn(emp1, "Manager");

            var emp2 = metadata.Handlers.Create();
            emp2.Key = 2;
            metadata.FindField("Name")!.SetValueFn(emp2, "Jaime");
            metadata.FindField("Title")!.SetValueFn(emp2, "Manager");
            metadata.FindField("ManagerId")!.SetValueFn(emp2, "1");

            var emp3 = metadata.Handlers.Create();
            emp3.Key = 3;
            metadata.FindField("Name")!.SetValueFn(emp3, "Mr William Eastbury");
            metadata.FindField("Title")!.SetValueFn(emp3, "Solution Engineer");
            metadata.FindField("ManagerId")!.SetValueFn(emp3, "2");

            var employees = new List<BaseDataObject> { emp1, emp2, emp3 };

            var html = DataScaffold.BuildOrgChartHtml(metadata, employees, selectedId: null, basePath: "/admin/data/employees");
            
            // Format HTML for better readability
            var formatted = html
                .Replace("><", ">\n<")
                .Replace("<div", "\n<div")
                .Replace("</div>", "</div>\n");

            Console.WriteLine("=== Generated Org Chart HTML ===");
            Console.WriteLine(formatted);
            Console.WriteLine("\n=== End HTML ===");
        }
        finally
        {
            DataStoreProvider.Current = originalStore;
        }
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
