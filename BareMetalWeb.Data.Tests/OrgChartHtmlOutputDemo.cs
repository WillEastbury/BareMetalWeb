using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Data.DataObjects;
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
            _ = typeof(BareMetalWeb.UserClasses.DataObjects.Employee).Assembly;
            DataEntityRegistry.RegisterAllEntities();

            var metadata = DataScaffold.GetEntityByType(typeof(BareMetalWeb.UserClasses.DataObjects.Employee));
            Assert.NotNull(metadata);

            var employees = new List<BaseDataObject>
            {
                new BareMetalWeb.UserClasses.DataObjects.Employee
                {
                    Id = "idit-id",
                    Name = "Idit",
                    Title = "Manager",
                    ManagerId = null
                },
                new BareMetalWeb.UserClasses.DataObjects.Employee
                {
                    Id = "jaime-id",
                    Name = "Jaime",
                    Title = "Manager",
                    ManagerId = "idit-id"
                },
                new BareMetalWeb.UserClasses.DataObjects.Employee
                {
                    Id = "william-id",
                    Name = "Mr William Eastbury",
                    Title = "Solution Engineer",
                    ManagerId = "jaime-id"
                }
            };

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
