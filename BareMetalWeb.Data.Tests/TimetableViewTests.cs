using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for BuildTimetableHtml and CanShowTimetableView to validate
/// timetable view rendering with custom day-of-week enum types.
/// </summary>
[Collection("SharedState")]
public class TimetableViewTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;

    public TimetableViewTests()
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
    public void CanShowTimetableView_TimeTablePlanEntity_ReturnsTrue()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("time-table-plans", out var metadata));

        // Act
        var canShow = DataScaffold.CanShowTimetableView(metadata);

        // Assert - TimeTablePlan has Day (custom DayOfWeek enum) and StartTime (TimeOnly)
        Assert.True(canShow);
    }

    [Fact]
    public void CanShowTimetableView_EntityWithoutTimeField_ReturnsFalse()
    {
        // Arrange - Customer has no TimeOnly/DateTime field
        Assert.True(DataScaffold.TryGetEntity("customers", out var metadata));

        // Act
        var canShow = DataScaffold.CanShowTimetableView(metadata);

        // Assert
        Assert.False(canShow);
    }

    [Fact]
    public void BuildTimetableHtml_GroupsByDay_EachDayInOwnSection()
    {
        // Arrange
        Assert.True(DataScaffold.TryGetEntity("time-table-plans", out var metadata));

        var monday = metadata.Handlers.Create();
        monday.Key = 1;
        metadata.FindField("Day")!.SetValueFn(monday, 1);
        metadata.FindField("StartTime")!.SetValueFn(monday, new TimeOnly(9, 0));
        metadata.FindField("Minutes")!.SetValueFn(monday, 60);

        var tuesday = metadata.Handlers.Create();
        tuesday.Key = 2;
        metadata.FindField("Day")!.SetValueFn(tuesday, 2);
        metadata.FindField("StartTime")!.SetValueFn(tuesday, new TimeOnly(10, 0));
        metadata.FindField("Minutes")!.SetValueFn(tuesday, 45);

        var mondayLater = metadata.Handlers.Create();
        mondayLater.Key = 3;
        metadata.FindField("Day")!.SetValueFn(mondayLater, 1);
        metadata.FindField("StartTime")!.SetValueFn(mondayLater, new TimeOnly(11, 0));
        metadata.FindField("Minutes")!.SetValueFn(mondayLater, 30);

        var items = new List<BaseDataObject> { monday, tuesday, mondayLater };

        // Act
        var html = DataScaffold.BuildTimetableHtml(metadata, items, "/admin/data/timetableplans");

        // Assert: each day gets its own section header
        Assert.Contains("Monday", html);
        Assert.Contains("Tuesday", html);
        Assert.Contains("bm-timetable-day-section", html);
        Assert.Contains("bm-timetable-day-header", html);
    }

    [Fact]
    public void BuildTimetableHtml_SortsByTimeWithinDay()
    {
        // Arrange: two Monday entries out of time order
        Assert.True(DataScaffold.TryGetEntity("time-table-plans", out var metadata));

        var laterLesson = metadata.Handlers.Create();
        laterLesson.Key = 4;
        metadata.FindField("Day")!.SetValueFn(laterLesson, 1);
        metadata.FindField("StartTime")!.SetValueFn(laterLesson, new TimeOnly(12, 0));
        metadata.FindField("Minutes")!.SetValueFn(laterLesson, 60);

        var earlierLesson = metadata.Handlers.Create();
        earlierLesson.Key = 5;
        metadata.FindField("Day")!.SetValueFn(earlierLesson, 1);
        metadata.FindField("StartTime")!.SetValueFn(earlierLesson, new TimeOnly(9, 5));
        metadata.FindField("Minutes")!.SetValueFn(earlierLesson, 120);

        var items = new List<BaseDataObject> { laterLesson, earlierLesson };

        // Act
        var html = DataScaffold.BuildTimetableHtml(metadata, items, "/admin/data/timetableplans");

        // Assert: 09:05 should appear before 12:00 in the output
        var idx09 = html.IndexOf("09:05", StringComparison.Ordinal);
        var idx12 = html.IndexOf("12:00", StringComparison.Ordinal);
        Assert.True(idx09 < idx12, "Earlier time (09:05) should appear before later time (12:00) in HTML");
    }

    [Fact]
    public void BuildTimetableHtml_NoItems_ReturnsNoItemsMessage()
    {
        // Arrange
        var items = new List<BaseDataObject>();
        Assert.True(DataScaffold.TryGetEntity("time-table-plans", out var metadata));

        // Act
        var html = DataScaffold.BuildTimetableHtml(metadata, items, "/admin/data/timetableplans");

        // Assert
        Assert.Contains("No items found", html);
    }

    [Fact]
    public void BuildTimetableHtml_MissingDayOrTimeField_ReturnsWarning()
    {
        // Arrange - Customer has no Day enum or TimeOnly field
        Assert.True(DataScaffold.TryGetEntity("customers", out var metadata));
        var items = new List<BaseDataObject>();

        // Act
        var html = DataScaffold.BuildTimetableHtml(metadata, items, "/admin/data/customers");

        // Assert
        Assert.Contains("Timetable view requires", html);
    }

    [Fact]
    public void BuildTimetableHtml_DaysSortedInEnumOrder()
    {
        // Arrange: Tuesday (enum value 2) and Monday (enum value 1) - added in reverse order
        Assert.True(DataScaffold.TryGetEntity("time-table-plans", out var metadata));

        var tuesday = metadata.Handlers.Create();
        tuesday.Key = 6;
        metadata.FindField("Day")!.SetValueFn(tuesday, 2);
        metadata.FindField("StartTime")!.SetValueFn(tuesday, new TimeOnly(9, 0));
        metadata.FindField("Minutes")!.SetValueFn(tuesday, 60);

        var monday = metadata.Handlers.Create();
        monday.Key = 7;
        metadata.FindField("Day")!.SetValueFn(monday, 1);
        metadata.FindField("StartTime")!.SetValueFn(monday, new TimeOnly(9, 0));
        metadata.FindField("Minutes")!.SetValueFn(monday, 60);

        var items = new List<BaseDataObject> { tuesday, monday };

        // Act
        var html = DataScaffold.BuildTimetableHtml(metadata, items, "/admin/data/timetableplans");

        // Assert: Monday (enum value 1) should appear before Tuesday (enum value 2)
        var idxMonday = html.IndexOf("Monday", StringComparison.Ordinal);
        var idxTuesday = html.IndexOf("Tuesday", StringComparison.Ordinal);
        Assert.True(idxMonday < idxTuesday, "Monday should appear before Tuesday in sorted output");
    }

    [Fact]
    public void BuildTimetableHtml_LookupField_ShowsDisplayValueNotRawId()
    {
        // Arrange: seed a Subject so the lookup can be resolved
        Assert.True(DataScaffold.TryGetEntity("subjects", out var subjectMeta));
        var subject = subjectMeta.Handlers.Create();
        subject.Key = 1;
        subjectMeta.FindField("Name")!.SetValueFn(subject, "Mathematics");
        subjectMeta.Handlers.SaveAsync(subject, CancellationToken.None).AsTask().GetAwaiter().GetResult();

        // Clear lookup cache to force re-query with seeded data
        ClearLookupCache();

        Assert.True(DataScaffold.TryGetEntity("time-table-plans", out var metadata));

        var plan = metadata.Handlers.Create();
        plan.Key = 2;
        metadata.FindField("SubjectId")!.SetValueFn(plan, "1");
        metadata.FindField("Day")!.SetValueFn(plan, 3);
        metadata.FindField("StartTime")!.SetValueFn(plan, new TimeOnly(10, 0));
        metadata.FindField("Minutes")!.SetValueFn(plan, 45);

        var items = new List<BaseDataObject> { plan };

        // Act
        var html = DataScaffold.BuildTimetableHtml(metadata, items, "/admin/data/timetableplans");

        // Assert: the Subject's Name should appear as the display value
        Assert.Contains("Mathematics", html);
        // The raw ID should NOT appear as a standalone cell value (it may appear in a title attribute as part of BuildLookupHtml)
        Assert.DoesNotContain("<td>1</td>", html);
    }

    private static void ClearLookupCache()
    {
        var cacheField = typeof(DataScaffold).GetField("LookupCache",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        if (cacheField?.GetValue(null) is System.Collections.IDictionary cache)
            cache.Clear();
    }
}
