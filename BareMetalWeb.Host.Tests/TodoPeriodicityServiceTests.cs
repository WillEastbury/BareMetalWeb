using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Host.Tests;

public class TodoPeriodicityServiceTests
{
    // ── helpers ───────────────────────────────────────────────────────────────

    private static uint _nextKey = 1;

    private static ToDo MakeTodo(
        TodoPeriodicity periodicity,
        bool isCompleted,
        DateOnly deadline,
        TimeOnly startTime = default)
        => new ToDo
        {
            Key = _nextKey++,
            Title = "Test",
            Periodicity = periodicity,
            IsCompleted = isCompleted,
            Deadline = deadline,
            StartTime = startTime
        };

    // ── AdvanceDeadline ───────────────────────────────────────────────────────

    [Theory]
    [InlineData(TodoPeriodicity.Hourly,    1,  0)]
    [InlineData(TodoPeriodicity.Daily,     1,  0)]
    [InlineData(TodoPeriodicity.Weekly,    7,  0)]
    [InlineData(TodoPeriodicity.Monthly,   0,  1)]
    [InlineData(TodoPeriodicity.Quarterly, 0,  3)]
    [InlineData(TodoPeriodicity.Yearly,    0, 12)]
    public void AdvanceDeadline_ReturnsDateStrictlyAfterNow(
        TodoPeriodicity periodicity, int addDays, int addMonths)
    {
        // Arrange
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = DateOnly.FromDateTime(nowUtc).AddDays(-1); // already past

        // Act
        var result = TodoPeriodicityService.AdvanceDeadline(current, periodicity, nowUtc);

        // Assert
        Assert.True(result > DateOnly.FromDateTime(nowUtc),
            $"Expected advanced date to be after {DateOnly.FromDateTime(nowUtc)} but got {result}");
    }

    [Fact]
    public void AdvanceDeadline_Hourly_AdvancesByOneDay()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2025, 6, 14);

        var result = TodoPeriodicityService.AdvanceDeadline(current, TodoPeriodicity.Hourly, nowUtc);

        Assert.Equal(new DateOnly(2025, 6, 16), result);
    }

    [Fact]
    public void AdvanceDeadline_Daily_AdvancesByOneDay()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2025, 6, 14);

        var result = TodoPeriodicityService.AdvanceDeadline(current, TodoPeriodicity.Daily, nowUtc);

        Assert.Equal(new DateOnly(2025, 6, 16), result);
    }

    [Fact]
    public void AdvanceDeadline_Weekly_AdvancesBySevenDays()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2025, 6, 8);

        var result = TodoPeriodicityService.AdvanceDeadline(current, TodoPeriodicity.Weekly, nowUtc);

        Assert.Equal(new DateOnly(2025, 6, 22), result);
    }

    [Fact]
    public void AdvanceDeadline_Monthly_AdvancesByOneMonth()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2025, 5, 10);

        var result = TodoPeriodicityService.AdvanceDeadline(current, TodoPeriodicity.Monthly, nowUtc);

        Assert.Equal(new DateOnly(2025, 7, 10), result);
    }

    [Fact]
    public void AdvanceDeadline_Quarterly_AdvancesByThreeMonths()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2025, 3, 1);

        var result = TodoPeriodicityService.AdvanceDeadline(current, TodoPeriodicity.Quarterly, nowUtc);

        Assert.Equal(new DateOnly(2025, 9, 1), result);
    }

    [Fact]
    public void AdvanceDeadline_Yearly_AdvancesByOneYear()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2024, 6, 1);

        var result = TodoPeriodicityService.AdvanceDeadline(current, TodoPeriodicity.Yearly, nowUtc);

        Assert.Equal(new DateOnly(2026, 6, 1), result);
    }

    [Fact]
    public void AdvanceDeadline_FarInPast_SkipsMultiplePeriods()
    {
        // current is 14 days in the past; weekly should skip forward to first future occurrence
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var current = new DateOnly(2025, 6, 1); // 14 days ago

        var result = TodoPeriodicityService.AdvanceDeadline(current, TodoPeriodicity.Weekly, nowUtc);

        // 2025-06-01 + 7 = 2025-06-08 (still past) + 7 = 2025-06-15 (today, still <=) + 7 = 2025-06-22
        Assert.Equal(new DateOnly(2025, 6, 22), result);
    }

    // ── ProcessTodos ──────────────────────────────────────────────────────────

    [Fact]
    public void ProcessTodos_OneOff_IsNotReset()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var store = new SimpleStore();
        var todo = MakeTodo(TodoPeriodicity.OneOff, isCompleted: true,
            deadline: new DateOnly(2025, 6, 10));
        store.Save(todo);

        var count = TodoPeriodicityService.ProcessTodos(store, nowUtc);

        Assert.Equal(0, count);
        Assert.True(store.Load<ToDo>(todo.Key)!.IsCompleted);
    }

    [Fact]
    public void ProcessTodos_RecurringNotCompleted_IsNotTouched()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var store = new SimpleStore();
        var todo = MakeTodo(TodoPeriodicity.Daily, isCompleted: false,
            deadline: new DateOnly(2025, 6, 10));
        store.Save(todo);

        var count = TodoPeriodicityService.ProcessTodos(store, nowUtc);

        Assert.Equal(0, count);
    }

    [Fact]
    public void ProcessTodos_RecurringCompletedDeadlinePast_IsReset()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var store = new SimpleStore();
        var todo = MakeTodo(TodoPeriodicity.Daily, isCompleted: true,
            deadline: new DateOnly(2025, 6, 10));
        store.Save(todo);

        var count = TodoPeriodicityService.ProcessTodos(store, nowUtc);

        Assert.Equal(1, count);
        var updated = store.Load<ToDo>(todo.Key)!;
        Assert.False(updated.IsCompleted);
        Assert.True(updated.Deadline > DateOnly.FromDateTime(nowUtc));
    }

    [Fact]
    public void ProcessTodos_RecurringCompletedDeadlineFuture_IsNotReset()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var store = new SimpleStore();
        var todo = MakeTodo(TodoPeriodicity.Daily, isCompleted: true,
            deadline: new DateOnly(2025, 6, 20),
            startTime: new TimeOnly(23, 0)); // deadline in the future
        store.Save(todo);

        var count = TodoPeriodicityService.ProcessTodos(store, nowUtc);

        Assert.Equal(0, count);
        Assert.True(store.Load<ToDo>(todo.Key)!.IsCompleted);
    }

    [Fact]
    public void ProcessTodos_MultipleItems_ReturnsCorrectCount()
    {
        var nowUtc = new DateTime(2025, 6, 15, 12, 0, 0, DateTimeKind.Utc);
        var store = new SimpleStore();

        // Should be reset
        store.Save(MakeTodo(TodoPeriodicity.Daily, true, new DateOnly(2025, 6, 10)));
        store.Save(MakeTodo(TodoPeriodicity.Weekly, true, new DateOnly(2025, 6, 1)));

        // Should NOT be reset
        store.Save(MakeTodo(TodoPeriodicity.OneOff, true, new DateOnly(2025, 6, 10)));
        store.Save(MakeTodo(TodoPeriodicity.Daily, false, new DateOnly(2025, 6, 10)));
        store.Save(MakeTodo(TodoPeriodicity.Daily, true, new DateOnly(2025, 6, 20)));

        var count = TodoPeriodicityService.ProcessTodos(store, nowUtc);

        Assert.Equal(2, count);
    }

    // ── minimal IDataObjectStore stub ─────────────────────────────────────────

    private sealed class SimpleStore : IDataObjectStore
    {
        private readonly Dictionary<(Type, uint), BaseDataObject> _data = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        public void Save<T>(T obj) where T : BaseDataObject
            => _data[(typeof(T), obj.Key)] = obj;

        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Save(obj);
            return ValueTask.CompletedTask;
        }

        public T? Load<T>(uint key) where T : BaseDataObject
            => _data.TryGetValue((typeof(T), key), out var v) ? v as T : null;
        public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Load<T>(key));

        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
            => _data.Values.OfType<T>();
        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Query<T>(query));

        public int Count<T>(QueryDefinition? query = null) where T : BaseDataObject => Query<T>().Count();
        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Count<T>());

        public void Delete<T>(uint key) where T : BaseDataObject => _data.Remove((typeof(T), key));
        public ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Delete<T>(key);
            return ValueTask.CompletedTask;
        }
    }
}
