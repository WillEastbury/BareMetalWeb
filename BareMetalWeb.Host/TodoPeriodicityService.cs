using System;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Host;

/// <summary>
/// Background service that runs hourly and resets completed recurring ToDo items
/// whose deadline has passed, advancing their deadline to the next occurrence.
/// </summary>
public sealed class TodoPeriodicityService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(1);
    private readonly IBufferedLogger _logger;

    public TodoPeriodicityService(IBufferedLogger logger)
    {
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken token)
    {
        _logger.LogInfo("TodoPeriodicityService starting.");

        while (!token.IsCancellationRequested)
        {
            try
            {
                var count = ProcessTodos(DataStoreProvider.Current, DateTime.UtcNow);
                if (count > 0)
                    _logger.LogInfo($"TodoPeriodicityService reset {count} recurring todo item(s).");
            }
            catch (Exception ex)
            {
                _logger.LogError("TodoPeriodicityService processing error.", ex);
            }

            try
            {
                await Task.Delay(CheckInterval, token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInfo("TodoPeriodicityService stopped.");
    }

    /// <summary>
    /// Processes all recurring todos and resets any that are completed and past their deadline.
    /// Returns the number of todos that were reset.
    /// </summary>
    public static int ProcessTodos(IDataObjectStore store, DateTime nowUtc)
    {
        var todos = store.Query<ToDo>(null);
        int count = 0;

        foreach (var todo in todos)
        {
            if (todo.Periodicity == TodoPeriodicity.OneOff)
                continue;

            if (!todo.IsCompleted)
                continue;

            var deadlineUtc = todo.Deadline.ToDateTime(todo.StartTime, DateTimeKind.Utc);
            if (nowUtc < deadlineUtc)
                continue;

            // Advance deadline to the next occurrence
            var nextDeadline = AdvanceDeadline(todo.Deadline, todo.Periodicity, nowUtc);
            todo.Deadline = nextDeadline;
            todo.IsCompleted = false;
            store.Save(todo);
            count++;
        }

        return count;
    }

    /// <summary>
    /// Advances the deadline by one period, skipping forward until the deadline is in the future.
    /// </summary>
    public static DateOnly AdvanceDeadline(DateOnly current, TodoPeriodicity periodicity, DateTime nowUtc)
    {
        var nowDate = DateOnly.FromDateTime(nowUtc);
        var next = current;

        do
        {
            next = periodicity switch
            {
                TodoPeriodicity.Hourly    => next.AddDays(1),  // hourly tasks repeat the next day
                TodoPeriodicity.Daily     => next.AddDays(1),
                TodoPeriodicity.Weekly    => next.AddDays(7),
                TodoPeriodicity.Monthly   => next.AddMonths(1),
                TodoPeriodicity.Quarterly => next.AddMonths(3),
                TodoPeriodicity.Yearly    => next.AddYears(1),
                _                         => next.AddDays(1),
            };
        }
        while (next <= nowDate);

        return next;
    }
}
