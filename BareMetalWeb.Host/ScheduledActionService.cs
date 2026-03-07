using System;

using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Host;

/// <summary>
/// Background service that checks <see cref="BareMetalWeb.Runtime.ScheduledActionDefinition"/>
/// records every minute and executes due actions against qualifying entity records.
/// </summary>
public sealed class ScheduledActionService
{
    private static readonly TimeSpan TickInterval = TimeSpan.FromMinutes(1);
    private readonly IBufferedLogger _logger;

    public ScheduledActionService(IBufferedLogger logger)
    {
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken token)
    {
        _logger.LogInfo("ScheduledActionService starting.");

        while (!token.IsCancellationRequested)
        {
            try
            {
                await ProcessSchedulesAsync(DateTime.UtcNow, token);
            }
            catch (Exception ex)
            {
                _logger.LogError("ScheduledActionService tick error.", ex);
            }

            try
            {
                await Task.Delay(TickInterval, token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInfo("ScheduledActionService stopped.");
    }

    private async Task ProcessSchedulesAsync(DateTime nowUtc, CancellationToken ct)
    {
        var store = DataStoreProvider.Current;
        var schedulesResult = await store.QueryAsync<BareMetalWeb.Runtime.ScheduledActionDefinition>(null, ct);
        var schedules = new List<BareMetalWeb.Runtime.ScheduledActionDefinition>();
        foreach (var s in schedulesResult)
            schedules.Add(s);

        foreach (var sched in schedules)
        {
            if (!sched.Enabled) continue;

            if (!IsDue(sched, nowUtc)) continue;

            var entitySlug = ResolveEntitySlug(sched.EntityId);
            if (string.IsNullOrEmpty(entitySlug) || !DataScaffold.TryGetEntity(entitySlug, out var meta))
                continue;

            // Find the action
            RemoteCommandMetadata? actionCmd = null;
            foreach (var c in meta.Commands)
            {
                if (string.Equals(c.Name, sched.ActionName, StringComparison.OrdinalIgnoreCase))
                {
                    actionCmd = c;
                    break;
                }
            }
            if (actionCmd == null) continue;

            try
            {
                // Query all records (optionally filtered)
                var query = string.IsNullOrWhiteSpace(sched.FilterExpression)
                    ? null
                    : new QueryDefinition();

                var queryResults = await meta.Handlers.QueryAsync(query, ct);
                var items = new List<BaseDataObject>();
                foreach (var item in queryResults)
                    items.Add(item);
                int count = 0;

                foreach (var item in items)
                {
                    // Execute the action by building a CommandIntent and routing through the normal pipeline
                    try
                    {
                        var intent = new BareMetalWeb.Runtime.CommandIntent
                        {
                            EntitySlug = entitySlug,
                            EntityId = item.Key.ToString(),
                            Operation = sched.ActionName
                        };

                        var svc = new BareMetalWeb.Runtime.CommandService();
                        await svc.ExecuteAsync(intent, ct);
                        count++;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"ScheduledAction '{sched.Name}' failed on item: {ex.Message}", ex);
                    }
                }

                sched.LastRunUtc = nowUtc;
                sched.LastRunCount = count;
                await store.SaveAsync(sched, ct);

                if (count > 0)
                    _logger.LogInfo($"ScheduledAction '{sched.Name}' executed on {count} record(s).");
            }
            catch (Exception ex)
            {
                _logger.LogError($"ScheduledAction '{sched.Name}' error: {ex.Message}", ex);
            }
        }
    }

    private static bool IsDue(BareMetalWeb.Runtime.ScheduledActionDefinition sched, DateTime nowUtc)
    {
        if (!sched.LastRunUtc.HasValue) return true;

        var elapsed = nowUtc - sched.LastRunUtc.Value;
        var interval = ParseInterval(sched.Schedule);

        return elapsed >= interval;
    }

    internal static TimeSpan ParseInterval(string schedule)
    {
        if (string.IsNullOrWhiteSpace(schedule)) return TimeSpan.FromDays(1);

        return schedule.Trim().ToLowerInvariant() switch
        {
            "hourly" => TimeSpan.FromHours(1),
            "daily" => TimeSpan.FromDays(1),
            "weekly" => TimeSpan.FromDays(7),
            "monthly" => TimeSpan.FromDays(30),
            _ => int.TryParse(schedule.Trim(), out var mins) && mins > 0
                ? TimeSpan.FromMinutes(mins)
                : TimeSpan.FromDays(1)
        };
    }

    private static string? ResolveEntitySlug(string entityId)
    {
        var store = DataStoreProvider.Current;
        var defs = store.QueryAsync<BareMetalWeb.Runtime.EntityDefinition>(
            new QueryDefinition
            {
                Clauses = { new QueryClause { Field = "EntityId", Operator = QueryOperator.Equals, Value = entityId } }
            }, CancellationToken.None).GetAwaiter().GetResult(); // TODO: convert to async

        BareMetalWeb.Runtime.EntityDefinition? def = null;
        foreach (var d in defs)
        {
            def = d;
            break;
        }
        return def?.Slug ?? def?.Name?.Replace(' ', '-').ToLowerInvariant();
    }
}
