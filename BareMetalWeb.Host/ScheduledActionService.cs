using System;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Host;

/// <summary>
/// Background service that checks scheduled-actions metadata records
/// every minute and executes due actions against qualifying entity records.
/// Works with generic field access — no dependency on typed C# entity classes.
/// </summary>
public sealed class ScheduledActionService
{
    private static readonly TimeSpan TickInterval = TimeSpan.FromMinutes(1);
    private readonly IBufferedLogger _logger;
    private readonly SemaphoreSlim _executionGuard = new(1, 1);

    public ScheduledActionService(IBufferedLogger logger)
    {
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken token)
    {
        _logger.LogInfo("ScheduledActionService starting.");

        while (!token.IsCancellationRequested)
        {
            // #1242: Overlap prevention — skip tick if previous is still running
            if (_executionGuard.Wait(0))
            {
                try
                {
                    await ProcessSchedulesAsync(DateTime.UtcNow, token);
                }
                catch (Exception ex)
                {
                    _logger.LogError("ScheduledActionService tick error.", ex);
                }
                finally
                {
                    _executionGuard.Release();
                }
            }
            else
            {
                _logger.LogInfo("ScheduledActionService: skipping tick — previous execution still running.");
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
        if (!DataScaffold.TryGetEntity("scheduled-actions", out var schedMeta))
            return;

        var schedulesResult = await schedMeta.Handlers.QueryAsync(null, ct);
        var schedules = new List<BaseDataObject>();
        foreach (var s in schedulesResult)
            schedules.Add(s);

        foreach (var sched in schedules)
        {
            var enabled = schedMeta.FindField("Enabled")?.GetValueFn(sched);
            if (enabled is false || string.Equals(enabled?.ToString(), "False", StringComparison.OrdinalIgnoreCase))
                continue;

            var lastRunUtc = schedMeta.FindField("LastRunUtc")?.GetValueFn(sched) as DateTime?;
            var schedule = schedMeta.FindField("Schedule")?.GetValueFn(sched)?.ToString() ?? "daily";

            if (lastRunUtc.HasValue)
            {
                var elapsed = nowUtc - lastRunUtc.Value;
                var interval = ParseInterval(schedule);
                if (elapsed < interval) continue;
            }

            var entityIdVal = schedMeta.FindField("EntityId")?.GetValueFn(sched)?.ToString() ?? string.Empty;
            var actionName = schedMeta.FindField("ActionName")?.GetValueFn(sched)?.ToString() ?? string.Empty;
            var schedName = schedMeta.FindField("Name")?.GetValueFn(sched)?.ToString() ?? string.Empty;
            var filterExpr = schedMeta.FindField("FilterExpression")?.GetValueFn(sched)?.ToString();

            var entitySlug = ResolveEntitySlug(entityIdVal);
            if (string.IsNullOrEmpty(entitySlug) || !DataScaffold.TryGetEntity(entitySlug, out var meta))
                continue;

            // Find the action
            RemoteCommandMetadata? actionCmd = null;
            foreach (var c in meta.Commands)
            {
                if (string.Equals(c.Name, actionName, StringComparison.OrdinalIgnoreCase))
                {
                    actionCmd = c;
                    break;
                }
            }
            if (actionCmd == null) continue;

            try
            {
                var query = string.IsNullOrWhiteSpace(filterExpr)
                    ? null
                    : new QueryDefinition();

                var queryResults = await meta.Handlers.QueryAsync(query, ct);
                var items = new List<BaseDataObject>();
                foreach (var item in queryResults)
                    items.Add(item);
                int count = 0;

                foreach (var item in items)
                {
                    try
                    {
                        var intent = new BareMetalWeb.Runtime.CommandIntent
                        {
                            EntitySlug = entitySlug,
                            EntityId = item.Key.ToString(),
                            Operation = actionName
                        };

                        var svc = new BareMetalWeb.Runtime.CommandService();
                        await svc.ExecuteAsync(intent, ct);
                        count++;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"ScheduledAction '{schedName}' failed on item: {ex.Message}", ex);
                    }
                }

                // Update last run info
                schedMeta.FindField("LastRunUtc")?.SetValueFn(sched, nowUtc);
                schedMeta.FindField("LastRunCount")?.SetValueFn(sched, count);
                await schedMeta.Handlers.SaveAsync(sched, ct);

                if (count > 0)
                    _logger.LogInfo($"ScheduledAction '{schedName}' executed on {count} record(s).");
            }
            catch (Exception ex)
            {
                _logger.LogError($"ScheduledAction '{schedName}' error: {ex.Message}", ex);
            }
        }
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
