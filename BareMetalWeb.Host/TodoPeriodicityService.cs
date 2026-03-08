using System;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Runtime;

namespace BareMetalWeb.Host;

/// <summary>
/// Background service that runs hourly and resets completed recurring items
/// whose deadline has passed, advancing their deadline to the next occurrence.
/// Metadata-driven: scans RuntimeEntityRegistry for any entity with
/// Deadline (DateOnly), IsCompleted (bool), and Periodicity (enum) fields.
/// </summary>
public sealed class TodoPeriodicityService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromHours(1);
    private readonly IBufferedLogger _logger;

    // Standard periodicity values (matched case-insensitively against enum members)
    private static readonly string[] PeriodicityValues = ["OneOff", "Hourly", "Daily", "Weekly", "Monthly", "Quarterly", "Yearly"];

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
                int count = ProcessPeriodicEntities(DateTime.UtcNow);
                if (count > 0)
                    _logger.LogInfo($"TodoPeriodicityService reset {count} recurring item(s).");
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
    /// Scans all runtime entities for periodic fields and resets completed items.
    /// </summary>
    public int ProcessPeriodicEntities(DateTime nowUtc)
    {
        var walProvider = DataStoreProvider.PrimaryProvider as WalDataProvider;
        if (walProvider == null) return 0;

        var registry = RuntimeEntityRegistry.Current;
        int total = 0;

        foreach (var model in registry.All)
        {
            // Find required fields by name
            int deadlineOrd = -1, completedOrd = -1, periodicityOrd = -1, startTimeOrd = -1;
            foreach (var f in model.Fields)
            {
                var name = f.Name;
                if (string.Equals(name, "Deadline", StringComparison.OrdinalIgnoreCase)) deadlineOrd = f.Ordinal;
                else if (string.Equals(name, "IsCompleted", StringComparison.OrdinalIgnoreCase)) completedOrd = f.Ordinal;
                else if (string.Equals(name, "Periodicity", StringComparison.OrdinalIgnoreCase)) periodicityOrd = f.Ordinal;
                else if (string.Equals(name, "StartTime", StringComparison.OrdinalIgnoreCase)) startTimeOrd = f.Ordinal;
            }

            if (deadlineOrd < 0 || completedOrd < 0 || periodicityOrd < 0)
                continue;

            var schema = EntitySchemaFactory.FromModel(model);
            var records = walProvider.QueryRecords(schema);

            foreach (var record in records)
            {
                var periodicityVal = record.GetValue(periodicityOrd)?.ToString();
                if (string.IsNullOrEmpty(periodicityVal) || string.Equals(periodicityVal, "OneOff", StringComparison.OrdinalIgnoreCase))
                    continue;

                var isCompleted = record.GetValue(completedOrd) is true;
                if (!isCompleted)
                    continue;

                var deadlineVal = record.GetValue(deadlineOrd);
                if (deadlineVal is not DateOnly deadline)
                    continue;

                var startTime = startTimeOrd >= 0 && record.GetValue(startTimeOrd) is TimeOnly st ? st : TimeOnly.MinValue;
                var deadlineUtc = deadline.ToDateTime(startTime, DateTimeKind.Utc);
                if (nowUtc < deadlineUtc)
                    continue;

                var nextDeadline = AdvanceDeadline(deadline, periodicityVal, nowUtc);
                record.SetValue(deadlineOrd, nextDeadline);
                record.SetValue(completedOrd, false);
                walProvider.SaveRecord(record, schema);
                total++;
            }
        }

        return total;
    }

    /// <summary>
    /// Advances the deadline by one period, skipping forward until the deadline is in the future.
    /// </summary>
    public static DateOnly AdvanceDeadline(DateOnly current, string periodicity, DateTime nowUtc)
    {
        var nowDate = DateOnly.FromDateTime(nowUtc);
        var next = current;

        do
        {
            next = periodicity.ToUpperInvariant() switch
            {
                "HOURLY"    => next.AddDays(1),  // DateOnly has no AddHours; hourly granularity needs DateTime
                "DAILY"     => next.AddDays(1),
                "WEEKLY"    => next.AddDays(7),
                "MONTHLY"   => next.AddMonths(1),
                "QUARTERLY" => next.AddMonths(3),
                "YEARLY"    => next.AddYears(1),
                _           => next.AddDays(1),
            };
        }
        while (next <= nowDate);

        return next;
    }
}
