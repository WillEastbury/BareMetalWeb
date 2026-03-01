using System.Collections.Concurrent;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Evaluates domain event subscriptions after a successful commit.
/// Subscriptions are declarative (entity + field + value → action) and
/// fire inside the same lock scope — deterministic and replay-safe.
///
/// Constraints:
/// - Flat only — event-triggered actions may NOT themselves fire events (depth=0)
/// - No cross-aggregate arbitrary mutation — respects the lock model
/// - No recursion or nested chains
/// </summary>
public static class DomainEventDispatcher
{
    private static volatile int _generation;
    private static int _cachedGeneration = -1;
    private static IReadOnlyList<SubscriptionEntry> _cachedSubscriptions = Array.Empty<SubscriptionEntry>();
    private static readonly object _cacheLock = new();

    /// <summary>Increment to invalidate subscription cache.</summary>
    public static void Invalidate() => Interlocked.Increment(ref _generation);

    /// <summary>
    /// Evaluate all matching subscriptions for mutations that occurred in a committed envelope.
    /// Called by TransactionCommitEngine after save, inside lock scope.
    /// Returns fired action results (empty if no subscriptions matched).
    /// </summary>
    public static async ValueTask<IReadOnlyList<DomainEventResult>> DispatchAsync(
        TransactionEnvelope envelope,
        IReadOnlyDictionary<string, (DataEntityMetadata Meta, BaseDataObject BeforeEntity, BaseDataObject AfterEntity, EntityLayout Layout)> entityStates,
        Func<string, ActionDef?> actionResolver,
        TransactionCommitEngine commitEngine,
        string userName,
        CancellationToken ct)
    {
        var subscriptions = await GetSubscriptionsAsync(ct);
        if (subscriptions.Count == 0) return Array.Empty<DomainEventResult>();

        var results = new List<DomainEventResult>();

        foreach (var mutation in envelope.Mutations)
        {
            var key = $"{mutation.AggregateType}:{mutation.AggregateId}";
            if (!entityStates.TryGetValue(key, out var state)) continue;

            // Find subscriptions for this entity type
            var matching = FindMatchingSubscriptions(
                subscriptions, mutation.AggregateType, state.BeforeEntity, state.AfterEntity, state.Layout);

            foreach (var sub in matching)
            {
                var result = await FireSubscriptionAsync(
                    sub, state, mutation, actionResolver, commitEngine, userName, ct);
                results.Add(result);

                // If any event-triggered action fails with Error, stop processing
                // further events for this envelope (fail-fast)
                if (!result.Success && result.IsHardFailure)
                    return results;
            }
        }

        return results;
    }

    private static List<SubscriptionEntry> FindMatchingSubscriptions(
        IReadOnlyList<SubscriptionEntry> all,
        string entitySlug,
        BaseDataObject before,
        BaseDataObject after,
        EntityLayout layout)
    {
        var matched = new List<SubscriptionEntry>();

        foreach (var sub in all)
        {
            if (!string.Equals(sub.SourceEntity, entitySlug, StringComparison.OrdinalIgnoreCase))
                continue;

            // No watch field = fire on any save
            if (string.IsNullOrEmpty(sub.WatchField))
            {
                matched.Add(sub);
                continue;
            }

            // Find the field in the layout
            var fieldIdx = -1;
            for (int i = 0; i < layout.Fields.Length; i++)
            {
                if (string.Equals(layout.Fields[i].Name, sub.WatchField, StringComparison.OrdinalIgnoreCase))
                {
                    fieldIdx = i;
                    break;
                }
            }
            if (fieldIdx < 0) continue;

            var field = layout.Fields[fieldIdx];
            var beforeVal = field.Getter(before)?.ToString() ?? string.Empty;
            var afterVal = field.Getter(after)?.ToString() ?? string.Empty;

            // Value didn't change — skip
            if (string.Equals(beforeVal, afterVal, StringComparison.OrdinalIgnoreCase))
                continue;

            // Check FROM value constraint
            if (!string.IsNullOrEmpty(sub.FromValue) &&
                !string.Equals(beforeVal, sub.FromValue, StringComparison.OrdinalIgnoreCase))
                continue;

            // Check TO value constraint
            if (!string.IsNullOrEmpty(sub.TriggerValue) &&
                !string.Equals(afterVal, sub.TriggerValue, StringComparison.OrdinalIgnoreCase))
                continue;

            matched.Add(sub);
        }

        // Sort by priority (lower first)
        matched.Sort((a, b) => a.Priority.CompareTo(b.Priority));
        return matched;
    }

    private static async ValueTask<DomainEventResult> FireSubscriptionAsync(
        SubscriptionEntry sub,
        (DataEntityMetadata Meta, BaseDataObject BeforeEntity, BaseDataObject AfterEntity, EntityLayout Layout) state,
        AggregateMutation sourceMutation,
        Func<string, ActionDef?> actionResolver,
        TransactionCommitEngine commitEngine,
        string userName,
        CancellationToken ct)
    {
        // Resolve target action
        var action = actionResolver(sub.TargetAction);
        if (action == null)
            return new DomainEventResult(sub.Name, sub.TargetAction, false, "ACTION_NOT_FOUND",
                $"Target action '{sub.TargetAction}' not found.", IsHardFailure: false);

        // Resolve target aggregate key
        uint targetKey;
        if (string.Equals(sub.TargetResolution, "self", StringComparison.OrdinalIgnoreCase))
        {
            targetKey = state.AfterEntity.Key;
        }
        else if (sub.TargetResolution.StartsWith("field:", StringComparison.OrdinalIgnoreCase))
        {
            var fieldName = sub.TargetResolution[6..];
            var fieldIdx = -1;
            for (int i = 0; i < state.Layout.Fields.Length; i++)
            {
                if (string.Equals(state.Layout.Fields[i].Name, fieldName, StringComparison.OrdinalIgnoreCase))
                {
                    fieldIdx = i;
                    break;
                }
            }

            if (fieldIdx < 0)
                return new DomainEventResult(sub.Name, sub.TargetAction, false, "FIELD_NOT_FOUND",
                    $"Target resolution field '{fieldName}' not found.", IsHardFailure: false);

            var val = state.Layout.Fields[fieldIdx].Getter(state.AfterEntity);
            if (val is uint uintVal) targetKey = uintVal;
            else if (uint.TryParse(val?.ToString(), out var parsed)) targetKey = parsed;
            else
                return new DomainEventResult(sub.Name, sub.TargetAction, false, "INVALID_TARGET",
                    $"Could not resolve target key from field '{fieldName}'.", IsHardFailure: false);
        }
        else
        {
            return new DomainEventResult(sub.Name, sub.TargetAction, false, "INVALID_RESOLUTION",
                $"Unknown target resolution '{sub.TargetResolution}'.", IsHardFailure: false);
        }

        // Fire the action — depth guard prevents nested event chains
        try
        {
            var result = await commitEngine.ExecuteActionAsync(
                action, targetKey, parameters: null, actionResolver, userName, ct);

            return new DomainEventResult(
                sub.Name, sub.TargetAction, result.Success,
                result.ErrorCode, result.ErrorMessage,
                IsHardFailure: !result.Success && result.ErrorCode != "LOCK_TIMEOUT");
        }
        catch (Exception ex)
        {
            return new DomainEventResult(sub.Name, sub.TargetAction, false, "DISPATCH_ERROR",
                ex.Message, IsHardFailure: false);
        }
    }

    /// <summary>Load and cache subscriptions from the data store.</summary>
    private static async ValueTask<IReadOnlyList<SubscriptionEntry>> GetSubscriptionsAsync(CancellationToken ct)
    {
        var gen = _generation;
        if (gen == _cachedGeneration) return _cachedSubscriptions;

        lock (_cacheLock)
        {
            if (gen == _cachedGeneration) return _cachedSubscriptions;
        }

        if (!DataScaffold.TryGetEntity("domain-event-subscriptions", out var meta))
            return Array.Empty<SubscriptionEntry>();

        var items = await meta.Handlers.QueryAsync(null, ct);
        var entries = new List<SubscriptionEntry>();

        foreach (var item in items)
        {
            var enabled = GetField(item, meta, "Enabled");
            if (string.Equals(enabled, "False", StringComparison.OrdinalIgnoreCase)) continue;

            entries.Add(new SubscriptionEntry(
                Name: GetField(item, meta, "Name"),
                SourceEntity: GetField(item, meta, "SourceEntity"),
                WatchField: GetField(item, meta, "WatchField"),
                TriggerValue: GetField(item, meta, "TriggerValue"),
                FromValue: GetField(item, meta, "FromValue"),
                TargetAction: GetField(item, meta, "TargetAction"),
                TargetResolution: GetField(item, meta, "TargetResolution"),
                Priority: int.TryParse(GetField(item, meta, "Priority"), out var p) ? p : 100));
        }

        entries.Sort((a, b) => a.Priority.CompareTo(b.Priority));

        lock (_cacheLock)
        {
            _cachedSubscriptions = entries;
            _cachedGeneration = gen;
        }

        return entries;
    }

    private static string GetField(BaseDataObject obj, DataEntityMetadata meta, string fieldName)
    {
        var field = meta.Fields.FirstOrDefault(f =>
            string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase));
        return field?.GetValueFn?.Invoke(obj)?.ToString() ?? string.Empty;
    }

    private sealed record SubscriptionEntry(
        string Name, string SourceEntity, string WatchField,
        string TriggerValue, string FromValue, string TargetAction,
        string TargetResolution, int Priority);
}

/// <summary>Result of a domain event subscription firing.</summary>
public sealed record DomainEventResult(
    string SubscriptionName,
    string TargetAction,
    bool Success,
    string? ErrorCode,
    string? ErrorMessage,
    bool IsHardFailure);
