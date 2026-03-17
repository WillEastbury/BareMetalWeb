using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Service for capturing audit trail records for entity changes and remote commands.
/// Uses generic DataScaffold handlers — no dependency on the typed AuditEntry class.
/// </summary>
public sealed class AuditService
{
    private readonly IBufferedLogger? _logger;

    // Cache of compiled property accessors per type — uses DataScaffold metadata (AOT-safe)
    private static readonly ConcurrentDictionary<Type, (string Name, Func<object, object?> Getter)[]> _accessorCache = new();

    private static (string Name, Func<object, object?> Getter)[] GetCachedAccessors(Type type)
    {
        return _accessorCache.GetOrAdd(type, static t =>
        {
            var meta = DataScaffold.GetEntityByType(t);
            if (meta == null) return Array.Empty<(string, Func<object, object?>)>();

            var layout = EntityLayoutCompiler.GetOrCompile(meta);
            var list = new List<(string, Func<object, object?>)>(layout.Fields.Length);
            foreach (var f in layout.Fields)
            {
                if (f.Getter != null)
                    list.Add((f.Name, f.Getter));
            }
            return list.ToArray();
        });
    }

    /// <summary>
    /// When true, audit saves are awaited directly instead of fire-and-forget.
    /// Intended for unit testing only.
    /// </summary>
    internal bool RunSynchronously { get; set; }

    public AuditService(IDataObjectStore store, IBufferedLogger? logger = null)
    {
        _ = store ?? throw new ArgumentNullException(nameof(store));
        _logger = logger;
    }

    private DataEntityMetadata? GetAuditMeta()
        => DataScaffold.TryGetEntity("auditentry", out var meta) ? meta : null;

    private BaseDataObject? CreateAuditRecord(DataEntityMetadata meta, string userName)
    {
        var entry = meta.Handlers.Create();
        entry.CreatedBy = userName;
        entry.UpdatedBy = userName;
        return entry;
    }

    private static void SetField(BaseDataObject record, DataEntityMetadata meta, string fieldName, object? value)
        => meta.FindField(fieldName)?.SetValueFn(record, value);

    /// <summary>
    /// Captures an audit record for entity creation
    /// </summary>
    public async ValueTask AuditCreateAsync<T>(T entity, string userName, CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        try
        {
            var meta = GetAuditMeta();
            if (meta == null) return;
            var entry = CreateAuditRecord(meta, userName);
            if (entry == null) return;

            SetField(entry, meta, "EntityType", typeof(T).Name);
            SetField(entry, meta, "EntityKey", entity.Key);
            SetField(entry, meta, "Operation", AuditOperation.Create);
            SetField(entry, meta, "TimestampUtc", DateTime.UtcNow);
            SetField(entry, meta, "UserName", userName);
            SetField(entry, meta, "Notes", "Entity created");

            await SaveAuditEntryAsync(meta, entry, "create", cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to create audit entry for create: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Captures an audit record for entity update with field-level change tracking
    /// </summary>
    public async ValueTask AuditUpdateAsync<T>(T oldEntity, T newEntity, string userName, CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        try
        {
            var changes = DetectChanges(oldEntity, newEntity);

            // Skip if no meaningful changes (e.g., only UpdatedOnUtc, ETag changed)
            if (changes.Count == 0)
                return;

            var meta = GetAuditMeta();
            if (meta == null) return;
            var entry = CreateAuditRecord(meta, userName);
            if (entry == null) return;

            SetField(entry, meta, "EntityType", typeof(T).Name);
            SetField(entry, meta, "EntityKey", newEntity.Key);
            SetField(entry, meta, "Operation", AuditOperation.Update);
            SetField(entry, meta, "TimestampUtc", DateTime.UtcNow);
            SetField(entry, meta, "UserName", userName);
            SetField(entry, meta, "FieldChangesJson", JsonSerializer.Serialize(changes, BmwDataJsonContext.Default.ListFieldChange));
            SetField(entry, meta, "Notes", $"{changes.Count} field(s) changed");

            await SaveAuditEntryAsync(meta, entry, "update", cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to create audit entry for update: {ex.Message}", ex);
            if (RunSynchronously) throw;
        }
    }

    /// <summary>
    /// Captures an audit record for entity deletion
    /// </summary>
    public async ValueTask AuditDeleteAsync<T>(uint entityKey, string userName, CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        try
        {
            var meta = GetAuditMeta();
            if (meta == null) return;
            var entry = CreateAuditRecord(meta, userName);
            if (entry == null) return;

            SetField(entry, meta, "EntityType", typeof(T).Name);
            SetField(entry, meta, "EntityKey", entityKey);
            SetField(entry, meta, "Operation", AuditOperation.Delete);
            SetField(entry, meta, "TimestampUtc", DateTime.UtcNow);
            SetField(entry, meta, "UserName", userName);
            SetField(entry, meta, "Notes", "Entity deleted");

            await SaveAuditEntryAsync(meta, entry, "delete", cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to create audit entry for delete: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Captures an audit record for remote command execution
    /// </summary>
    public async ValueTask AuditRemoteCommandAsync<T>(
        T entity,
        string commandName,
        string userName,
        Dictionary<string, object?>? parameters = null,
        RemoteCommandResult? result = null,
        CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        try
        {
            var meta = GetAuditMeta();
            if (meta == null) return;
            var entry = CreateAuditRecord(meta, userName);
            if (entry == null) return;

            SetField(entry, meta, "EntityType", typeof(T).Name);
            SetField(entry, meta, "EntityKey", entity.Key);
            SetField(entry, meta, "Operation", AuditOperation.RemoteCommand);
            SetField(entry, meta, "TimestampUtc", DateTime.UtcNow);
            SetField(entry, meta, "UserName", userName);
            SetField(entry, meta, "CommandName", commandName);
            SetField(entry, meta, "CommandParameters", parameters != null ? DataJsonWriter.ToJsonString(parameters) : null);
            SetField(entry, meta, "CommandResult", result != null ? $"Success: {result.Success}, Message: {result.Message}" : null);
            SetField(entry, meta, "Notes", $"Remote command '{commandName}' executed");

            await SaveAuditEntryAsync(meta, entry, "remote command", cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to create audit entry for remote command: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Gets audit history for a specific entity
    /// </summary>
    public async ValueTask<IEnumerable<BaseDataObject>> GetEntityHistoryAsync<T>(
        uint entityKey,
        CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        var meta = GetAuditMeta();
        if (meta == null) return Array.Empty<BaseDataObject>();

        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = "EntityType", Operator = QueryOperator.Equals, Value = typeof(T).Name },
                new() { Field = "EntityKey", Operator = QueryOperator.Equals, Value = entityKey }
            },
            Sorts = new List<SortClause>
            {
                new() { Field = "TimestampUtc", Direction = SortDirection.Desc }
            }
        };

        return await meta.Handlers.QueryAsync(query, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets all audit entries with optional filtering
    /// </summary>
    public async ValueTask<IEnumerable<BaseDataObject>> QueryAuditLogAsync(
        string? entityType = null,
        string? userName = null,
        DateTime? fromDate = null,
        DateTime? toDate = null,
        AuditOperation? operation = null,
        int? limit = null,
        CancellationToken cancellationToken = default)
    {
        var meta = GetAuditMeta();
        if (meta == null) return Array.Empty<BaseDataObject>();

        var clauses = new List<QueryClause>();

        if (!string.IsNullOrEmpty(entityType))
            clauses.Add(new() { Field = "EntityType", Operator = QueryOperator.Equals, Value = entityType });

        if (!string.IsNullOrEmpty(userName))
            clauses.Add(new() { Field = "UserName", Operator = QueryOperator.Equals, Value = userName });

        if (fromDate.HasValue)
            clauses.Add(new() { Field = "TimestampUtc", Operator = QueryOperator.GreaterThanOrEqual, Value = fromDate.Value });

        if (toDate.HasValue)
            clauses.Add(new() { Field = "TimestampUtc", Operator = QueryOperator.LessThanOrEqual, Value = toDate.Value });

        if (operation.HasValue)
            clauses.Add(new() { Field = "Operation", Operator = QueryOperator.Equals, Value = operation.Value });

        var query = new QueryDefinition
        {
            Clauses = clauses,
            Sorts = new List<SortClause>
            {
                new() { Field = "TimestampUtc", Direction = SortDirection.Desc }
            },
            Top = limit ?? 100
        };

        return await meta.Handlers.QueryAsync(query, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Detects changes between old and new entity instances using pre-compiled delegates.
    /// </summary>
    private List<FieldChange> DetectChanges<T>(T oldEntity, T newEntity) where T : BaseDataObject
    {
        var changes = new List<FieldChange>();
        var type = typeof(T);

        // Fields to skip (metadata fields that always change + sensitive credential fields)
        var skipFields = new HashSet<string>
        {
            "UpdatedOnUtc", "UpdatedBy", "ETag", "Version",
            "PasswordHash", "PasswordSalt", "PasswordIterations",
            "MfaSecret", "MfaSecretEncrypted",
            "MfaPendingSecret", "MfaPendingSecretEncrypted",
            "MfaLastVerifiedStep", "MfaPendingFailedAttempts",
            "MfaBackupCodeHashes",
            "ApiKeyHashes"
        };

        // Use DataScaffold metadata (compiled delegates) instead of raw reflection
        var meta = DataScaffold.GetEntityByType(type);
        if (meta != null)
        {
            foreach (var field in meta.Fields)
            {
                if (skipFields.Contains(field.Name))
                    continue;

                try
                {
                    var oldValue = field.GetValueFn(oldEntity);
                    var newValue = field.GetValueFn(newEntity);

                    if (!AreEqual(oldValue, newValue))
                    {
                        changes.Add(new FieldChange(
                            field.Name,
                            SerializeValue(oldValue),
                            SerializeValue(newValue)
                        ));
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogError($"Failed to detect change for property {field.Name}: {ex.Message}", ex);
                }
            }
            return changes;
        }

        // Fallback for unregistered types — uses cached compiled delegates
        foreach (var (name, getter) in GetCachedAccessors(type))
        {
            if (skipFields.Contains(name))
                continue;

            try
            {
                var oldValue = getter(oldEntity);
                var newValue = getter(newEntity);

                if (!AreEqual(oldValue, newValue))
                {
                    changes.Add(new FieldChange(
                        name,
                        SerializeValue(oldValue),
                        SerializeValue(newValue)
                    ));
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Failed to detect change for property {name}: {ex.Message}", ex);
            }
        }

        return changes;
    }

    private static bool AreEqual(object? a, object? b)
    {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;

        // Handle collections
        if (a is IEnumerable<object> enumA && b is IEnumerable<object> enumB)
        {
            using var eA = enumA.GetEnumerator();
            using var eB = enumB.GetEnumerator();
            while (true)
            {
                bool hasA = eA.MoveNext();
                bool hasB = eB.MoveNext();
                if (!hasA && !hasB) return true;
                if (hasA != hasB) return false;
                if (!Equals(eA.Current, eB.Current)) return false;
            }
        }

        return a.Equals(b);
    }

    private static string? SerializeValue(object? value)
    {
        if (value == null)
            return null;

        try
        {
            // For simple types, use ToString
            if (value is string || value.GetType().IsPrimitive || value is DateTime || value is Guid)
                return value.ToString();

            // For complex types, use JSON
            return DataJsonWriter.ToJsonString(value);
        }
        catch
        {
            return value.ToString();
        }
    }

    /// <summary>
    /// Captures an audit record for a denied operation (authorization failure).
    /// </summary>
    public async ValueTask AuditDeniedAsync(
        string entityType,
        uint entityKey,
        string attemptedAction,
        string userName,
        string reason,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var meta = GetAuditMeta();
            if (meta == null) return;
            var entry = CreateAuditRecord(meta, userName);
            if (entry == null) return;

            SetField(entry, meta, "EntityType", entityType);
            SetField(entry, meta, "EntityKey", entityKey);
            SetField(entry, meta, "Operation", AuditOperation.AccessDenied);
            SetField(entry, meta, "TimestampUtc", DateTime.UtcNow);
            SetField(entry, meta, "UserName", userName);
            SetField(entry, meta, "Notes", $"Denied {attemptedAction}: {reason}");

            await SaveAuditEntryAsync(meta, entry, "access denied", cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to create audit entry for denied operation: {ex.Message}", ex);
        }
    }

    private async ValueTask SaveAuditEntryAsync(DataEntityMetadata meta, BaseDataObject entry, string operationName, CancellationToken cancellationToken)
    {
        // Auto-assign a sequential key if not already set
        if (entry.Key == 0)
        {
            var provider = DataStoreProvider.PrimaryProvider;
            entry.Key = provider != null
                ? provider.NextSequentialKey("AuditEntry")
                : IdSequenceProvider.NextKey("AuditEntry");
        }

        if (RunSynchronously)
        {
            await meta.Handlers.SaveAsync(entry, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    await meta.Handlers.SaveAsync(entry, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger?.LogError($"Failed to save audit entry for {operationName}: {ex.Message}", ex);
                }
            }, cancellationToken);
        }
    }
}
