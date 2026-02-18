using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Core.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Service for capturing audit trail records for entity changes and remote commands
/// </summary>
public sealed class AuditService
{
    private readonly IDataObjectStore _store;
    private readonly IBufferedLogger? _logger;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    public AuditService(IDataObjectStore store, IBufferedLogger? logger = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _logger = logger;
    }

    /// <summary>
    /// Captures an audit record for entity creation
    /// </summary>
    public async ValueTask AuditCreateAsync<T>(T entity, string userName, CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        try
        {
            var auditEntry = new AuditEntry(userName)
            {
                EntityType = typeof(T).Name,
                EntityId = entity.Id,
                Operation = AuditOperation.Create,
                TimestampUtc = DateTime.UtcNow,
                UserName = userName,
                Notes = "Entity created"
            };

            // Fire and forget - don't block the main operation
            _ = Task.Run(async () =>
            {
                try
                {
                    await _store.SaveAsync(auditEntry, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger?.LogError($"Failed to save audit entry for create: {ex.Message}", ex);
                }
            }, cancellationToken);
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
            if (!changes.Any())
                return;

            var auditEntry = new AuditEntry(userName)
            {
                EntityType = typeof(T).Name,
                EntityId = newEntity.Id,
                Operation = AuditOperation.Update,
                TimestampUtc = DateTime.UtcNow,
                UserName = userName,
                FieldChanges = changes,
                Notes = $"{changes.Count} field(s) changed"
            };

            // Fire and forget - don't block the main operation
            _ = Task.Run(async () =>
            {
                try
                {
                    await _store.SaveAsync(auditEntry, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger?.LogError($"Failed to save audit entry for update: {ex.Message}", ex);
                }
            }, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to create audit entry for update: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Captures an audit record for entity deletion
    /// </summary>
    public async ValueTask AuditDeleteAsync<T>(string entityId, string userName, CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        try
        {
            var auditEntry = new AuditEntry(userName)
            {
                EntityType = typeof(T).Name,
                EntityId = entityId,
                Operation = AuditOperation.Delete,
                TimestampUtc = DateTime.UtcNow,
                UserName = userName,
                Notes = "Entity deleted"
            };

            // Fire and forget - don't block the main operation
            _ = Task.Run(async () =>
            {
                try
                {
                    await _store.SaveAsync(auditEntry, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger?.LogError($"Failed to save audit entry for delete: {ex.Message}", ex);
                }
            }, cancellationToken);
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
            var auditEntry = new AuditEntry(userName)
            {
                EntityType = typeof(T).Name,
                EntityId = entity.Id,
                Operation = AuditOperation.RemoteCommand,
                TimestampUtc = DateTime.UtcNow,
                UserName = userName,
                CommandName = commandName,
                CommandParameters = parameters != null ? JsonSerializer.Serialize(parameters, JsonOptions) : null,
                CommandResult = result != null ? $"Success: {result.Success}, Message: {result.Message}" : null,
                Notes = $"Remote command '{commandName}' executed"
            };

            // Fire and forget - don't block the main operation
            _ = Task.Run(async () =>
            {
                try
                {
                    await _store.SaveAsync(auditEntry, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger?.LogError($"Failed to save audit entry for remote command: {ex.Message}", ex);
                }
            }, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to create audit entry for remote command: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Gets audit history for a specific entity
    /// </summary>
    public async ValueTask<IEnumerable<AuditEntry>> GetEntityHistoryAsync<T>(
        string entityId,
        CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        // Query all audit entries for this entity type and ID
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = nameof(AuditEntry.EntityType), Operator = QueryOperator.Equals, Value = typeof(T).Name },
                new() { Field = nameof(AuditEntry.EntityId), Operator = QueryOperator.Equals, Value = entityId }
            },
            Sorts = new List<SortClause>
            {
                new() { Field = nameof(AuditEntry.TimestampUtc), Direction = SortDirection.Desc }
            }
        };

        return await _store.QueryAsync<AuditEntry>(query, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets all audit entries with optional filtering
    /// </summary>
    public async ValueTask<IEnumerable<AuditEntry>> QueryAuditLogAsync(
        string? entityType = null,
        string? userName = null,
        DateTime? fromDate = null,
        DateTime? toDate = null,
        AuditOperation? operation = null,
        int? limit = null,
        CancellationToken cancellationToken = default)
    {
        var clauses = new List<QueryClause>();

        if (!string.IsNullOrEmpty(entityType))
            clauses.Add(new() { Field = nameof(AuditEntry.EntityType), Operator = QueryOperator.Equals, Value = entityType });

        if (!string.IsNullOrEmpty(userName))
            clauses.Add(new() { Field = nameof(AuditEntry.UserName), Operator = QueryOperator.Equals, Value = userName });

        if (fromDate.HasValue)
            clauses.Add(new() { Field = nameof(AuditEntry.TimestampUtc), Operator = QueryOperator.GreaterThanOrEqual, Value = fromDate.Value });

        if (toDate.HasValue)
            clauses.Add(new() { Field = nameof(AuditEntry.TimestampUtc), Operator = QueryOperator.LessThanOrEqual, Value = toDate.Value });

        if (operation.HasValue)
            clauses.Add(new() { Field = nameof(AuditEntry.Operation), Operator = QueryOperator.Equals, Value = operation.Value });

        var query = new QueryDefinition
        {
            Clauses = clauses,
            Sorts = new List<SortClause>
            {
                new() { Field = nameof(AuditEntry.TimestampUtc), Direction = SortDirection.Desc }
            },
            Top = limit ?? 100
        };

        return await _store.QueryAsync<AuditEntry>(query, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Detects changes between old and new entity instances
    /// </summary>
    private List<FieldChange> DetectChanges<T>(T oldEntity, T newEntity) where T : BaseDataObject
    {
        var changes = new List<FieldChange>();
        var type = typeof(T);

        // Get all public properties
        var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.CanRead && p.CanWrite);

        // Fields to skip (metadata fields that always change)
        var skipFields = new HashSet<string> { "UpdatedOnUtc", "UpdatedBy", "ETag" };

        foreach (var prop in properties)
        {
            if (skipFields.Contains(prop.Name))
                continue;

            try
            {
                var oldValue = prop.GetValue(oldEntity);
                var newValue = prop.GetValue(newEntity);

                // Compare values
                if (!AreEqual(oldValue, newValue))
                {
                    changes.Add(new FieldChange(
                        prop.Name,
                        SerializeValue(oldValue),
                        SerializeValue(newValue)
                    ));
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Failed to detect change for property {prop.Name}: {ex.Message}", ex);
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
            return enumA.SequenceEqual(enumB);
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
            return JsonSerializer.Serialize(value, JsonOptions);
        }
        catch
        {
            return value.ToString();
        }
    }
}
