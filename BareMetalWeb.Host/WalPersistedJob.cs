using System;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

/// <summary>
/// WAL-persisted record for a background job, enabling cross-instance job visibility.
/// One record per job; upserted on start, progress milestones, and completion.
/// Key is derived deterministically from <see cref="JobId"/> via FNV-1a so the same
/// job is always mapped to the same WAL slot regardless of which instance writes it.
/// </summary>
[DataEntity("Background Jobs", Slug = "background-jobs", ShowOnNav = false,
    NavGroup = "Admin", NavOrder = 99, Permissions = "admin")]
public sealed class WalPersistedJob : BaseDataObject
{
    public override string EntityTypeName => "WalPersistedJob";
    private const int Ord_JobId = BaseFieldCount + 0;
    private const int Ord_OperationName = BaseFieldCount + 1;
    private const int Ord_Status = BaseFieldCount + 2;
    private const int Ord_PercentComplete = BaseFieldCount + 3;
    private const int Ord_Description = BaseFieldCount + 4;
    private const int Ord_StartedAtUtc = BaseFieldCount + 5;
    private const int Ord_CompletedAtUtc = BaseFieldCount + 6;
    private const int Ord_Error = BaseFieldCount + 7;
    private const int Ord_ResultUrl = BaseFieldCount + 8;
    private const int Ord_InstanceId = BaseFieldCount + 9;
    internal const int TotalFieldCount = BaseFieldCount + 10;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CompletedAtUtc", Ord_CompletedAtUtc),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("Description", Ord_Description),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Error", Ord_Error),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("InstanceId", Ord_InstanceId),
        new FieldSlot("JobId", Ord_JobId),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("OperationName", Ord_OperationName),
        new FieldSlot("PercentComplete", Ord_PercentComplete),
        new FieldSlot("ResultUrl", Ord_ResultUrl),
        new FieldSlot("StartedAtUtc", Ord_StartedAtUtc),
        new FieldSlot("Status", Ord_Status),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public WalPersistedJob() : base(TotalFieldCount) { }
    public WalPersistedJob(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Unique job identifier (GUID, "N" format — 32 hex chars).</summary>
    [DataField(Label = "Job ID", Order = 1)]
    public string JobId
    {
        get => (string?)_values[Ord_JobId] ?? string.Empty;
        set => _values[Ord_JobId] = value;
    }

    /// <summary>Human-readable name of the operation being performed.</summary>
    [DataField(Label = "Operation", Order = 2)]
    public string OperationName
    {
        get => (string?)_values[Ord_OperationName] ?? string.Empty;
        set => _values[Ord_OperationName] = value;
    }

    /// <summary>Current status: "queued", "running", "succeeded", or "failed".</summary>
    [DataField(Label = "Status", Order = 3)]
    public string Status
    {
        get => (string?)_values[Ord_Status] ?? string.Empty;
        set => _values[Ord_Status] = value;
    }

    /// <summary>Completion percentage in the range [0, 100].</summary>
    [DataField(Label = "Progress %", Order = 4)]
    public int PercentComplete
    {
        get => (int)(_values[Ord_PercentComplete] ?? 0);
        set => _values[Ord_PercentComplete] = value;
    }

    /// <summary>Latest human-readable progress message from the job.</summary>
    [DataField(Label = "Details", Order = 5)]
    public string Description
    {
        get => (string?)_values[Ord_Description] ?? string.Empty;
        set => _values[Ord_Description] = value;
    }

    /// <summary>UTC timestamp when the job was first queued.</summary>
    [DataField(Label = "Started At (UTC)", Order = 6)]
    public DateTime StartedAtUtc
    {
        get => _values[Ord_StartedAtUtc] is DateTime dt ? dt : default;
        set => _values[Ord_StartedAtUtc] = value;
    }

    /// <summary>UTC timestamp when the job finished (null while still running).</summary>
    [DataField(Label = "Completed At (UTC)", Order = 7)]
    public DateTime? CompletedAtUtc
    {
        get => _values[Ord_CompletedAtUtc] as DateTime?;
        set => _values[Ord_CompletedAtUtc] = value;
    }

    /// <summary>Error message if the job failed, otherwise null.</summary>
    [DataField(Label = "Error", Order = 8)]
    public string? Error
    {
        get => (string?)_values[Ord_Error];
        set => _values[Ord_Error] = value;
    }

    /// <summary>Optional result URL returned when the job succeeds.</summary>
    [DataField(Label = "Result URL", Order = 9)]
    public string? ResultUrl
    {
        get => (string?)_values[Ord_ResultUrl];
        set => _values[Ord_ResultUrl] = value;
    }

    /// <summary>
    /// Identifier of the server instance that owns this job
    /// (format: <c>MachineName/ProcessId</c>).
    /// </summary>
    [DataField(Label = "Instance", Order = 10)]
    public string InstanceId
    {
        get => (string?)_values[Ord_InstanceId] ?? string.Empty;
        set => _values[Ord_InstanceId] = value;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Derives a stable, non-zero <c>uint</c> WAL key from a job ID string using FNV-1a.
    /// The same input always produces the same key, guaranteeing in-place upserts.
    /// Job IDs are always 32 ASCII hex chars ("N" format), so <c>(byte)c</c> is safe.
    /// </summary>
    public static uint DeriveKey(string jobId)
    {
        uint h = 2166136261u;
        foreach (char c in jobId.AsSpan())
            h = (h ^ (byte)c) * 16777619u;
        return h == 0 ? 1u : h;
    }
}

/// <summary>Ordinal constants for <see cref="WalPersistedJob"/> fields.</summary>
public static class WalPersistedJobFields
{
    public const int JobId          = BaseDataObject.BaseFieldCount + 0;
    public const int OperationName  = BaseDataObject.BaseFieldCount + 1;
    public const int Status         = BaseDataObject.BaseFieldCount + 2;
    public const int PercentComplete = BaseDataObject.BaseFieldCount + 3;
    public const int Description    = BaseDataObject.BaseFieldCount + 4;
    public const int StartedAtUtc   = BaseDataObject.BaseFieldCount + 5;
    public const int CompletedAtUtc = BaseDataObject.BaseFieldCount + 6;
    public const int Error          = BaseDataObject.BaseFieldCount + 7;
    public const int ResultUrl      = BaseDataObject.BaseFieldCount + 8;
    public const int InstanceId     = BaseDataObject.BaseFieldCount + 9;
}
