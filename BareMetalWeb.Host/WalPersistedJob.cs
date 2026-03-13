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
    /// <summary>Unique job identifier (GUID, "N" format — 32 hex chars).</summary>
    [DataField(Label = "Job ID", Order = 1)]
    public string JobId { get; set; } = string.Empty;

    /// <summary>Human-readable name of the operation being performed.</summary>
    [DataField(Label = "Operation", Order = 2)]
    public string OperationName { get; set; } = string.Empty;

    /// <summary>Current status: "queued", "running", "succeeded", or "failed".</summary>
    [DataField(Label = "Status", Order = 3)]
    public string Status { get; set; } = string.Empty;

    /// <summary>Completion percentage in the range [0, 100].</summary>
    [DataField(Label = "Progress %", Order = 4)]
    public int PercentComplete { get; set; }

    /// <summary>Latest human-readable progress message from the job.</summary>
    [DataField(Label = "Details", Order = 5)]
    public string Description { get; set; } = string.Empty;

    /// <summary>UTC timestamp when the job was first queued.</summary>
    [DataField(Label = "Started At (UTC)", Order = 6)]
    public DateTime StartedAtUtc { get; set; }

    /// <summary>UTC timestamp when the job finished (null while still running).</summary>
    [DataField(Label = "Completed At (UTC)", Order = 7)]
    public DateTime? CompletedAtUtc { get; set; }

    /// <summary>Error message if the job failed, otherwise null.</summary>
    [DataField(Label = "Error", Order = 8)]
    public string? Error { get; set; }

    /// <summary>Optional result URL returned when the job succeeds.</summary>
    [DataField(Label = "Result URL", Order = 9)]
    public string? ResultUrl { get; set; }

    /// <summary>
    /// Identifier of the server instance that owns this job
    /// (format: <c>MachineName/ProcessId</c>).
    /// </summary>
    [DataField(Label = "Instance", Order = 10)]
    public string InstanceId { get; set; } = string.Empty;

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
    public const int JobId          = 0;
    public const int OperationName  = 1;
    public const int Status         = 2;
    public const int PercentComplete = 3;
    public const int Description    = 4;
    public const int StartedAtUtc   = 5;
    public const int CompletedAtUtc = 6;
    public const int Error          = 7;
    public const int ResultUrl      = 8;
    public const int InstanceId     = 9;
}
