namespace BareMetalWeb.ControlPlane;

/// <summary>
/// Point-in-time health snapshot for the observability telemetry pipeline.
/// Returned by <see cref="ControlPlaneService.GetHealth"/>.
/// </summary>
public readonly struct ObservabilityHealth
{
    /// <summary>Number of records currently waiting in the offline buffer.</summary>
    public int PendingQueueDepth { get; init; }

    /// <summary>Total records dropped because the buffer was full.</summary>
    public long DroppedCount { get; init; }

    /// <summary>Total send attempts that were retried after an initial failure.</summary>
    public long RetryCount { get; init; }

    /// <summary>UTC timestamp of the last successfully delivered batch, or null if none.</summary>
    public DateTime? LastSuccessfulSendUtc { get; init; }

    /// <summary>Whether the most recent send attempt reached the control-plane endpoint.</summary>
    public bool IsOnline { get; init; }
}
