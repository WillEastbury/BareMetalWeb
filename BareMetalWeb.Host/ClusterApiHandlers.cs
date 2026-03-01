using System.Buffers.Binary;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Cluster replication and status endpoints.
/// GET /api/_cluster — cluster state snapshot (role, epoch, LSN)
/// GET /api/_cluster/replicate?afterLsn=X — WAL entries for follower catch-up
/// POST /api/_cluster/stepdown — voluntarily step down from leadership
/// </summary>
public static class ClusterApiHandlers
{
    private static ClusterState? _clusterState;

    /// <summary>Initialize with cluster state reference.</summary>
    public static void Initialize(ClusterState clusterState) => _clusterState = clusterState;

    /// <summary>GET /api/_cluster — cluster state snapshot.</summary>
    public static async ValueTask ClusterStatusHandler(HttpContext context)
    {
        if (_clusterState == null)
        {
            context.Response.StatusCode = 503;
            await context.Response.WriteAsync("Cluster state not initialized.");
            return;
        }

        var snapshot = _clusterState.GetSnapshot();

        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";
        await using var w = new System.Text.Json.Utf8JsonWriter(context.Response.Body);
        w.WriteStartObject();
        w.WriteString("role", snapshot.Role.ToString().ToLowerInvariant());
        w.WriteNumber("epoch", snapshot.Epoch);
        w.WriteNumber("lastLsn", snapshot.LastLsn);
        w.WriteString("instanceId", snapshot.InstanceId);
        w.WriteBoolean("leaseValid", snapshot.IsLeaseValid);
        w.WriteEndObject();
        await w.FlushAsync(context.RequestAborted);
    }

    /// <summary>
    /// GET /api/_cluster/replicate?afterLsn=X — return WAL entries after given LSN.
    /// Followers poll this endpoint to catch up with the leader.
    /// </summary>
    public static async ValueTask ReplicationHandler(HttpContext context)
    {
        if (_clusterState == null || !_clusterState.IsLeader)
        {
            context.Response.StatusCode = 503;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("""{"error":"not_leader","message":"This instance is not the leader. Redirect to the current leader."}""");
            return;
        }

        if (!context.Request.Query.TryGetValue("afterLsn", out var afterLsnStr) ||
            !long.TryParse(afterLsnStr, out var afterLsn))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("afterLsn query parameter required.");
            return;
        }

        // Return current state info — followers use this to track progress
        // Full WAL entry streaming would require WalStore segment access;
        // for now, return metadata sufficient for follower to detect lag
        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";
        await using var w = new System.Text.Json.Utf8JsonWriter(context.Response.Body);
        w.WriteStartObject();
        w.WriteNumber("epoch", _clusterState.CurrentEpoch);
        w.WriteNumber("leaderLsn", _clusterState.LastLsn);
        w.WriteNumber("afterLsn", afterLsn);
        w.WriteNumber("lag", _clusterState.LastLsn - afterLsn);
        w.WriteString("instanceId", _clusterState.InstanceId);
        w.WriteEndObject();
        await w.FlushAsync(context.RequestAborted);
    }

    /// <summary>POST /api/_cluster/stepdown — voluntary leadership stepdown.</summary>
    public static async ValueTask StepDownHandler(HttpContext context)
    {
        if (_clusterState == null)
        {
            context.Response.StatusCode = 503;
            await context.Response.WriteAsync("Cluster state not initialized.");
            return;
        }

        await _clusterState.StepDownAsync(context.RequestAborted);

        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("""{"success":true,"role":"follower"}""");
    }
}
