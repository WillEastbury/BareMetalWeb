using System.Buffers.Binary;
using BareMetalWeb.ControlPlane;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Cluster replication and status endpoints.
/// GET /api/_cluster — cluster state snapshot (role, epoch, LSN)
/// GET /api/_cluster/replicate?afterLsn=X — WAL entries for follower catch-up
/// POST /api/_cluster/stepdown — voluntarily step down from leadership
/// All endpoints require admin authentication.
/// </summary>
public static class ClusterApiHandlers
{
    private static ClusterState? _clusterState;
    private static CompactorState? _compactorState;

    /// <summary>Initialize with cluster state reference.</summary>
    public static void Initialize(ClusterState clusterState, CompactorState? compactorState = null)
    {
        _clusterState = clusterState;
        _compactorState = compactorState;
    }

    /// <summary>GET /api/_cluster — cluster state snapshot.</summary>
    public static async ValueTask ClusterStatusHandler(BmwContext context)
    {
        if (!await RequireAdminAsync(context)) return;

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
        w.WriteBoolean("isCompactor", _compactorState?.IsCompactor ?? false);
        w.WriteEndObject();
        await w.FlushAsync(context.RequestAborted);
    }

    /// <summary>
    /// GET /api/_cluster/replicate?afterLsn=X — return WAL entries after given LSN.
    /// Followers poll this endpoint to catch up with the leader.
    /// </summary>
    public static async ValueTask ReplicationHandler(BmwContext context)
    {
        if (!await RequireAdminAsync(context)) return;

        if (_clusterState == null || !_clusterState.IsLeader)
        {
            context.Response.StatusCode = 503;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("""{"error":"not_leader","message":"This instance is not the leader. Redirect to the current leader."}""");
            return;
        }

        if (!context.HttpRequest.Query.TryGetValue("afterLsn", out var afterLsnStr) ||
            !long.TryParse(afterLsnStr, out var afterLsn))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("afterLsn query parameter required.");
            return;
        }

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
    public static async ValueTask StepDownHandler(BmwContext context)
    {
        if (!await RequireAdminAsync(context)) return;

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

    /// <summary>Require admin-level authentication. Returns false and writes 401/403 if denied.</summary>
    private static async ValueTask<bool> RequireAdminAsync(BmwContext context)
    {
        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted);
        if (user == null)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("""{"error":"Authentication required."}""");
            return false;
        }
        var perms = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        if (!perms.Contains("admin") && !perms.Contains("monitoring"))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("""{"error":"Admin access required."}""");
            return false;
        }
        return true;
    }

    /// <summary>
    /// GET /api/_cluster/upgrade-status?instanceId=X&amp;targetVersion=Y
    /// Returns whether the named instance has self-reported the target version with healthy status.
    /// Deployment agents poll this endpoint to gate rollout success on pod version + error-rate data.
    /// Requires admin or monitoring permission.
    /// </summary>
    public static async ValueTask UpgradeStatusHandler(BmwContext context)
    {
        if (!await RequireAdminAsync(context)) return;

        var instanceId = context.HttpRequest.Query.TryGetValue("instanceId", out var iid)
            ? iid.ToString() : null;
        var targetVersion = context.HttpRequest.Query.TryGetValue("targetVersion", out var tv)
            ? tv.ToString() : null;

        if (string.IsNullOrWhiteSpace(instanceId) || string.IsNullOrWhiteSpace(targetVersion))
        {
            context.Response.StatusCode = 400;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                """{"error":"instanceId and targetVersion query parameters are required."}""");
            return;
        }

        if (!DataScaffold.TryGetEntity("InstanceHeartbeat", out var meta))
        {
            context.Response.StatusCode = 503;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                """{"error":"InstanceHeartbeat entity not registered on this instance."}""");
            return;
        }

        InstanceHeartbeat? latest = null;
        try
        {
            var query = new QueryDefinition
            {
                Clauses =
                [
                    new QueryClause
                    {
                        Field = "InstanceId",
                        Operator = QueryOperator.Equals,
                        Value = instanceId,
                    }
                ],
                Sorts = [new SortClause { Field = "Timestamp", Direction = SortDirection.Desc }],
                Top = 1,
            };
            var results = await DataScaffold.QueryAsync(meta, query, context.RequestAborted)
                .ConfigureAwait(false);
            foreach (var r in results)
            {
                if (r is InstanceHeartbeat hb) { latest = hb; break; }
                if (r != null)
                {
                    // Use metadata-driven field access for DataRecord or other BaseDataObject subtypes
                    latest = new InstanceHeartbeat
                    {
                        InstanceId   = GetFieldString(r, "InstanceId"),
                        Version      = GetFieldString(r, "Version"),
                        Ready        = GetFieldValue(r, "Ready") is bool rd && rd,
                        ErrorRate5xx = GetFieldValue(r, "ErrorRate5xx") is double er ? er : 0,
                        Timestamp    = GetFieldString(r, "Timestamp"),
                    };
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            context.Response.StatusCode = 500;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                $"{{\"error\":\"Query failed: {System.Text.Json.JsonEncodedText.Encode(ex.Message)}\"}}");
            return;
        }

        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";
        await using var w = new System.Text.Json.Utf8JsonWriter(context.Response.Body);
        w.WriteStartObject();
        w.WriteString("instanceId", instanceId);
        w.WriteString("targetVersion", targetVersion);

        if (latest == null)
        {
            w.WriteBoolean("verified", false);
            w.WriteBoolean("ready", false);
            w.WriteNumber("errorRate5xx", 0);
            w.WriteNull("currentVersion");
            w.WriteNull("timestamp");
            w.WriteString("reason", "no_heartbeat_found");
        }
        else
        {
            const double BlockingErrorThreshold = 0.05;
            bool versionMatch = string.Equals(latest.Version, targetVersion, StringComparison.OrdinalIgnoreCase);
            bool ready = latest.Ready;
            bool errorRateOk = latest.ErrorRate5xx < BlockingErrorThreshold;
            bool verified = versionMatch && ready && errorRateOk;

            string reason = verified ? "ok"
                : !versionMatch ? $"version_mismatch:reported={latest.Version}"
                : !ready        ? "not_ready"
                : $"error_rate_too_high:{latest.ErrorRate5xx:F4}";

            w.WriteBoolean("verified", verified);
            w.WriteBoolean("ready", ready);
            w.WriteNumber("errorRate5xx", latest.ErrorRate5xx);
            w.WriteString("currentVersion", latest.Version);
            w.WriteString("timestamp", latest.Timestamp);
            w.WriteString("reason", reason);
        }

        w.WriteEndObject();
        await w.FlushAsync(context.RequestAborted);
    }

    /// <summary>Reads a field value from a query result using metadata (no reflection).</summary>
    private static object? GetFieldValue(object obj, string fieldName)
    {
        if (obj is DataRecord rec && rec.Schema != null)
            return rec.GetField(rec.Schema, fieldName);

        if (obj is BaseDataObject bdo)
        {
            var meta = DataScaffold.GetEntityByType(bdo.GetType());
            if (meta != null)
            {
                var field = meta.FindField(fieldName);
                if (field != null) return field.GetValueFn(bdo);
                return EntityLayoutCompiler.GetOrCompile(meta).FieldByName(fieldName)?.Getter(bdo);
            }
        }

        return null;
    }

    private static string? GetFieldString(object obj, string fieldName)
        => GetFieldValue(obj, fieldName) as string;
}
