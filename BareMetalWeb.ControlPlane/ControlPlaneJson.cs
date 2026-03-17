using System.Buffers;
using System.Text;
using System.Text.Json;

namespace BareMetalWeb.ControlPlane;

/// <summary>
/// Manual Utf8JsonWriter / JsonDocument serializers for all ControlPlane model types.
/// Eliminates JsonSerializer dependency — uses snake_case property names and skips null strings.
/// </summary>
internal static class ControlPlaneJson
{
    // ── Serialize ────────────────────────────────────────────────────────────

    internal static string Serialize(NodeRegistrationRequest obj)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (obj.NodeId is not null) w.WriteString("node_id"u8, obj.NodeId);
        if (obj.SecretHash is not null) w.WriteString("secret_hash"u8, obj.SecretHash);
        if (obj.BootstrapPrincipal is not null) w.WriteString("bootstrap_principal"u8, obj.BootstrapPrincipal);
        if (obj.Architecture is not null) w.WriteString("architecture"u8, obj.Architecture);
        if (obj.OsDescription is not null) w.WriteString("os_description"u8, obj.OsDescription);
        if (obj.GlibcVersion is not null) w.WriteString("glibc_version"u8, obj.GlibcVersion);
        if (obj.MacHash is not null) w.WriteString("mac_hash"u8, obj.MacHash);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(NodeAttestationRequest obj)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (obj.NodeId is not null) w.WriteString("node_id"u8, obj.NodeId);
        if (obj.Architecture is not null) w.WriteString("architecture"u8, obj.Architecture);
        if (obj.OsDescription is not null) w.WriteString("os_description"u8, obj.OsDescription);
        if (obj.GlibcVersion is not null) w.WriteString("glibc_version"u8, obj.GlibcVersion);
        if (obj.MacHash is not null) w.WriteString("mac_hash"u8, obj.MacHash);
        if (obj.Timestamp is not null) w.WriteString("timestamp"u8, obj.Timestamp);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(NodeIdentity obj)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (obj.NodeId is not null) w.WriteString("node_id"u8, obj.NodeId);
        if (obj.ServicePrincipal is not null) w.WriteString("service_principal"u8, obj.ServicePrincipal);
        if (obj.Secret is not null) w.WriteString("secret"u8, obj.Secret);
        if (obj.ClusterEndpoint is not null) w.WriteString("cluster_endpoint"u8, obj.ClusterEndpoint);
        if (obj.CertFingerprint is not null) w.WriteString("cert_fingerprint"u8, obj.CertFingerprint);
        w.WriteString("ring"u8, obj.Ring.ToString());
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(InstanceHeartbeat obj)
    {
        var buf = new ArrayBufferWriter<byte>(512);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (obj.InstanceId is not null) w.WriteString("instance_id"u8, obj.InstanceId);
        if (obj.Url is not null) w.WriteString("url"u8, obj.Url);
        if (obj.Version is not null) w.WriteString("version"u8, obj.Version);
        if (obj.CommitSha is not null) w.WriteString("commit_sha"u8, obj.CommitSha);
        w.WriteNumber("uptime_seconds"u8, obj.UptimeSeconds);
        if (obj.Status is not null) w.WriteString("status"u8, obj.Status);
        w.WriteBoolean("ready"u8, obj.Ready);
        w.WriteNumber("record_count"u8, obj.RecordCount);
        w.WriteNumber("wal_segment_count"u8, obj.WalSegmentCount);
        if (obj.LastBackupAt is not null) w.WriteString("last_backup_at"u8, obj.LastBackupAt);
        if (obj.LastCompactionAt is not null) w.WriteString("last_compaction_at"u8, obj.LastCompactionAt);
        w.WriteNumber("memory_mb"u8, obj.MemoryMb);
        w.WriteNumber("requests_total"u8, obj.RequestsTotal);
        w.WriteNumber("error_rate5xx"u8, obj.ErrorRate5xx);
        w.WriteBoolean("is_leader"u8, obj.IsLeader);
        w.WriteNumber("epoch"u8, obj.Epoch);
        if (obj.Timestamp is not null) w.WriteString("timestamp"u8, obj.Timestamp);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(TelemetrySnapshot obj)
    {
        var buf = new ArrayBufferWriter<byte>(512);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (obj.InstanceId is not null) w.WriteString("instance_id"u8, obj.InstanceId);
        if (obj.PeriodStart is not null) w.WriteString("period_start"u8, obj.PeriodStart);
        if (obj.PeriodEnd is not null) w.WriteString("period_end"u8, obj.PeriodEnd);
        w.WriteNumber("requests_total"u8, obj.RequestsTotal);
        w.WriteNumber("requests2xx"u8, obj.Requests2xx);
        w.WriteNumber("requests4xx"u8, obj.Requests4xx);
        w.WriteNumber("requests5xx"u8, obj.Requests5xx);
        w.WriteNumber("throttled_requests"u8, obj.ThrottledRequests);
        w.WriteNumber("p50_ms"u8, obj.P50Ms);
        w.WriteNumber("p95_ms"u8, obj.P95Ms);
        w.WriteNumber("p99_ms"u8, obj.P99Ms);
        w.WriteNumber("wal_reads"u8, obj.WalReads);
        w.WriteNumber("wal_commits"u8, obj.WalCommits);
        w.WriteNumber("wal_compactions"u8, obj.WalCompactions);
        w.WriteNumber("gc_gen0"u8, obj.GcGen0);
        w.WriteNumber("gc_gen1"u8, obj.GcGen1);
        w.WriteNumber("gc_gen2"u8, obj.GcGen2);
        w.WriteNumber("gc_allocated_bytes"u8, obj.GcAllocatedBytes);
        if (obj.TopError is not null) w.WriteString("top_error"u8, obj.TopError);
        if (obj.Timestamp is not null) w.WriteString("timestamp"u8, obj.Timestamp);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(ErrorEvent obj)
    {
        var buf = new ArrayBufferWriter<byte>(512);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (obj.InstanceId is not null) w.WriteString("instance_id"u8, obj.InstanceId);
        if (obj.Level is not null) w.WriteString("level"u8, obj.Level);
        if (obj.Message is not null) w.WriteString("message"u8, obj.Message);
        if (obj.ExceptionType is not null) w.WriteString("exception_type"u8, obj.ExceptionType);
        if (obj.StackTrace is not null) w.WriteString("stack_trace"u8, obj.StackTrace);
        if (obj.Path is not null) w.WriteString("path"u8, obj.Path);
        if (obj.Method is not null) w.WriteString("method"u8, obj.Method);
        w.WriteNumber("status_code"u8, obj.StatusCode);
        if (obj.CorrelationId is not null) w.WriteString("correlation_id"u8, obj.CorrelationId);
        if (obj.Timestamp is not null) w.WriteString("timestamp"u8, obj.Timestamp);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(BackupRecord obj)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (obj.InstanceId is not null) w.WriteString("instance_id"u8, obj.InstanceId);
        if (obj.BackupId is not null) w.WriteString("backup_id"u8, obj.BackupId);
        if (obj.Timestamp is not null) w.WriteString("timestamp"u8, obj.Timestamp);
        w.WriteNumber("record_count"u8, obj.RecordCount);
        w.WriteNumber("segment_count"u8, obj.SegmentCount);
        w.WriteNumber("size_bytes"u8, obj.SizeBytes);
        w.WriteBoolean("validated"u8, obj.Validated);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(UpgradeVerificationRecord obj)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (obj.InstanceId is not null) w.WriteString("instance_id"u8, obj.InstanceId);
        if (obj.TargetVersion is not null) w.WriteString("target_version"u8, obj.TargetVersion);
        w.WriteBoolean("success"u8, obj.Success);
        if (obj.Reason is not null) w.WriteString("reason"u8, obj.Reason);
        if (obj.Timestamp is not null) w.WriteString("timestamp"u8, obj.Timestamp);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    // ── Deserialize ─────────────────────────────────────────────────────────

    internal static RuntimeResponse? DeserializeRuntimeResponse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        return new RuntimeResponse
        {
            DesiredVersion = r.TryGetProperty("desired_version"u8, out var dv) ? dv.GetString() : null,
            Sha256 = r.TryGetProperty("sha256"u8, out var sh) ? sh.GetString() : null,
            DownloadUrl = r.TryGetProperty("download_url"u8, out var du) ? du.GetString() : null,
            PollSeconds = r.TryGetProperty("poll_seconds"u8, out var ps) ? ps.GetInt32() : 0,
        };
    }

    internal static NodeIdentity? DeserializeNodeIdentity(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        var ringStr = r.TryGetProperty("ring"u8, out var rg) ? rg.GetString() : null;
        Enum.TryParse<DeploymentRing>(ringStr, ignoreCase: true, out var ring);
        return new NodeIdentity
        {
            NodeId = r.TryGetProperty("node_id"u8, out var ni) ? ni.GetString() ?? "" : "",
            ServicePrincipal = r.TryGetProperty("service_principal"u8, out var sp) ? sp.GetString() ?? "" : "",
            Secret = r.TryGetProperty("secret"u8, out var se) ? se.GetString() ?? "" : "",
            ClusterEndpoint = r.TryGetProperty("cluster_endpoint"u8, out var ce) ? ce.GetString() ?? "" : "",
            CertFingerprint = r.TryGetProperty("cert_fingerprint"u8, out var cf) ? cf.GetString() ?? "" : "",
            Ring = ring,
        };
    }

    internal static UpgradeStatus? DeserializeUpgradeStatus(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        return new UpgradeStatus
        {
            InstanceId = r.TryGetProperty("instance_id"u8, out var ii) ? ii.GetString() : null,
            TargetVersion = r.TryGetProperty("target_version"u8, out var tv) ? tv.GetString() : null,
            CurrentVersion = r.TryGetProperty("current_version"u8, out var cv) ? cv.GetString() : null,
            Verified = r.TryGetProperty("verified"u8, out var v) && v.GetBoolean(),
            Ready = r.TryGetProperty("ready"u8, out var rd) && rd.GetBoolean(),
            ErrorRate5xx = r.TryGetProperty("error_rate5xx"u8, out var er) ? er.GetDouble() : 0,
            Timestamp = r.TryGetProperty("timestamp"u8, out var ts) ? ts.GetString() : null,
            Reason = r.TryGetProperty("reason"u8, out var re) ? re.GetString() : null,
        };
    }

    internal static List<GalleryListing>? DeserializeGalleryListings(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Support both a raw array and a wrapper object with a "packages" property
        JsonElement arr;
        if (root.ValueKind == JsonValueKind.Array)
            arr = root;
        else if (root.TryGetProperty("packages"u8, out var pkgs) && pkgs.ValueKind == JsonValueKind.Array)
            arr = pkgs;
        else
            return null;

        var list = new List<GalleryListing>(arr.GetArrayLength());
        foreach (var el in arr.EnumerateArray())
        {
            list.Add(new GalleryListing
            {
                Name = el.TryGetProperty("name"u8, out var n) ? n.GetString() : null,
                Slug = el.TryGetProperty("slug"u8, out var sl) ? sl.GetString() : null,
                Description = el.TryGetProperty("description"u8, out var d) ? d.GetString() : null,
                Icon = el.TryGetProperty("icon"u8, out var ic) ? ic.GetString() : null,
                Version = el.TryGetProperty("version"u8, out var vr) ? vr.GetString() : null,
                Author = el.TryGetProperty("author"u8, out var au) ? au.GetString() : null,
                EntityCount = el.TryGetProperty("entity_count"u8, out var ec) ? ec.GetInt32() : 0,
                FieldCount = el.TryGetProperty("field_count"u8, out var fc) ? fc.GetInt32() : 0,
                Category = el.TryGetProperty("category"u8, out var ca) ? ca.GetString() : null,
                PublishedAt = el.TryGetProperty("published_at"u8, out var pa) ? pa.GetString() : null,
                Downloads = el.TryGetProperty("downloads"u8, out var dl) ? dl.GetInt64() : 0,
            });
        }
        return list;
    }
}
