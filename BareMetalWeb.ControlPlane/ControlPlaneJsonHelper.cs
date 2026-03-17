using System.Buffers;
using System.Text;
using System.Text.Json;

namespace BareMetalWeb.ControlPlane;

/// <summary>
/// Low-allocation JSON helpers using Utf8JsonWriter and JsonDocument directly,
/// bypassing JsonSerializer to eliminate reflection and attribute-scanning overhead.
/// Property names are hardcoded in snake_case to match the wire format.
/// Null string values are omitted (equivalent to WhenWritingNull).
/// </summary>
internal static class ControlPlaneJsonHelper
{
    // ── Generic dispatch ─────────────────────────────────────────────────────

    internal static string SerializeObject<T>(T value) => value switch
    {
        NodeRegistrationRequest v => Serialize(v),
        NodeAttestationRequest v => Serialize(v),
        InstanceHeartbeat v => Serialize(v),
        TelemetrySnapshot v => Serialize(v),
        ErrorEvent v => Serialize(v),
        BackupRecord v => Serialize(v),
        UpgradeVerificationRecord v => Serialize(v),
        _ => throw new NotSupportedException($"No manual JSON serializer for {typeof(T).Name}"),
    };

    internal static T? DeserializeObject<T>(string json) where T : class
    {
        if (typeof(T) == typeof(RuntimeResponse))
            return DeserializeRuntimeResponse(json) as T;
        if (typeof(T) == typeof(NodeIdentity))
            return DeserializeNodeIdentity(json) as T;
        if (typeof(T) == typeof(UpgradeStatus))
            return DeserializeUpgradeStatus(json) as T;
        if (typeof(T) == typeof(List<GalleryListing>))
            return DeserializeGalleryListings(json) as T;
        throw new NotSupportedException($"No manual JSON deserializer for {typeof(T).Name}");
    }

    // ── Serializers ──────────────────────────────────────────────────────────

    internal static string Serialize(NodeRegistrationRequest v)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        w.WriteString("node_id"u8, v.NodeId);
        w.WriteString("secret_hash"u8, v.SecretHash);
        w.WriteString("bootstrap_principal"u8, v.BootstrapPrincipal);
        w.WriteString("architecture"u8, v.Architecture);
        w.WriteString("os_description"u8, v.OsDescription);
        w.WriteString("glibc_version"u8, v.GlibcVersion);
        w.WriteString("mac_hash"u8, v.MacHash);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(NodeAttestationRequest v)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        w.WriteString("node_id"u8, v.NodeId);
        w.WriteString("architecture"u8, v.Architecture);
        w.WriteString("os_description"u8, v.OsDescription);
        w.WriteString("glibc_version"u8, v.GlibcVersion);
        w.WriteString("mac_hash"u8, v.MacHash);
        w.WriteString("timestamp"u8, v.Timestamp);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(InstanceHeartbeat v)
    {
        var buf = new ArrayBufferWriter<byte>(512);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (v.InstanceId != null) w.WriteString("instance_id"u8, v.InstanceId);
        if (v.Url != null) w.WriteString("url"u8, v.Url);
        if (v.Version != null) w.WriteString("version"u8, v.Version);
        if (v.CommitSha != null) w.WriteString("commit_sha"u8, v.CommitSha);
        w.WriteNumber("uptime_seconds"u8, v.UptimeSeconds);
        if (v.Status != null) w.WriteString("status"u8, v.Status);
        w.WriteBoolean("ready"u8, v.Ready);
        w.WriteNumber("record_count"u8, v.RecordCount);
        w.WriteNumber("wal_segment_count"u8, v.WalSegmentCount);
        if (v.LastBackupAt != null) w.WriteString("last_backup_at"u8, v.LastBackupAt);
        if (v.LastCompactionAt != null) w.WriteString("last_compaction_at"u8, v.LastCompactionAt);
        w.WriteNumber("memory_mb"u8, v.MemoryMb);
        w.WriteNumber("requests_total"u8, v.RequestsTotal);
        w.WriteNumber("error_rate5xx"u8, v.ErrorRate5xx);
        w.WriteBoolean("is_leader"u8, v.IsLeader);
        w.WriteNumber("epoch"u8, v.Epoch);
        if (v.Timestamp != null) w.WriteString("timestamp"u8, v.Timestamp);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(TelemetrySnapshot v)
    {
        var buf = new ArrayBufferWriter<byte>(512);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (v.InstanceId != null) w.WriteString("instance_id"u8, v.InstanceId);
        if (v.PeriodStart != null) w.WriteString("period_start"u8, v.PeriodStart);
        if (v.PeriodEnd != null) w.WriteString("period_end"u8, v.PeriodEnd);
        w.WriteNumber("requests_total"u8, v.RequestsTotal);
        w.WriteNumber("requests2xx"u8, v.Requests2xx);
        w.WriteNumber("requests4xx"u8, v.Requests4xx);
        w.WriteNumber("requests5xx"u8, v.Requests5xx);
        w.WriteNumber("throttled_requests"u8, v.ThrottledRequests);
        w.WriteNumber("p50_ms"u8, v.P50Ms);
        w.WriteNumber("p95_ms"u8, v.P95Ms);
        w.WriteNumber("p99_ms"u8, v.P99Ms);
        w.WriteNumber("wal_reads"u8, v.WalReads);
        w.WriteNumber("wal_commits"u8, v.WalCommits);
        w.WriteNumber("wal_compactions"u8, v.WalCompactions);
        w.WriteNumber("gc_gen0"u8, v.GcGen0);
        w.WriteNumber("gc_gen1"u8, v.GcGen1);
        w.WriteNumber("gc_gen2"u8, v.GcGen2);
        w.WriteNumber("gc_allocated_bytes"u8, v.GcAllocatedBytes);
        if (v.TopError != null) w.WriteString("top_error"u8, v.TopError);
        if (v.Timestamp != null) w.WriteString("timestamp"u8, v.Timestamp);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(ErrorEvent v)
    {
        var buf = new ArrayBufferWriter<byte>(512);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (v.InstanceId != null) w.WriteString("instance_id"u8, v.InstanceId);
        if (v.Level != null) w.WriteString("level"u8, v.Level);
        if (v.Message != null) w.WriteString("message"u8, v.Message);
        if (v.ExceptionType != null) w.WriteString("exception_type"u8, v.ExceptionType);
        if (v.StackTrace != null) w.WriteString("stack_trace"u8, v.StackTrace);
        if (v.Path != null) w.WriteString("path"u8, v.Path);
        if (v.Method != null) w.WriteString("method"u8, v.Method);
        w.WriteNumber("status_code"u8, v.StatusCode);
        if (v.CorrelationId != null) w.WriteString("correlation_id"u8, v.CorrelationId);
        if (v.Timestamp != null) w.WriteString("timestamp"u8, v.Timestamp);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(BackupRecord v)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (v.InstanceId != null) w.WriteString("instance_id"u8, v.InstanceId);
        if (v.BackupId != null) w.WriteString("backup_id"u8, v.BackupId);
        if (v.Timestamp != null) w.WriteString("timestamp"u8, v.Timestamp);
        w.WriteNumber("record_count"u8, v.RecordCount);
        w.WriteNumber("segment_count"u8, v.SegmentCount);
        w.WriteNumber("size_bytes"u8, v.SizeBytes);
        w.WriteBoolean("validated"u8, v.Validated);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    internal static string Serialize(UpgradeVerificationRecord v)
    {
        var buf = new ArrayBufferWriter<byte>(256);
        using var w = new Utf8JsonWriter(buf);
        w.WriteStartObject();
        if (v.InstanceId != null) w.WriteString("instance_id"u8, v.InstanceId);
        if (v.TargetVersion != null) w.WriteString("target_version"u8, v.TargetVersion);
        w.WriteBoolean("success"u8, v.Success);
        if (v.Reason != null) w.WriteString("reason"u8, v.Reason);
        if (v.Timestamp != null) w.WriteString("timestamp"u8, v.Timestamp);
        w.WriteEndObject();
        w.Flush();
        return Encoding.UTF8.GetString(buf.WrittenSpan);
    }

    // ── Deserializers ────────────────────────────────────────────────────────

    internal static RuntimeResponse? DeserializeRuntimeResponse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        if (r.ValueKind != JsonValueKind.Object) return null;

        return new RuntimeResponse
        {
            DesiredVersion = r.TryGetProperty("desired_version"u8, out var dv) ? dv.GetString() : null,
            Sha256 = r.TryGetProperty("sha256"u8, out var sha) ? sha.GetString() : null,
            DownloadUrl = r.TryGetProperty("download_url"u8, out var du) ? du.GetString() : null,
            PollSeconds = r.TryGetProperty("poll_seconds"u8, out var ps) ? ps.GetInt32() : 0,
        };
    }

    internal static NodeIdentity? DeserializeNodeIdentity(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        if (r.ValueKind != JsonValueKind.Object) return null;

        return new NodeIdentity
        {
            NodeId = r.TryGetProperty("node_id"u8, out var nid) ? nid.GetString() ?? "" : "",
            ServicePrincipal = r.TryGetProperty("service_principal"u8, out var sp) ? sp.GetString() ?? "" : "",
            Secret = r.TryGetProperty("secret"u8, out var sec) ? sec.GetString() ?? "" : "",
            ClusterEndpoint = r.TryGetProperty("cluster_endpoint"u8, out var ce) ? ce.GetString() ?? "" : "",
            CertFingerprint = r.TryGetProperty("cert_fingerprint"u8, out var cf) ? cf.GetString() ?? "" : "",
            Ring = r.TryGetProperty("ring"u8, out var ring) && ring.ValueKind == JsonValueKind.String
                   && Enum.TryParse<DeploymentRing>(ring.GetString(), ignoreCase: true, out var ringVal)
                ? ringVal : DeploymentRing.Main,
        };
    }

    internal static UpgradeStatus? DeserializeUpgradeStatus(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var r = doc.RootElement;
        if (r.ValueKind != JsonValueKind.Object) return null;

        return new UpgradeStatus
        {
            InstanceId = r.TryGetProperty("instance_id"u8, out var iid) ? iid.GetString() : null,
            TargetVersion = r.TryGetProperty("target_version"u8, out var tv) ? tv.GetString() : null,
            CurrentVersion = r.TryGetProperty("current_version"u8, out var cv) ? cv.GetString() : null,
            Verified = r.TryGetProperty("verified"u8, out var ver) && ver.GetBoolean(),
            Ready = r.TryGetProperty("ready"u8, out var rdy) && rdy.GetBoolean(),
            ErrorRate5xx = r.TryGetProperty("error_rate5xx"u8, out var er) ? er.GetDouble() : 0,
            Timestamp = r.TryGetProperty("timestamp"u8, out var ts) ? ts.GetString() : null,
            Reason = r.TryGetProperty("reason"u8, out var rsn) ? rsn.GetString() : null,
        };
    }

    internal static List<GalleryListing>? DeserializeGalleryListings(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Array) return null;

        var list = new List<GalleryListing>(root.GetArrayLength());
        foreach (var r in root.EnumerateArray())
        {
            if (r.ValueKind != JsonValueKind.Object) continue;
            list.Add(new GalleryListing
            {
                Name = r.TryGetProperty("name"u8, out var n) ? n.GetString() : null,
                Slug = r.TryGetProperty("slug"u8, out var sl) ? sl.GetString() : null,
                Description = r.TryGetProperty("description"u8, out var d) ? d.GetString() : null,
                Icon = r.TryGetProperty("icon"u8, out var ic) ? ic.GetString() : null,
                Version = r.TryGetProperty("version"u8, out var v) ? v.GetString() : null,
                Author = r.TryGetProperty("author"u8, out var a) ? a.GetString() : null,
                EntityCount = r.TryGetProperty("entity_count"u8, out var ec) ? ec.GetInt32() : 0,
                FieldCount = r.TryGetProperty("field_count"u8, out var fc) ? fc.GetInt32() : 0,
                Category = r.TryGetProperty("category"u8, out var cat) ? cat.GetString() : null,
                PublishedAt = r.TryGetProperty("published_at"u8, out var pa) ? pa.GetString() : null,
                Downloads = r.TryGetProperty("downloads"u8, out var dl) ? dl.GetInt64() : 0,
            });
        }
        return list;
    }
}
