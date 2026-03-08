using System.Text;

using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Formats internal metrics as Prometheus text exposition format (v0.0.4).
/// Zero external dependencies — hand-written formatter.
/// </summary>
internal static class PrometheusFormatter
{
    private const string ContentType = "text/plain; version=0.0.4; charset=utf-8";

    /// <summary>
    /// Writes a complete Prometheus scrape response to the HTTP response body.
    /// </summary>
    public static async ValueTask WriteMetricsAsync(BmwContext context)
    {
        var snap = context.App.Metrics.GetSnapshot();
        var engine = EngineMetrics.GetSnapshot();

        context.Response.StatusCode = 200;
        context.Response.ContentType = ContentType;

        // Pre-size to avoid re-allocations; typical output is 3-4 KB
        var sb = new StringBuilder(4096);

        // ── HTTP request counters ───────────────────────────────────────
        WriteHelp(sb, "bmw_http_requests_total", "Total HTTP requests by status class.");
        WriteType(sb, "bmw_http_requests_total", "counter");
        WriteCounter(sb, "bmw_http_requests_total", snap.Requests2xx, ("status_class", "2xx"));
        WriteCounter(sb, "bmw_http_requests_total", snap.Requests4xx, ("status_class", "4xx"));
        WriteCounter(sb, "bmw_http_requests_total", snap.Requests5xx, ("status_class", "5xx"));
        WriteCounter(sb, "bmw_http_requests_total", snap.RequestsOther, ("status_class", "other"));

        WriteHelp(sb, "bmw_http_requests_throttled_total", "Total throttled HTTP requests.");
        WriteType(sb, "bmw_http_requests_throttled_total", "counter");
        WriteCounter(sb, "bmw_http_requests_throttled_total", snap.ThrottledRequests);

        WriteHelp(sb, "bmw_http_requests_errors_total", "Total HTTP error requests (4xx+5xx).");
        WriteType(sb, "bmw_http_requests_errors_total", "counter");
        WriteCounter(sb, "bmw_http_requests_errors_total", snap.ErrorRequests);

        WriteHelp(sb, "bmw_http_requests_in_flight", "Current number of HTTP requests being processed.");
        WriteType(sb, "bmw_http_requests_in_flight", "gauge");
        WriteGauge(sb, "bmw_http_requests_in_flight", snap.RequestsInFlight);

        // ── Request duration summary ────────────────────────────────────
        WriteHelp(sb, "bmw_http_request_duration_seconds", "HTTP request duration quantiles (recent window).");
        WriteType(sb, "bmw_http_request_duration_seconds", "summary");
        WriteSummaryQuantile(sb, "bmw_http_request_duration_seconds", "0.5", snap.RecentAverageResponseTime.TotalSeconds);
        WriteSummaryQuantile(sb, "bmw_http_request_duration_seconds", "0.95", snap.RecentP95ResponseTime.TotalSeconds);
        WriteSummaryQuantile(sb, "bmw_http_request_duration_seconds", "0.99", snap.RecentP99ResponseTime.TotalSeconds);
        WriteGauge(sb, "bmw_http_request_duration_seconds_sum", snap.AverageResponseTime.TotalSeconds * snap.TotalRequests);
        WriteGauge(sb, "bmw_http_request_duration_seconds_count", snap.TotalRequests);

        // ── Process / runtime gauges ────────────────────────────────────
        WriteHelp(sb, "bmw_uptime_seconds", "Server uptime in seconds.");
        WriteType(sb, "bmw_uptime_seconds", "gauge");
        WriteGauge(sb, "bmw_uptime_seconds", snap.ProcessUptime.TotalSeconds);

        WriteHelp(sb, "bmw_process_working_set_bytes", "Process working set size in bytes.");
        WriteType(sb, "bmw_process_working_set_bytes", "gauge");
        WriteGauge(sb, "bmw_process_working_set_bytes", snap.WorkingSet64);

        WriteHelp(sb, "bmw_process_virtual_memory_bytes", "Process virtual memory size in bytes.");
        WriteType(sb, "bmw_process_virtual_memory_bytes", "gauge");
        WriteGauge(sb, "bmw_process_virtual_memory_bytes", snap.VirtualMemorySize64);

        // ── GC counters ─────────────────────────────────────────────────
        WriteHelp(sb, "bmw_gc_collections_total", "Total GC collections by generation.");
        WriteType(sb, "bmw_gc_collections_total", "counter");
        WriteCounter(sb, "bmw_gc_collections_total", snap.GcGen0Collections, ("generation", "0"));
        WriteCounter(sb, "bmw_gc_collections_total", snap.GcGen1Collections, ("generation", "1"));
        WriteCounter(sb, "bmw_gc_collections_total", snap.GcGen2Collections, ("generation", "2"));

        WriteHelp(sb, "bmw_gc_allocated_bytes_total", "Total bytes allocated since process start.");
        WriteType(sb, "bmw_gc_allocated_bytes_total", "counter");
        WriteCounter(sb, "bmw_gc_allocated_bytes_total", snap.GcTotalAllocatedBytes);

        // ── Subsystem operation counters ─────────────────────────────────
        WriteHelp(sb, "bmw_route_dispatch_total", "Total route dispatch operations.");
        WriteType(sb, "bmw_route_dispatch_total", "counter");
        WriteCounter(sb, "bmw_route_dispatch_total", snap.RouteDispatchCount);

        WriteHelp(sb, "bmw_route_dispatch_avg_seconds", "Average route dispatch duration in seconds.");
        WriteType(sb, "bmw_route_dispatch_avg_seconds", "gauge");
        WriteGauge(sb, "bmw_route_dispatch_avg_seconds", snap.RouteDispatchAverage.TotalSeconds);

        WriteHelp(sb, "bmw_wal_reads_total", "Total WAL read operations.");
        WriteType(sb, "bmw_wal_reads_total", "counter");
        WriteCounter(sb, "bmw_wal_reads_total", snap.WalReadCount);

        WriteHelp(sb, "bmw_wal_read_avg_seconds", "Average WAL read duration in seconds.");
        WriteType(sb, "bmw_wal_read_avg_seconds", "gauge");
        WriteGauge(sb, "bmw_wal_read_avg_seconds", snap.WalReadAverage.TotalSeconds);

        WriteHelp(sb, "bmw_ui_renders_total", "Total UI render operations.");
        WriteType(sb, "bmw_ui_renders_total", "counter");
        WriteCounter(sb, "bmw_ui_renders_total", snap.UiRenderCount);

        WriteHelp(sb, "bmw_serializations_total", "Total serialization operations.");
        WriteType(sb, "bmw_serializations_total", "counter");
        WriteCounter(sb, "bmw_serializations_total", snap.SerializationCount);

        // ── Engine / WAL metrics ────────────────────────────────────────
        WriteHelp(sb, "bmw_wal_appends_total", "Total WAL append operations.");
        WriteType(sb, "bmw_wal_appends_total", "counter");
        WriteCounter(sb, "bmw_wal_appends_total", engine.WalAppendCount);

        WriteHelp(sb, "bmw_wal_append_bytes_total", "Total bytes written via WAL appends.");
        WriteType(sb, "bmw_wal_append_bytes_total", "counter");
        WriteCounter(sb, "bmw_wal_append_bytes_total", engine.WalAppendBytesTotal);

        WriteHelp(sb, "bmw_wal_append_max_seconds", "Maximum single WAL append duration in seconds.");
        WriteType(sb, "bmw_wal_append_max_seconds", "gauge");
        WriteGauge(sb, "bmw_wal_append_max_seconds", engine.WalAppendMaxUs / 1_000_000.0);

        WriteHelp(sb, "bmw_wal_append_avg_seconds", "Average WAL append duration in seconds.");
        WriteType(sb, "bmw_wal_append_avg_seconds", "gauge");
        WriteGauge(sb, "bmw_wal_append_avg_seconds", engine.WalAppendAvgUs / 1_000_000.0);

        // ── Lock metrics ────────────────────────────────────────────────
        WriteHelp(sb, "bmw_lock_acquisitions_total", "Total lock acquisitions.");
        WriteType(sb, "bmw_lock_acquisitions_total", "counter");
        WriteCounter(sb, "bmw_lock_acquisitions_total", engine.LockAcquireCount);

        WriteHelp(sb, "bmw_lock_contentions_total", "Total lock contentions.");
        WriteType(sb, "bmw_lock_contentions_total", "counter");
        WriteCounter(sb, "bmw_lock_contentions_total", engine.LockContentions);

        WriteHelp(sb, "bmw_lock_contention_ratio", "Lock contention rate (contentions / acquisitions).");
        WriteType(sb, "bmw_lock_contention_ratio", "gauge");
        WriteGauge(sb, "bmw_lock_contention_ratio", engine.LockContentionRate);

        // ── Commit metrics ──────────────────────────────────────────────
        WriteHelp(sb, "bmw_commits_total", "Total commit operations by result.");
        WriteType(sb, "bmw_commits_total", "counter");
        WriteCounter(sb, "bmw_commits_total", engine.CommitSuccessCount, ("result", "success"));
        WriteCounter(sb, "bmw_commits_total", engine.CommitFailCount, ("result", "fail"));

        WriteHelp(sb, "bmw_commit_retries_total", "Total commit retry attempts.");
        WriteType(sb, "bmw_commit_retries_total", "counter");
        WriteCounter(sb, "bmw_commit_retries_total", engine.CommitRetryCount);

        WriteHelp(sb, "bmw_commit_avg_seconds", "Average commit duration in seconds.");
        WriteType(sb, "bmw_commit_avg_seconds", "gauge");
        WriteGauge(sb, "bmw_commit_avg_seconds", engine.CommitAvgUs / 1_000_000.0);

        WriteHelp(sb, "bmw_commit_max_seconds", "Maximum single commit duration in seconds.");
        WriteType(sb, "bmw_commit_max_seconds", "gauge");
        WriteGauge(sb, "bmw_commit_max_seconds", engine.CommitMaxUs / 1_000_000.0);

        // ── Delta size metrics ──────────────────────────────────────────
        WriteHelp(sb, "bmw_delta_size_bytes_total", "Total delta bytes written.");
        WriteType(sb, "bmw_delta_size_bytes_total", "counter");
        WriteCounter(sb, "bmw_delta_size_bytes_total", engine.DeltaSizeTotal);

        WriteHelp(sb, "bmw_delta_size_bytes_avg", "Average delta size in bytes.");
        WriteType(sb, "bmw_delta_size_bytes_avg", "gauge");
        WriteGauge(sb, "bmw_delta_size_bytes_avg", engine.DeltaSizeAvg);

        // ── Compaction metrics ──────────────────────────────────────────
        WriteHelp(sb, "bmw_compactions_total", "Total compaction runs.");
        WriteType(sb, "bmw_compactions_total", "counter");
        WriteCounter(sb, "bmw_compactions_total", engine.CompactionCount);

        WriteHelp(sb, "bmw_compaction_bytes_reclaimed_total", "Total bytes reclaimed by compaction.");
        WriteType(sb, "bmw_compaction_bytes_reclaimed_total", "counter");
        WriteCounter(sb, "bmw_compaction_bytes_reclaimed_total", engine.CompactionBytesReclaimed);

        // ── Replay metrics ──────────────────────────────────────────────
        WriteHelp(sb, "bmw_replay_runs_total", "Total WAL replay runs.");
        WriteType(sb, "bmw_replay_runs_total", "counter");
        WriteCounter(sb, "bmw_replay_runs_total", engine.ReplayCount);

        WriteHelp(sb, "bmw_replay_ops_total", "Total operations replayed from WAL.");
        WriteType(sb, "bmw_replay_ops_total", "counter");
        WriteCounter(sb, "bmw_replay_ops_total", engine.ReplayOpsTotal);

        await context.Response.WriteAsync(sb.ToString());
    }

    // ── Formatting helpers ──────────────────────────────────────────────

    private static void WriteHelp(StringBuilder sb, string name, string help)
    {
        sb.Append("# HELP ").Append(name).Append(' ').AppendLine(help);
    }

    private static void WriteType(StringBuilder sb, string name, string type)
    {
        sb.Append("# TYPE ").Append(name).Append(' ').AppendLine(type);
    }

    private static void WriteCounter(StringBuilder sb, string name, long value)
    {
        sb.Append(name).Append(' ').Append(value).Append('\n');
    }

    private static void WriteCounter(StringBuilder sb, string name, double value)
    {
        sb.Append(name).Append(' ').AppendFormat("{0:G}", value).Append('\n');
    }

    private static void WriteCounter(StringBuilder sb, string name, long value, (string key, string val) label)
    {
        sb.Append(name).Append('{').Append(label.key).Append("=\"").Append(label.val).Append("\"} ").Append(value).Append('\n');
    }

    private static void WriteGauge(StringBuilder sb, string name, double value)
    {
        sb.Append(name).Append(' ').AppendFormat("{0:G}", value).Append('\n');
    }

    private static void WriteGauge(StringBuilder sb, string name, long value)
    {
        sb.Append(name).Append(' ').Append(value).Append('\n');
    }

    private static void WriteSummaryQuantile(StringBuilder sb, string name, string quantile, double value)
    {
        sb.Append(name).Append("{quantile=\"").Append(quantile).Append("\"} ").AppendFormat("{0:G}", value).Append('\n');
    }
}
