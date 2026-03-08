using System.IO;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Automated backup service that periodically snapshots the WAL head map and
/// copies WAL segment files to a timestamped backup directory.
///
/// Each backup is a self-contained directory containing:
/// <list type="bullet">
///   <item><c>wal_snapshot.bin</c> — point-in-time head map snapshot</item>
///   <item><c>wal_seg_*.log</c> — all WAL segment files at time of backup</item>
///   <item><c>wal_seqids.bin</c> — table key allocator state</item>
/// </list>
///
/// To restore, copy the backup directory contents into the WAL data root
/// and restart the server. <see cref="WalStore.Recover"/> will load the
/// snapshot and replay any WAL tail automatically.
/// </summary>
public sealed class WalBackupService : IDisposable
{
    private readonly WalStore _walStore;
    private readonly string _walDirectory;
    private readonly string _backupRoot;
    private readonly TimeSpan _interval;
    private readonly int _retentionDays;
    private readonly IBufferedLogger? _logger;
    private CancellationTokenSource? _cts;
    private Task? _runTask;

    /// <summary>
    /// Creates a new backup service.
    /// </summary>
    /// <param name="walStore">The WAL store to snapshot.</param>
    /// <param name="walDirectory">Path to the WAL segment directory (e.g. Data/wal).</param>
    /// <param name="backupRoot">Root directory for timestamped backup folders.</param>
    /// <param name="intervalMinutes">Minutes between automatic backups (default: 360 = 6 hours).</param>
    /// <param name="retentionDays">Days to retain old backups before cleanup (default: 30).</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    public WalBackupService(
        WalStore walStore,
        string walDirectory,
        string backupRoot,
        int intervalMinutes = 360,
        int retentionDays = 30,
        IBufferedLogger? logger = null)
    {
        _walStore = walStore ?? throw new ArgumentNullException(nameof(walStore));
        _walDirectory = walDirectory ?? throw new ArgumentNullException(nameof(walDirectory));
        _backupRoot = backupRoot ?? throw new ArgumentNullException(nameof(backupRoot));
        _interval = TimeSpan.FromMinutes(Math.Max(1, intervalMinutes));
        _retentionDays = Math.Max(1, retentionDays);
        _logger = logger;

        Directory.CreateDirectory(_backupRoot);
    }

    /// <summary>
    /// Starts the periodic backup loop in the background.
    /// </summary>
    public void Start()
    {
        if (_cts != null) return;
        _cts = new CancellationTokenSource();
        _runTask = RunAsync(_cts.Token);
    }

    /// <summary>
    /// Stops the periodic backup loop.
    /// </summary>
    public async Task StopAsync()
    {
        if (_cts == null) return;
        _cts.Cancel();
        if (_runTask != null)
        {
            try { await _runTask.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }
        _cts.Dispose();
        _cts = null;
    }

    /// <summary>
    /// Creates a backup immediately. Returns the backup directory path.
    /// Thread-safe — can be called while the periodic loop is running.
    /// </summary>
    public string CreateBackup()
    {
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        var backupDir = Path.Combine(_backupRoot, $"backup_{timestamp}");
        Directory.CreateDirectory(backupDir);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        int filesCopied = 0;

        try
        {
            // 1. Write a fresh snapshot into the backup directory
            if (_walStore.VisibleCommitPtr != WalConstants.NullPtr)
            {
                WalSnapshot.Write(backupDir, _walStore.VisibleCommitPtr, _walStore.HeadMap);
                filesCopied++;
            }

            // 2. Copy all WAL segment files
            foreach (var segFile in Directory.EnumerateFiles(_walDirectory, "wal_seg_*.log"))
            {
                var destPath = Path.Combine(backupDir, Path.GetFileName(segFile));
                File.Copy(segFile, destPath, overwrite: true);
                filesCopied++;
            }

            // 3. Copy key allocator state
            var seqIdsPath = Path.Combine(_walDirectory, "wal_seqids.bin");
            if (File.Exists(seqIdsPath))
            {
                File.Copy(seqIdsPath, Path.Combine(backupDir, "wal_seqids.bin"), overwrite: true);
                filesCopied++;
            }

            // 4. Write a manifest for verification
            var manifestPath = Path.Combine(backupDir, "backup.manifest");
            var manifest = $"timestamp={DateTime.UtcNow:O}\n" +
                           $"commit_ptr=0x{_walStore.VisibleCommitPtr:X16}\n" +
                           $"files={filesCopied}\n" +
                           $"wal_directory={_walDirectory}\n";
            File.WriteAllText(manifestPath, manifest);

            sw.Stop();
            _logger?.LogInfo($"[Backup] Created backup: {backupDir} ({filesCopied} files, {sw.ElapsedMilliseconds}ms)");
            Console.WriteLine($"[BMW Backup] ✓ Backup created: {backupDir} ({filesCopied} files, {sw.ElapsedMilliseconds}ms)");

            return backupDir;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
        {
            _logger?.LogError($"[Backup] Failed to create backup at {backupDir}: {ex.Message}", ex);
            Console.WriteLine($"[BMW Backup] ✗ Backup failed: {ex.Message}");

            // Clean up partial backup
            try { if (Directory.Exists(backupDir)) Directory.Delete(backupDir, recursive: true); }
            catch { /* best-effort */ }

            throw;
        }
    }

    /// <summary>
    /// Lists all available backups, newest first.
    /// </summary>
    public IReadOnlyList<BackupInfo> ListBackups()
    {
        var backups = new List<BackupInfo>();

        if (!Directory.Exists(_backupRoot)) return backups;

        foreach (var dir in Directory.EnumerateDirectories(_backupRoot, "backup_*"))
        {
            var name = Path.GetFileName(dir);
            var manifestPath = Path.Combine(dir, "backup.manifest");
            DateTime? timestamp = null;
            string? commitPtr = null;
            int? fileCount = null;

            if (File.Exists(manifestPath))
            {
                foreach (var line in File.ReadLines(manifestPath))
                {
                    var eq = line.IndexOf('=');
                    if (eq < 0) continue;
                    var key = line[..eq];
                    var val = line[(eq + 1)..];
                    if (key == "timestamp" && DateTime.TryParse(val, out var ts)) timestamp = ts;
                    else if (key == "commit_ptr") commitPtr = val;
                    else if (key == "files" && int.TryParse(val, out var fc)) fileCount = fc;
                }
            }

            var dirInfo = new DirectoryInfo(dir);
            long totalBytes = 0;
            foreach (var fi in dirInfo.EnumerateFiles()) totalBytes += fi.Length;

            backups.Add(new BackupInfo
            {
                Path = dir,
                Name = name,
                Timestamp = timestamp ?? dirInfo.CreationTimeUtc,
                CommitPtr = commitPtr ?? "unknown",
                FileCount = fileCount ?? dirInfo.GetFiles().Length,
                TotalBytes = totalBytes
            });
        }

        backups.Sort((a, b) => b.Timestamp.CompareTo(a.Timestamp));
        return backups;
    }

    /// <summary>
    /// Removes backups older than the retention period.
    /// </summary>
    public int PurgeExpiredBackups()
    {
        var cutoff = DateTime.UtcNow.AddDays(-_retentionDays);
        int purged = 0;

        foreach (var backup in ListBackups())
        {
            if (backup.Timestamp < cutoff)
            {
                try
                {
                    Directory.Delete(backup.Path, recursive: true);
                    _logger?.LogInfo($"[Backup] Purged expired backup: {backup.Name} (created {backup.Timestamp:O})");
                    purged++;
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    _logger?.LogError($"[Backup] Failed to purge {backup.Name}: {ex.Message}", ex);
                }
            }
        }

        if (purged > 0)
            Console.WriteLine($"[BMW Backup] Purged {purged} expired backup(s) (retention: {_retentionDays} days)");

        return purged;
    }

    /// <summary>
    /// Validates a backup directory by attempting to load its snapshot.
    /// </summary>
    public static bool ValidateBackup(string backupDir)
    {
        if (!Directory.Exists(backupDir)) return false;

        var snapshotPath = Path.Combine(backupDir, WalSnapshot.FileName);
        if (!File.Exists(snapshotPath)) return false;

        return WalSnapshot.TryLoad(backupDir, out _, out _, out _);
    }

    // ── Private ──────────────────────────────────────────────────────────────

    private async Task RunAsync(CancellationToken ct)
    {
        _logger?.LogInfo($"[Backup] Service started (interval: {_interval.TotalMinutes}min, retention: {_retentionDays}d, dir: {_backupRoot})");
        Console.WriteLine($"[BMW Backup] Service started (interval: {_interval.TotalMinutes}min, retention: {_retentionDays}d)");

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_interval, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }

            try
            {
                CreateBackup();
                PurgeExpiredBackups();
            }
            catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
            {
                _logger?.LogError($"[Backup] Periodic backup failed: {ex.Message}", ex);
            }
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
    }
}

/// <summary>
/// Metadata about a backup directory.
/// </summary>
public sealed class BackupInfo
{
    public required string Path { get; init; }
    public required string Name { get; init; }
    public required DateTime Timestamp { get; init; }
    public required string CommitPtr { get; init; }
    public required int FileCount { get; init; }
    public required long TotalBytes { get; init; }

    /// <summary>Human-readable size.</summary>
    public string SizeDisplay => TotalBytes switch
    {
        < 1024 => $"{TotalBytes} B",
        < 1024 * 1024 => $"{TotalBytes / 1024.0:F1} KB",
        < 1024 * 1024 * 1024 => $"{TotalBytes / (1024.0 * 1024):F1} MB",
        _ => $"{TotalBytes / (1024.0 * 1024 * 1024):F2} GB"
    };
}
