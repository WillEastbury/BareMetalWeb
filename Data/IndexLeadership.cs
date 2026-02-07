using System;
using System.IO;
using System.Text;
using System.Threading;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Data;

public sealed class IndexLeader : IDisposable
{
    private readonly FileStream _lockStream;
    private readonly Timer _heartbeatTimer;
    private readonly string _heartbeatPath;
    private readonly string _nodeId;
    private readonly IBufferedLogger? _logger;
    private bool _disposed;

    internal IndexLeader(FileStream lockStream, string heartbeatPath, string nodeId, TimeSpan heartbeatInterval, IBufferedLogger? logger)
    {
        _lockStream = lockStream ?? throw new ArgumentNullException(nameof(lockStream));
        _heartbeatPath = heartbeatPath ?? throw new ArgumentNullException(nameof(heartbeatPath));
        _nodeId = nodeId ?? throw new ArgumentNullException(nameof(nodeId));
        _logger = logger;
        _heartbeatTimer = new Timer(WriteHeartbeat, null, TimeSpan.Zero, heartbeatInterval);
    }

    public string NodeId => _nodeId;
    public string HeartbeatPath => _heartbeatPath;

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _heartbeatTimer.Dispose();
        try
        {
            if (File.Exists(_heartbeatPath))
                File.Delete(_heartbeatPath);
        }
        catch (Exception ex)
        {
            _logger?.LogError("Failed to delete index leader heartbeat file.", ex);
        }
        _lockStream.Dispose();
    }

    private void WriteHeartbeat(object? state)
    {
        try
        {
            var content = $"{_nodeId}|{DateTime.UtcNow.Ticks}";
            var bytes = Encoding.UTF8.GetBytes(content);
            using var stream = new FileStream(_heartbeatPath, FileMode.Create, FileAccess.Write, FileShare.Read);
            stream.Write(bytes, 0, bytes.Length);
        }
        catch (Exception ex)
        {
            _logger?.LogError("Failed to write index leader heartbeat.", ex);
        }
    }
}

public static class IndexLeadership
{
    private const string LeaderLockFileName = "index.leader.lock";
    private const string LeaderHeartbeatFileName = "index.leader.heartbeat";
    private const long TicksPerSecond = TimeSpan.TicksPerSecond;

    public static IndexLeader? TryAcquireLeader(IDataProvider provider, string storageKey, string nodeId, TimeSpan heartbeatInterval, IBufferedLogger? logger = null)
    {
        if (provider == null)
            throw new ArgumentNullException(nameof(provider));
        if (string.IsNullOrWhiteSpace(storageKey))
            throw new ArgumentException("Storage key cannot be empty.", nameof(storageKey));
        if (string.IsNullOrWhiteSpace(nodeId))
            throw new ArgumentException("Node id cannot be empty.", nameof(nodeId));
        if (heartbeatInterval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(heartbeatInterval), "Heartbeat interval must be positive.");

        var folder = Path.Combine(provider.IndexRootPath, provider.IndexFolderName);
        Directory.CreateDirectory(folder);

        var lockPath = Path.Combine(folder, BuildLeaderFileName(LeaderLockFileName, storageKey));
        var heartbeatPath = Path.Combine(folder, BuildLeaderFileName(LeaderHeartbeatFileName, storageKey));

        try
        {
            var lockStream = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            var leader = new IndexLeader(lockStream, heartbeatPath, nodeId, heartbeatInterval, logger);
            logger?.LogInfo($"Index leader elected: {nodeId} (storage={storageKey}).");
            return leader;
        }
        catch (IOException)
        {
            logger?.LogInfo("Index leader already held by another node.");
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            logger?.LogInfo("Index leader lock denied by filesystem permissions.");
            return null;
        }
    }

    public static IndexHeartbeatMonitor StartHeartbeatMonitor(IDataProvider provider, TimeSpan interval, TimeSpan staleThreshold, IBufferedLogger? logger = null)
    {
        if (provider == null)
            throw new ArgumentNullException(nameof(provider));
        if (interval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(interval), "Interval must be positive.");
        if (staleThreshold <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(staleThreshold), "Stale threshold must be positive.");

        var folder = Path.Combine(provider.IndexRootPath, provider.IndexFolderName);
        Directory.CreateDirectory(folder);
        var heartbeatPath = Path.Combine(folder, LeaderHeartbeatFileName);
        return new IndexHeartbeatMonitor(heartbeatPath, interval, staleThreshold, logger);
    }

    public static IndexHeartbeatMonitor StartHeartbeatMonitor(IDataProvider provider, string storageKey, TimeSpan interval, TimeSpan staleThreshold, IBufferedLogger? logger = null)
    {
        if (provider == null)
            throw new ArgumentNullException(nameof(provider));
        if (string.IsNullOrWhiteSpace(storageKey))
            throw new ArgumentException("Storage key cannot be empty.", nameof(storageKey));
        if (interval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(interval), "Interval must be positive.");
        if (staleThreshold <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(staleThreshold), "Stale threshold must be positive.");

        var folder = Path.Combine(provider.IndexRootPath, provider.IndexFolderName);
        Directory.CreateDirectory(folder);
        var heartbeatPath = Path.Combine(folder, BuildLeaderFileName(LeaderHeartbeatFileName, storageKey));
        return new IndexHeartbeatMonitor(heartbeatPath, interval, staleThreshold, logger);
    }

    public static IndexLeaderElection StartLeaderElectionLoop(
        IDataProvider provider,
        string storageKey,
        string nodeId,
        TimeSpan heartbeatInterval,
        TimeSpan retryInterval,
        Func<bool> isLeader,
        Action<IndexLeader> onLeaderAcquired,
        IBufferedLogger? logger = null)
    {
        if (provider == null)
            throw new ArgumentNullException(nameof(provider));
        if (string.IsNullOrWhiteSpace(storageKey))
            throw new ArgumentException("Storage key cannot be empty.", nameof(storageKey));
        if (string.IsNullOrWhiteSpace(nodeId))
            throw new ArgumentException("Node id cannot be empty.", nameof(nodeId));
        if (heartbeatInterval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(heartbeatInterval), "Heartbeat interval must be positive.");
        if (retryInterval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(retryInterval), "Retry interval must be positive.");
        if (isLeader == null)
            throw new ArgumentNullException(nameof(isLeader));
        if (onLeaderAcquired == null)
            throw new ArgumentNullException(nameof(onLeaderAcquired));

        return new IndexLeaderElection(provider, storageKey, nodeId, heartbeatInterval, retryInterval, isLeader, onLeaderAcquired, logger);
    }

    private static string BuildLeaderFileName(string baseName, string storageKey)
    {
        var sanitized = storageKey.Replace(Path.DirectorySeparatorChar, '_').Replace(Path.AltDirectorySeparatorChar, '_');
        return $"{baseName}.{sanitized}";
    }
}

public sealed class IndexHeartbeatMonitor : IDisposable
{
    private readonly string _heartbeatPath;
    private readonly TimeSpan _staleThreshold;
    private readonly IBufferedLogger? _logger;
    private readonly Timer _timer;
    private bool _disposed;
    private HealthState _lastState = HealthState.Unknown;

    internal IndexHeartbeatMonitor(string heartbeatPath, TimeSpan interval, TimeSpan staleThreshold, IBufferedLogger? logger)
    {
        _heartbeatPath = heartbeatPath ?? throw new ArgumentNullException(nameof(heartbeatPath));
        _staleThreshold = staleThreshold;
        _logger = logger;
        _timer = new Timer(CheckHeartbeat, null, TimeSpan.Zero, interval);
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _timer.Dispose();
    }

    private void CheckHeartbeat(object? state)
    {
        try
        {
            if (!File.Exists(_heartbeatPath))
            {
                ReportState(HealthState.Missing, "Index leader heartbeat missing.");
                return;
            }

            var content = File.ReadAllText(_heartbeatPath, Encoding.UTF8).Trim();
            if (string.IsNullOrWhiteSpace(content))
            {
                ReportState(HealthState.Invalid, "Index leader heartbeat empty.");
                return;
            }

            var parts = content.Split('|');
            if (parts.Length != 2 || !long.TryParse(parts[1], out var ticks))
            {
                ReportState(HealthState.Invalid, "Index leader heartbeat invalid.");
                return;
            }

            var ageTicks = DateTime.UtcNow.Ticks - ticks;
            if (ageTicks < 0)
                ageTicks = 0;

            if (ageTicks > _staleThreshold.Ticks)
            {
                var ageSeconds = ageTicks / TimeSpan.TicksPerSecond;
                ReportState(HealthState.Stale, $"Index leader heartbeat stale ({ageSeconds}s). Node={parts[0]}.");
                return;
            }

            ReportState(HealthState.Healthy, $"Index leader heartbeat healthy. Node={parts[0]}.");
        }
        catch (Exception ex)
        {
            _logger?.LogError("Failed to read index leader heartbeat.", ex);
        }
    }

    private void ReportState(HealthState state, string message)
    {
        if (_lastState == state)
            return;

        _lastState = state;
        if (state == HealthState.Healthy)
            _logger?.LogInfo(message);
        else
            _logger?.LogError(message, new InvalidOperationException(message));
    }

    private enum HealthState
    {
        Unknown,
        Healthy,
        Stale,
        Missing,
        Invalid
    }
}

public sealed class IndexLeaderElection : IDisposable
{
    private readonly IDataProvider _provider;
    private readonly string _storageKey;
    private readonly string _nodeId;
    private readonly TimeSpan _heartbeatInterval;
    private readonly Func<bool> _isLeader;
    private readonly Action<IndexLeader> _onLeaderAcquired;
    private readonly IBufferedLogger? _logger;
    private readonly Timer _timer;
    private bool _disposed;

    internal IndexLeaderElection(
        IDataProvider provider,
        string storageKey,
        string nodeId,
        TimeSpan heartbeatInterval,
        TimeSpan retryInterval,
        Func<bool> isLeader,
        Action<IndexLeader> onLeaderAcquired,
        IBufferedLogger? logger)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _storageKey = storageKey ?? throw new ArgumentNullException(nameof(storageKey));
        _nodeId = nodeId ?? throw new ArgumentNullException(nameof(nodeId));
        _heartbeatInterval = heartbeatInterval;
        _isLeader = isLeader ?? throw new ArgumentNullException(nameof(isLeader));
        _onLeaderAcquired = onLeaderAcquired ?? throw new ArgumentNullException(nameof(onLeaderAcquired));
        _logger = logger;
        _timer = new Timer(TryPromote, null, retryInterval, retryInterval);
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _timer.Dispose();
    }

    private void TryPromote(object? state)
    {
        if (_isLeader())
            return;

        try
        {
            var leader = IndexLeadership.TryAcquireLeader(_provider, _storageKey, _nodeId, _heartbeatInterval, _logger);
            if (leader == null)
                return;

            _onLeaderAcquired(leader);
        }
        catch (Exception ex)
        {
            _logger?.LogError("Index leader election attempt failed.", ex);
        }
    }
}
