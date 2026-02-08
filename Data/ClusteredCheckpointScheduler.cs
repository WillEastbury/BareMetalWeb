using System;
using System.IO;
using System.Threading;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Data;

public sealed class ClusteredCheckpointScheduler : IDisposable
{
    private readonly LocalFolderBinaryDataProvider _provider;
    private readonly IBufferedLogger? _logger;
    private readonly Timer _timer;
    private int _running;
    private bool _disposed;

    public ClusteredCheckpointScheduler(LocalFolderBinaryDataProvider provider, TimeSpan interval, IBufferedLogger? logger = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        if (interval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(interval), "Interval must be positive.");

        _logger = logger;
        _timer = new Timer(Checkpoint, null, interval, interval);
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _timer.Dispose();
    }

    private void Checkpoint(object? state)
    {
        if (_disposed)
            return;
        if (Interlocked.Exchange(ref _running, 1) == 1)
            return;

        try
        {
            var entities = DataScaffold.Entities;
            foreach (var entity in entities)
            {
                if (!IsEntityLockOwned(entity.Type.Name))
                    continue;

                _provider.CompactClusteredEntity(entity.Type);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError("Clustered checkpoint failed.", ex);
        }
        finally
        {
            Interlocked.Exchange(ref _running, 0);
        }
    }

    private static bool IsEntityLockOwned(string entityName)
    {
        var provider = DataStoreProvider.PrimaryProvider;
        if (provider == null)
            return false;

        return DataStoreProvider.IsEntityLeader(provider.Name, entityName);
    }
}
