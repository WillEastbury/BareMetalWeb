# Data Recovery Runbook

## Overview

BareMetalWeb uses a Write-Ahead Log (WAL) for all data persistence. The automated backup service (`WalBackupService`) creates periodic snapshots of the WAL state that can be used for point-in-time recovery.

## Architecture

```
Data/
├── wal/
│   ├── wal_seg_0000000000.log   # WAL segment files (append-only)
│   ├── wal_seg_0000000001.log
│   ├── wal_snapshot.bin          # Latest head map checkpoint
│   └── wal_seqids.bin            # Table key allocator state
└── backups/
    ├── backup_20260308_060000/   # Timestamped backup directories
    │   ├── wal_snapshot.bin
    │   ├── wal_seg_*.log
    │   ├── wal_seqids.bin
    │   └── backup.manifest
    └── backup_20260308_120000/
```

### How Recovery Works

1. `WalStore.Recover()` loads `wal_snapshot.bin` (point-in-time head map)
2. Discovers all `wal_seg_*.log` segment files
3. Replays WAL tail from segments to rebuild any changes after the snapshot
4. Result: full data state restored

## Configuration

Add to `Metal.config`:

```
Backup.Enabled|true
Backup.IntervalMinutes|360
Backup.Directory|Data/backups
Backup.RetentionDays|30
```

| Key | Default | Description |
|-----|---------|-------------|
| `Backup.Enabled` | `false` | Enable automated periodic backups |
| `Backup.IntervalMinutes` | `360` | Minutes between automatic backups (default: 6 hours) |
| `Backup.Directory` | `Data/backups` | Root directory for timestamped backup folders |
| `Backup.RetentionDays` | `30` | Days to retain old backups before automatic cleanup |

## Procedures

### List Available Backups

**API:**
```bash
curl -H "Authorization: Bearer <token>" https://your-server/api/admin/backups
```

Returns JSON array of available backups with timestamp, commit pointer, file count, and size.

### Create an On-Demand Backup

**API:**
```bash
curl -X POST -H "Authorization: Bearer <token>" https://your-server/api/admin/backup
```

Returns the backup directory path on success.

### Restore from Backup

> **WARNING:** Restoring replaces all current data. Take a fresh backup first if you need to preserve current state.

1. **Stop the server**

2. **Back up current state** (optional safety net):
   ```bash
   cp -r Data/wal Data/wal_pre_restore
   ```

3. **Clear the WAL directory:**
   ```bash
   rm Data/wal/wal_seg_*.log
   rm Data/wal/wal_snapshot.bin
   rm Data/wal/wal_seqids.bin
   ```

4. **Copy backup files into the WAL directory:**
   ```bash
   cp backups/backup_YYYYMMDD_HHMMSS/* Data/wal/
   ```

5. **Restart the server.** `WalStore.Recover()` will:
   - Load the snapshot from `wal_snapshot.bin`
   - Replay any WAL segments included in the backup
   - Rebuild the head map and segment index

6. **Verify** by checking the health endpoint and spot-checking data.

### Validate a Backup

Each backup includes a `backup.manifest` file with metadata. The snapshot file includes CRC32C integrity checks that are validated automatically during restore.

To verify a backup is valid without restoring:
- Check that `wal_snapshot.bin` exists in the backup directory
- The server validates CRC32C checksums during `WalSnapshot.TryLoad()`

### Disaster Recovery Scenarios

#### Scenario: Corrupt WAL Segment

1. If the server fails to start due to a corrupt segment, check logs for the failing segment file
2. Remove only the corrupt segment file
3. Restart — the server will recover from the snapshot + remaining segments
4. Some recent data from the corrupt segment may be lost

#### Scenario: Complete Data Loss

1. Stop the server
2. Restore from the most recent backup (see procedure above)
3. Data written after the backup timestamp will be lost

#### Scenario: Accidental Data Deletion (Application Level)

1. The WAL is append-only — deleted records still exist as tombstone entries in older segments
2. Restore from a pre-deletion backup to recover the data
3. Re-apply any legitimate changes made after the backup

## Monitoring

- Backup creation is logged with `[Backup]` prefix in the application log
- Console output uses `[BMW Backup]` prefix for startup diagnostics
- Failed backups are logged as errors and do not stop the server
- Expired backups are automatically purged based on `Backup.RetentionDays`
