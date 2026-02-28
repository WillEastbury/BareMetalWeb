using System;
using System.IO;
using BareMetalWeb.Core.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Detects legacy string-based (GUID) data format and nukes the data folder
/// if found, since the storage layer now uses uint32 keys.
/// This is a breaking one-time upgrade with no migration path.
/// </summary>
public static class LegacyDataWipeGuard
{
    /// <summary>
    /// Checks the data root for signs of old GUID-based storage format.
    /// If detected, deletes the entire data folder so the engine re-creates it fresh.
    /// Returns true if a wipe was performed.
    /// </summary>
    public static bool WipeIfLegacyDetected(string dataRootPath, IBufferedLogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(dataRootPath) || !Directory.Exists(dataRootPath))
            return false;

        if (!DetectLegacyFormat(dataRootPath))
            return false;

        logger?.LogInfo($"Legacy GUID-based data format detected in '{dataRootPath}'. Wiping data folder for uint32 key upgrade.");

        try
        {
            Directory.Delete(dataRootPath, recursive: true);
            Directory.CreateDirectory(dataRootPath);
            logger?.LogInfo("Legacy data wipe complete. Data folder re-created.");
            return true;
        }
        catch (Exception ex)
        {
            logger?.LogError("Failed to wipe legacy data folder.", ex);
            throw;
        }
    }

    private static bool DetectLegacyFormat(string dataRootPath)
    {
        // Old format: _seqid.dat files were 8 bytes (int64 LE).
        // New format: _seqid.dat files are 4 bytes (uint32 LE).
        // If we find any 8-byte seqid file, it's legacy.
        foreach (var seqFile in Directory.EnumerateFiles(dataRootPath, "_seqid.dat", SearchOption.AllDirectories))
        {
            try
            {
                var info = new FileInfo(seqFile);
                if (info.Length == 8)
                    return true;
            }
            catch
            {
                // Ignore inaccessible files
            }
        }

        // Also check for GUID-named .bin files (32 hex chars) in entity folders
        foreach (var dir in Directory.EnumerateDirectories(dataRootPath))
        {
            foreach (var binFile in Directory.EnumerateFiles(dir, "*.bin", SearchOption.TopDirectoryOnly))
            {
                var name = Path.GetFileNameWithoutExtension(binFile);
                if (name.Length == 32 && IsHexString(name))
                    return true;
                // Only need to check one file per folder
                break;
            }
        }

        return false;
    }

    private static bool IsHexString(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return false;
        }
        return true;
    }
}
