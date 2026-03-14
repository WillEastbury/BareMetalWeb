using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace BareMetalWeb.Data;

/// <summary>
/// Optional hardware key provider using the Microchip ATECC608A secure element
/// over the Linux I2C interface.  When the chip is present and readable, it provides
/// a 32-byte hardware-bound secret that never leaves the device — suitable as IKM
/// for HKDF key derivation in place of the software-only /etc/machine-id fallback.
///
/// The ATECC608A stores keys in 16 slots (0–15).  This implementation reads from
/// slot 8 (a "miscellaneous read" slot commonly left readable in default configs).
/// If no chip is found, all public methods return false / null gracefully so the
/// caller can fall back to software key derivation.
/// </summary>
[SupportedOSPlatform("linux")]
public static class Atecc608a
{
    // Default I2C address for ATECC608A (0x60, shifted for Linux = 0xC0 >> 1)
    private const int DefaultI2CAddress = 0x60;

    // Linux I2C ioctl constants
    private const int I2C_SLAVE = 0x0703;

    // ATECC608A word address for I/O zone
    private const byte WordAddressCommand = 0x03;

    // ATECC608A opcodes
    private const byte OpcodeRead = 0x02;

    // Slot 8 — commonly configured as a readable data slot in default device configs.
    // Stores a 32-byte value that can serve as hardware-bound entropy.
    private const byte DefaultSlot = 8;

    // Read zone identifiers
    private const byte ZoneData = 0x02;

    /// <summary>
    /// Probes for an ATECC608A device on available I2C buses.
    /// Returns true if the device responds to a wake sequence.
    /// </summary>
    public static bool IsAvailable()
    {
        if (!OperatingSystem.IsLinux()) return false;

        var bus = FindI2CBus();
        if (bus is null) return false;

        try
        {
            using var fd = OpenI2C(bus, DefaultI2CAddress);
            if (fd < 0) return false;

            // Send wake token (write 0x00 at low speed) then read 4-byte response
            Wake(fd);
            Span<byte> wakeResp = stackalloc byte[4];
            var bytesRead = ReadDevice(fd, wakeResp);
            Sleep(fd); // Always put device back to sleep

            // Valid wake response: length=4, status byte=0x11 (after wake)
            return bytesRead >= 4 && wakeResp[0] == 0x04 && wakeResp[1] == 0x11;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Reads a 32-byte hardware-bound key from the specified slot.
    /// Returns null if the device is unavailable or the read fails.
    /// </summary>
    public static byte[]? ReadSlotKey(byte slot = DefaultSlot)
    {
        if (!OperatingSystem.IsLinux()) return null;

        var bus = FindI2CBus();
        if (bus is null) return null;

        try
        {
            using var fd = OpenI2C(bus, DefaultI2CAddress);
            if (fd < 0) return null;

            Wake(fd);
            try
            {
                // Read 32 bytes from the data zone slot (two 32-byte block reads)
                var key = new byte[32];

                // Block 0 (offset 0, 32 bytes)
                if (!ReadZone(fd, ZoneData, slot, 0, key.AsSpan(0, 32)))
                    return null;

                return key;
            }
            finally
            {
                Sleep(fd);
            }
        }
        catch
        {
            return null;
        }
    }

    // ── I2C low-level operations ────────────────────────────────────────────

    /// <summary>
    /// Finds the first available I2C bus device file.
    /// Checks /dev/i2c-1 first (most common on Raspberry Pi), then scans 0–7.
    /// </summary>
    private static string? FindI2CBus()
    {
        // Raspberry Pi and most ARM SBCs use bus 1
        if (File.Exists("/dev/i2c-1")) return "/dev/i2c-1";

        for (int i = 0; i <= 7; i++)
        {
            var path = $"/dev/i2c-{i}";
            if (File.Exists(path)) return path;
        }

        return null;
    }

    /// <summary>
    /// Opens the I2C bus device and sets the slave address.
    /// Returns a file descriptor wrapper, or -1 if the open/ioctl fails.
    /// </summary>
    private static I2CHandle OpenI2C(string busPath, int address)
    {
        int fd = Open(busPath, 2 /* O_RDWR */);
        if (fd < 0) return new I2CHandle(-1);

        if (Ioctl(fd, I2C_SLAVE, address) < 0)
        {
            Close(fd);
            return new I2CHandle(-1);
        }

        return new I2CHandle(fd);
    }

    /// <summary>
    /// Sends a wake sequence: write a zero byte, then wait 1.5ms for the device to wake.
    /// </summary>
    private static void Wake(I2CHandle fd)
    {
        Span<byte> zero = stackalloc byte[1];
        zero[0] = 0x00;
        WriteDevice(fd, zero);
        Thread.Sleep(2); // 1.5ms minimum wake delay, round up to 2ms
    }

    /// <summary>
    /// Sends the sleep command to put the device into low-power mode.
    /// </summary>
    private static void Sleep(I2CHandle fd)
    {
        Span<byte> sleep = stackalloc byte[1];
        sleep[0] = 0x01; // Sleep word address
        WriteDevice(fd, sleep);
    }

    /// <summary>
    /// Reads data from a zone/slot/block on the device.
    /// Sends a Read command, waits for execution, and copies the result.
    /// </summary>
    private static bool ReadZone(I2CHandle fd, byte zone, byte slot, byte block, Span<byte> output)
    {
        // Build the Read command packet
        // Format: [WordAddr=0x03] [Length] [Opcode] [Param1] [Param2_LSB] [Param2_MSB] [CRC_LSB] [CRC_MSB]
        byte param1 = (byte)(zone | 0x80); // 0x80 = 32-byte read
        ushort param2 = (ushort)((slot << 3) | (block & 0x07));

        Span<byte> cmd = stackalloc byte[8];
        cmd[0] = WordAddressCommand; // I/O group word address
        cmd[1] = 0x07;               // Count (bytes following including CRC)
        cmd[2] = OpcodeRead;          // Read opcode
        cmd[3] = param1;
        cmd[4] = (byte)(param2 & 0xFF);
        cmd[5] = (byte)(param2 >> 8);

        // CRC-16 over bytes [1..5] (count through param2)
        var crc = Crc16(cmd[1..6]);
        cmd[6] = (byte)(crc & 0xFF);
        cmd[7] = (byte)(crc >> 8);

        WriteDevice(fd, cmd);

        // Wait for command execution (Read takes ~1ms typical, 5ms max)
        Thread.Sleep(5);

        // Response: [Count] [Data...32 bytes] [CRC_LSB] [CRC_MSB] = 35 bytes
        Span<byte> resp = stackalloc byte[35];
        var bytesRead = ReadDevice(fd, resp);
        if (bytesRead < 35) return false;

        // Verify count byte
        if (resp[0] != 35) return false;

        // Verify response CRC
        var respCrc = Crc16(resp[..33]);
        if (resp[33] != (byte)(respCrc & 0xFF) || resp[34] != (byte)(respCrc >> 8))
            return false;

        // Copy data (bytes 1–32)
        resp[1..33].CopyTo(output);
        return true;
    }

    /// <summary>
    /// ATECC608A CRC-16 (polynomial 0x8005, initial value 0x0000, bit-reversed).
    /// </summary>
    private static ushort Crc16(ReadOnlySpan<byte> data)
    {
        ushort crc = 0x0000;
        foreach (byte b in data)
        {
            for (int shift = 0; shift < 8; shift++)
            {
                byte bit = (byte)(((b >> shift) & 1) ^ (byte)(crc & 1));
                crc >>= 1;
                if (bit != 0)
                    crc ^= 0x8005;
            }
        }
        return crc;
    }

    // ── Managed write/read wrappers ─────────────────────────────────────────

    private static unsafe void WriteDevice(I2CHandle fd, ReadOnlySpan<byte> data)
    {
        fixed (byte* ptr = data)
        {
            Write(fd.Fd, ptr, (nuint)data.Length);
        }
    }

    private static unsafe int ReadDevice(I2CHandle fd, Span<byte> buffer)
    {
        fixed (byte* ptr = buffer)
        {
            var result = Read(fd.Fd, ptr, (nuint)buffer.Length);
            return (int)result;
        }
    }

    // ── I2CHandle (IDisposable wrapper over raw fd) ─────────────────────────

    private readonly struct I2CHandle : IDisposable
    {
        public readonly int Fd;
        public I2CHandle(int fd) => Fd = fd;
        public void Dispose() { if (Fd >= 0) Close(Fd); }
        public static implicit operator int(I2CHandle h) => h.Fd;
        public static implicit operator bool(I2CHandle h) => h.Fd >= 0;
    }

    // ── P/Invoke declarations ───────────────────────────────────────────────

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int Open([MarshalAs(UnmanagedType.LPStr)] string path, int flags);

    [DllImport("libc", EntryPoint = "close", SetLastError = true)]
    private static extern int Close(int fd);

    [DllImport("libc", EntryPoint = "ioctl", SetLastError = true)]
    private static extern int Ioctl(int fd, uint request, int arg);

    [DllImport("libc", EntryPoint = "write", SetLastError = true)]
    private static extern unsafe nint Write(int fd, byte* buf, nuint count);

    [DllImport("libc", EntryPoint = "read", SetLastError = true)]
    private static extern unsafe nint Read(int fd, byte* buf, nuint count);
}
