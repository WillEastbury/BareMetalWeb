using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace BareMetalWeb.Host;

/// <summary>
/// Fixed-size struct array of pre-generated CSP nonces, one per connection.
/// Ordinal-indexed — no dictionary, no hashing, no GC pressure on the hot path.
/// </summary>
internal static class ConnectionNoncePool
{
    private const int SlotCount = 2048; // power of 2 for fast masking
    private const int SlotMask = SlotCount - 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct NonceSlot
    {
        public long Epoch;      // monotonic id — identifies which connection owns this slot
        public long NonceLo;    // raw nonce bytes 0-7
        public long NonceHi;    // raw nonce bytes 8-15
        public string? Base64;  // pre-formatted base64 (one alloc per connection, not per request)
    }

    private static readonly NonceSlot[] _slots = new NonceSlot[SlotCount];
    private static long _counter;

    /// <summary>
    /// Allocates a nonce slot for a new connection. Returns ordinal index and epoch
    /// for later lookup. Generates random nonce bytes and pre-formats base64.
    /// </summary>
    public static (int Index, long Epoch, string Nonce) Rent()
    {
        var epoch = Interlocked.Increment(ref _counter);
        var index = (int)(epoch & SlotMask);

        Span<byte> raw = stackalloc byte[16];
        RandomNumberGenerator.Fill(raw);

        var base64 = Convert.ToBase64String(raw);

        ref var slot = ref _slots[index];
        slot.Epoch = epoch;
        slot.NonceLo = BitConverter.ToInt64(raw);
        slot.NonceHi = BitConverter.ToInt64(raw.Slice(8));
        slot.Base64 = base64;

        return (index, epoch, base64);
    }

    /// <summary>
    /// Retrieves the cached nonce string for a connection. O(1) array index — no hash lookup.
    /// Returns null if the slot was recycled (caller should fall back to per-request generation).
    /// </summary>
    public static string? Get(int index, long epoch)
    {
        ref var slot = ref _slots[index & SlotMask];
        return slot.Epoch == epoch ? slot.Base64 : null;
    }

    /// <summary>
    /// Releases a slot (clears the base64 string reference for GC).
    /// </summary>
    public static void Return(int index, long epoch)
    {
        ref var slot = ref _slots[index & SlotMask];
        if (slot.Epoch == epoch)
            slot.Base64 = null;
    }
}

/// <summary>
/// Connection-level feature carrying the pre-generated CSP nonce.
/// Set once per connection in TlsConnectionMiddleware, read by every request on that connection.
/// </summary>
internal sealed class ConnectionNonceFeature(int slotIndex, long epoch, string nonce) : IConnectionNonceFeature
{
    public string Nonce { get; } = nonce;
    public int SlotIndex { get; } = slotIndex;
    public long Epoch { get; } = epoch;
}
