using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace BareMetalWeb.Rendering;

/// <summary>
/// SIMD-accelerated memory copy for HTML fragments. Uses Vector128 (SSE2/NEON)
/// for fragments ≥ 16 bytes, falling back to Span.CopyTo for smaller sizes.
/// Portable across x64 (SSE2) and ARM64 (NEON/AdvSIMD).
/// </summary>
public static class SimdCopy
{
    /// <summary>
    /// Copies <paramref name="source"/> into <paramref name="destination"/> using
    /// vectorised loads/stores for fragments ≥ 16 bytes.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void CopyFragment(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int length = source.Length;

        if (length < Vector128<byte>.Count)
        {
            source.CopyTo(destination);
            return;
        }

        CopyVectorized(ref MemoryMarshal.GetReference(source),
                        ref MemoryMarshal.GetReference(destination),
                        length);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void CopyVectorized(ref byte src, ref byte dst, int length)
    {
        int offset = 0;
        int vectorSize = Vector128<byte>.Count; // 16

        // Main loop: 16 bytes per iteration
        while (offset + vectorSize <= length)
        {
            var vec = Vector128.LoadUnsafe(ref src, (nuint)offset);
            vec.StoreUnsafe(ref dst, (nuint)offset);
            offset += vectorSize;
        }

        // Tail: copy remaining bytes
        int remaining = length - offset;
        if (remaining > 0)
        {
            Unsafe.CopyBlockUnaligned(
                ref Unsafe.Add(ref dst, offset),
                ref Unsafe.Add(ref src, offset),
                (uint)remaining);
        }
    }
}
