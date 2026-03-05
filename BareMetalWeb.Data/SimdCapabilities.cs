using System.Runtime.CompilerServices;
#if NET7_0_OR_GREATER
using System.Numerics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
#endif

namespace BareMetalWeb.Data;

/// <summary>
/// Reports available CPU SIMD/hardware-acceleration features at startup or on demand.
/// Used for diagnostics, logging, and capability-gating of hot-path SIMD code.
/// </summary>
public sealed class SimdCapabilities
{
    /// <summary>True when the runtime supports hardware accelerated <c>Vector&lt;T&gt;</c>.</summary>
    public bool IsHardwareAccelerated { get; }

    /// <summary>Number of single-precision floats that fit in one portable SIMD register.</summary>
    public int FloatVectorWidth { get; }

    // ─── x86 / x64 ───────────────────────────────────────────────────────────
    public bool Sse2   { get; }
    public bool Sse42  { get; }
    public bool Avx    { get; }
    public bool Avx2   { get; }
    public bool Fma    { get; }
    public bool Avx512F { get; }
    public bool Bmi1   { get; }
    public bool Bmi2   { get; }
    public bool Popcnt { get; }
    public bool Lzcnt  { get; }

    // ─── ARM ─────────────────────────────────────────────────────────────────
    public bool AdvSimd     { get; }
    public bool AdvSimdArm64 { get; }
    public bool ArmCrc32    { get; }
    public bool ArmAes      { get; }
    public bool ArmSha256   { get; }
    public bool ArmDp       { get; }

    /// <summary>
    /// Highest-performance SIMD tier available on this CPU/OS combination.
    /// Used for concise diagnostic logging.
    /// </summary>
    public string BestTier { get; }

    private SimdCapabilities()
    {
#if NET7_0_OR_GREATER
        IsHardwareAccelerated = System.Numerics.Vector.IsHardwareAccelerated;
        FloatVectorWidth      = System.Numerics.Vector<float>.Count;

        // x86
        Sse2    = System.Runtime.Intrinsics.X86.Sse2.IsSupported;
        Sse42   = System.Runtime.Intrinsics.X86.Sse42.IsSupported;
        Avx     = System.Runtime.Intrinsics.X86.Avx.IsSupported;
        Avx2    = System.Runtime.Intrinsics.X86.Avx2.IsSupported;
        Fma     = System.Runtime.Intrinsics.X86.Fma.IsSupported;
        Avx512F = System.Runtime.Intrinsics.X86.Avx512F.IsSupported;
        Bmi1    = System.Runtime.Intrinsics.X86.Bmi1.IsSupported;
        Bmi2    = System.Runtime.Intrinsics.X86.Bmi2.IsSupported;
        Popcnt  = System.Runtime.Intrinsics.X86.Popcnt.IsSupported;
        Lzcnt   = System.Runtime.Intrinsics.X86.Lzcnt.IsSupported;

        // ARM
        AdvSimd      = System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported;
        AdvSimdArm64 = System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported;
        ArmCrc32     = System.Runtime.Intrinsics.Arm.Crc32.IsSupported;
        ArmAes       = System.Runtime.Intrinsics.Arm.Aes.IsSupported;
        ArmSha256    = System.Runtime.Intrinsics.Arm.Sha256.IsSupported;
        ArmDp        = System.Runtime.Intrinsics.Arm.Dp.IsSupported;

        BestTier = DetermineBestTier();
#else
        IsHardwareAccelerated = false;
        FloatVectorWidth      = 1;
        BestTier              = "Scalar";
#endif
    }

    private static SimdCapabilities? _instance;

    /// <summary>Singleton instance – detected once at first access.</summary>
    public static SimdCapabilities Current => _instance ??= new SimdCapabilities();

    /// <summary>
    /// Returns a human-readable capability summary suitable for a startup log line.
    /// Example: "SIMD best-tier=AVX2+FMA, 8×float | x86=[AVX2+FMA POPCNT LZCNT BMI1 BMI2] | ARM=[none]"
    /// </summary>
    public string ToLogLine()
    {
        var x86Parts = new System.Text.StringBuilder();
        if (Avx512F) x86Parts.Append("AVX-512F ");
        if (Fma && Avx2) x86Parts.Append("AVX2+FMA ");
        else if (Avx2) x86Parts.Append("AVX2 ");
        else if (Avx) x86Parts.Append("AVX ");
        else if (Sse42) x86Parts.Append("SSE4.2 ");
        else if (Sse2) x86Parts.Append("SSE2 ");
        if (Popcnt) x86Parts.Append("POPCNT ");
        if (Lzcnt) x86Parts.Append("LZCNT ");
        if (Bmi1) x86Parts.Append("BMI1 ");
        if (Bmi2) x86Parts.Append("BMI2 ");

        var armParts = new System.Text.StringBuilder();
        if (AdvSimdArm64) armParts.Append("AdvSimd/ARM64 ");
        else if (AdvSimd) armParts.Append("AdvSimd ");
        if (ArmCrc32) armParts.Append("CRC32 ");
        if (ArmAes) armParts.Append("AES ");
        if (ArmSha256) armParts.Append("SHA256 ");
        if (ArmDp) armParts.Append("DP ");

        string x86 = x86Parts.Length > 0 ? x86Parts.ToString().TrimEnd() : "none";
        string arm = armParts.Length > 0 ? armParts.ToString().TrimEnd() : "none";

        return $"SIMD best-tier={BestTier}, {FloatVectorWidth}×float | x86=[{x86}] | ARM=[{arm}]";
    }

    private string DetermineBestTier()
    {
#if NET7_0_OR_GREATER
        if (Avx512F)          return "AVX-512F";
        if (Fma && Avx2)      return "AVX2+FMA";
        if (Avx2)             return "AVX2";
        if (Avx)              return "AVX";
        if (AdvSimdArm64)     return "AdvSimd-ARM64";
        if (AdvSimd)          return "AdvSimd";
        if (Sse42)            return "SSE4.2";
        if (Sse2)             return "SSE2";
        if (IsHardwareAccelerated) return "Vector<T>";
#endif
        return "Scalar";
    }
}
