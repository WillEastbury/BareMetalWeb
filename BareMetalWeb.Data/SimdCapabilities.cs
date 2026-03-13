using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Data;

/// <summary>
/// Central, detect-once capability cache for CPU SIMD/hardware-acceleration features.
/// Initialised as a singleton at first access; every consumer reads the cached flags
/// rather than calling <c>IsSupported</c> directly.
/// <para>
/// <b>Why two sets of x86 flags?</b>  The runtime properties (<see cref="Avx2"/>, etc.)
/// reflect what the AOT/JIT compiler baked in (controlled by <c>IlcInstructionSet</c>
/// for NativeAOT).  The raw CPUID properties (<see cref="CpuHasAvx2"/>, etc.) reflect
/// what the silicon actually advertises.  When these disagree the dashboard can pinpoint
/// whether the block is an AOT config issue, an OS/BIOS issue, or an environment-variable
/// override.
/// </para>
/// <para>
/// <b>Hot-path dispatch note:</b>  The SIMD math files (<c>SimdDistance</c>,
/// <c>SimdVectorMath</c>, <c>DictionaryColumnFilter</c>, <c>WalCrc32C</c>) still use
/// <c>Xxx.IsSupported</c> directly in their dispatch guards.  This is intentional:
/// NativeAOT requires the literal <c>IsSupported</c> check so ILC can dead-code-eliminate
/// the unused instruction paths.  Replacing them with a property read would compile
/// ALL tiers into the binary and defeat the AOT optimiser.  All reporting, logging,
/// and dashboard code uses this class instead.
/// </para>
/// </summary>
public sealed class SimdCapabilities
{
    /// <summary>True when the runtime supports hardware accelerated <c>Vector&lt;T&gt;</c>.</summary>
    public bool IsHardwareAccelerated { get; }

    /// <summary>Number of single-precision floats that fit in one portable SIMD register.</summary>
    public int FloatVectorWidth { get; }

    /// <summary>SIMD register width in bits (128 for SSE, 256 for AVX, 512 for AVX-512).</summary>
    public int VectorBitWidth { get; }

    // ─── x86 / x64 runtime-enabled (reflects IlcInstructionSet for AOT) ──────
    public bool Sse2    { get; }
    public bool Sse42   { get; }
    public bool Sse42X64 { get; }
    public bool Avx     { get; }
    public bool Avx2    { get; }
    public bool Fma     { get; }
    public bool Avx512F { get; }
    public bool Bmi1    { get; }
    public bool Bmi2    { get; }
    public bool Popcnt  { get; }
    public bool Lzcnt   { get; }

    // ─── x86 / x64 raw CPUID (what the silicon advertises) ───────────────────
    public bool CpuHasSse2    { get; }
    public bool CpuHasSse42   { get; }
    public bool CpuHasAvx     { get; }
    public bool CpuHasAvx2    { get; }
    public bool CpuHasFma     { get; }
    public bool CpuHasAvx512F { get; }
    public bool CpuHasBmi1    { get; }
    public bool CpuHasBmi2    { get; }
    public bool CpuHasPopcnt  { get; }
    public bool CpuHasLzcnt   { get; }
    public bool OsXSaveEnabled { get; }

    // ─── ARM ─────────────────────────────────────────────────────────────────
    public bool AdvSimd      { get; }
    public bool AdvSimdArm64 { get; }
    public bool ArmCrc32     { get; }
    public bool ArmCrc32Arm64 { get; }
    public bool ArmAes       { get; }
    public bool ArmSha256    { get; }
    public bool ArmDp        { get; }
    public bool Sve          { get; }
    public bool Sve2         { get; }

    // ─── Platform-neutral vector widths ──────────────────────────────────────
    public bool Vector128Accelerated { get; }
    public bool Vector256Accelerated { get; }
    public bool Vector512Accelerated { get; }

    /// <summary>
    /// Highest-performance SIMD tier available on this CPU/OS combination.
    /// Used for concise diagnostic logging.
    /// </summary>
    public string BestTier { get; }

    /// <summary>Active CRC-32C path description for the dashboard.</summary>
    public string Crc32CPath { get; }

    private SimdCapabilities()
    {
        IsHardwareAccelerated = Vector.IsHardwareAccelerated;
        FloatVectorWidth      = Vector<float>.Count;
        VectorBitWidth        = Vector<byte>.Count * 8;

        // x86 runtime checks
        Sse2     = Sse2Intrinsic.IsSupported;
        Sse42    = Sse42Intrinsic.IsSupported;
        Sse42X64 = Sse42Intrinsic.X64.IsSupported;
        Avx      = AvxIntrinsic.IsSupported;
        Avx2     = Avx2Intrinsic.IsSupported;
        Fma      = FmaIntrinsic.IsSupported;
        Avx512F  = Avx512FIntrinsic.IsSupported;
        Bmi1     = Bmi1Intrinsic.IsSupported;
        Bmi2     = Bmi2Intrinsic.IsSupported;
        Popcnt   = PopcntIntrinsic.IsSupported;
        Lzcnt    = LzcntIntrinsic.IsSupported;

        // Raw CPUID — what the silicon actually advertises
        if (X86Base.IsSupported)
        {
            var (_, _, ecx1, edx1) = X86Base.CpuId(1, 0);
            CpuHasSse2     = (edx1 & (1 << 26)) != 0;
            CpuHasSse42    = (ecx1 & (1 << 20)) != 0;
            CpuHasPopcnt   = (ecx1 & (1 << 23)) != 0;
            CpuHasFma      = (ecx1 & (1 << 12)) != 0;
            OsXSaveEnabled = (ecx1 & (1 << 27)) != 0;
            CpuHasAvx      = (ecx1 & (1 << 28)) != 0;

            var (_, ebx7, _, _) = X86Base.CpuId(7, 0);
            CpuHasAvx2    = (ebx7 & (1 <<  5)) != 0;
            CpuHasBmi1    = (ebx7 & (1 <<  3)) != 0;
            CpuHasBmi2    = (ebx7 & (1 <<  8)) != 0;
            CpuHasAvx512F = (ebx7 & (1 << 16)) != 0;

            var (_, _, ecxExt, _) = X86Base.CpuId(unchecked((int)0x80000001), 0);
            CpuHasLzcnt   = (ecxExt & (1 << 5)) != 0;
        }

        // ARM
        AdvSimd       = System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported;
        AdvSimdArm64  = System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported;
        ArmCrc32      = System.Runtime.Intrinsics.Arm.Crc32.IsSupported;
        ArmCrc32Arm64 = System.Runtime.Intrinsics.Arm.Crc32.Arm64.IsSupported;
        ArmAes        = System.Runtime.Intrinsics.Arm.Aes.IsSupported;
        ArmSha256     = System.Runtime.Intrinsics.Arm.Sha256.IsSupported;
        ArmDp         = System.Runtime.Intrinsics.Arm.Dp.IsSupported;
#pragma warning disable SYSLIB5003
        Sve           = System.Runtime.Intrinsics.Arm.Sve.IsSupported;
        Sve2          = Sve && IsSve2Supported();
#pragma warning restore SYSLIB5003

        // Platform-neutral vector widths
        Vector128Accelerated = Vector128.IsHardwareAccelerated;
        Vector256Accelerated = Vector256.IsHardwareAccelerated;
        Vector512Accelerated = Vector512.IsHardwareAccelerated;

        BestTier  = DetermineBestTier();
        Crc32CPath = DetermineCrc32CPath();
    }

    // Type aliases to avoid collision with property names
    private static class Sse2Intrinsic    { public static bool IsSupported => System.Runtime.Intrinsics.X86.Sse2.IsSupported; }
    private static class Sse42Intrinsic   { public static bool IsSupported => System.Runtime.Intrinsics.X86.Sse42.IsSupported; public static class X64 { public static bool IsSupported => System.Runtime.Intrinsics.X86.Sse42.X64.IsSupported; } }
    private static class AvxIntrinsic     { public static bool IsSupported => System.Runtime.Intrinsics.X86.Avx.IsSupported; }
    private static class Avx2Intrinsic    { public static bool IsSupported => System.Runtime.Intrinsics.X86.Avx2.IsSupported; }
    private static class FmaIntrinsic     { public static bool IsSupported => System.Runtime.Intrinsics.X86.Fma.IsSupported; }
    private static class Avx512FIntrinsic { public static bool IsSupported => System.Runtime.Intrinsics.X86.Avx512F.IsSupported; }
    private static class Bmi1Intrinsic    { public static bool IsSupported => System.Runtime.Intrinsics.X86.Bmi1.IsSupported; }
    private static class Bmi2Intrinsic    { public static bool IsSupported => System.Runtime.Intrinsics.X86.Bmi2.IsSupported; }
    private static class PopcntIntrinsic  { public static bool IsSupported => System.Runtime.Intrinsics.X86.Popcnt.IsSupported; }
    private static class LzcntIntrinsic   { public static bool IsSupported => System.Runtime.Intrinsics.X86.Lzcnt.IsSupported; }

    private static SimdCapabilities? _instance;

    /// <summary>Singleton instance – detected once at first access.</summary>
    public static SimdCapabilities Current => _instance ??= new SimdCapabilities();

    /// <summary>
    /// Returns a human-readable capability summary suitable for a startup log line.
    /// Example: "SIMD best-tier=AVX2+FMA, 256-bit (8×float) | x86=[AVX2+FMA POPCNT LZCNT BMI1 BMI2] | ARM=[none]"
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
        if (Sve2) armParts.Append("SVE2 ");
        else if (Sve) armParts.Append("SVE ");
        if (AdvSimdArm64) armParts.Append("AdvSimd/ARM64 ");
        else if (AdvSimd) armParts.Append("AdvSimd ");
        if (ArmCrc32) armParts.Append("CRC32 ");
        if (ArmAes) armParts.Append("AES ");
        if (ArmSha256) armParts.Append("SHA256 ");
        if (ArmDp) armParts.Append("DP ");

        string x86 = x86Parts.Length > 0 ? x86Parts.ToString().TrimEnd() : "none";
        string arm = armParts.Length > 0 ? armParts.ToString().TrimEnd() : "none";

        return $"SIMD best-tier={BestTier}, {VectorBitWidth}-bit ({FloatVectorWidth}×float) | x86=[{x86}] | ARM=[{arm}]";
    }

    /// <summary>
    /// Returns diagnostic lines for any feature the CPU supports but the runtime does not
    /// (typically caused by missing <c>IlcInstructionSet</c> in the csproj for NativeAOT).
    /// Empty when everything agrees.
    /// </summary>
    public IReadOnlyList<string> GetMismatchWarnings()
    {
        var warnings = new List<string>();
        CheckMismatch(warnings, "AVX",     Avx,    CpuHasAvx);
        CheckMismatch(warnings, "AVX2",    Avx2,   CpuHasAvx2);
        CheckMismatch(warnings, "FMA",     Fma,    CpuHasFma);
        CheckMismatch(warnings, "AVX-512F",Avx512F,CpuHasAvx512F);
        CheckMismatch(warnings, "BMI1",    Bmi1,   CpuHasBmi1);
        CheckMismatch(warnings, "BMI2",    Bmi2,   CpuHasBmi2);
        CheckMismatch(warnings, "LZCNT",   Lzcnt,  CpuHasLzcnt);
        CheckMismatch(warnings, "POPCNT",  Popcnt, CpuHasPopcnt);
        return warnings;

        static void CheckMismatch(List<string> list, string name, bool runtime, bool cpuid)
        {
            if (cpuid && !runtime)
                list.Add($"⚠ CPUID reports {name} but runtime has it disabled (check IlcInstructionSet for NativeAOT)");
        }
    }

    private string DetermineBestTier()
    {
        if (Avx512F)          return "AVX-512F";
        if (Fma && Avx2)      return "AVX2+FMA";
        if (Avx2)             return "AVX2";
        if (Avx)              return "AVX";
        if (Sve2)             return "SVE2";
        if (Sve)              return "SVE";
        if (AdvSimdArm64)     return "AdvSimd-ARM64";
        if (AdvSimd)          return "AdvSimd";
        if (Sse42)            return "SSE4.2";
        if (Sse2)             return "SSE2";
        if (IsHardwareAccelerated) return "Vector<T>";
        return "Scalar";
    }

    private string DetermineCrc32CPath()
    {
        if (ArmCrc32Arm64)  return "ARM CRC32 (64-bit, hardware)";
        if (ArmCrc32)       return "ARM CRC32 (32-bit, hardware)";
        if (Sse42X64)       return "x86 SSE4.2 CRC32Q (64-bit, hardware)";
        if (Sse42)          return "x86 SSE4.2 CRC32D (32-bit, hardware)";
        return "Software (slice-by-8)";
    }

#pragma warning disable SYSLIB5003
    private static bool IsSve2Supported()
    {
        try { return System.Runtime.Intrinsics.Arm.Sve2.IsSupported; }
        catch { return false; }
    }
#pragma warning restore SYSLIB5003
}
