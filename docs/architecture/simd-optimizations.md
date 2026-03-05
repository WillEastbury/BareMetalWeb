# SIMD & Hardware-Intrinsics Optimizations

This document analyses every area of BareMetalWeb where CPU-specific SIMD or
hardware-accelerated instructions can deliver a measurable performance win,
records what has been implemented, and describes the remaining opportunities.

---

## 1. Feature Inventory

### 1.1 x86 / x64 (Intel & AMD)

| Feature   | Instruction width | Best for                                    |
|-----------|------------------:|---------------------------------------------|
| SSE2      | 128-bit (4×float) | Baseline SIMD, almost universally available |
| SSE4.2    | 128-bit           | CRC-32C (one instruction)                   |
| AVX       | 256-bit (8×float) | Wider FP/integer vectors                    |
| AVX2      | 256-bit           | Integer SIMD, gather loads                  |
| FMA       | 256-bit           | Fused multiply-add (dot products, MACs)     |
| AVX-512F  | 512-bit (16×float)| Widest FP vectors; server CPUs only         |
| BMI1/BMI2 | scalar            | Bit manipulation (LZCNT, POPCNT, TZCNT)     |
| POPCNT    | scalar            | Population count (Bloom filter queries)     |
| LZCNT     | scalar            | Leading-zero count (bit-range searches)     |

### 1.2 ARM / ARM64

| Feature     | Instruction width  | Best for                                   |
|-------------|-------------------:|--------------------------------------------|
| AdvSimd     | 128-bit (4×float)  | General FP/integer SIMD (NEON)             |
| AdvSimd/A64 | 128-bit + extras   | `FADDP`, horizontal reductions, FMA        |
| CRC32       | scalar             | CRC-32C (one instruction)                  |
| AES         | 128-bit            | AES-NI encryption                          |
| SHA256      | 128-bit            | SHA-256 acceleration                       |
| DP          | 128-bit            | Dot-product int8 (quantized ML inference)  |

---

## 2. Implemented Optimizations

### 2.1 WAL CRC-32C  (`WalCrc32C.cs`)  ✅ Implemented

**Hot path:** WAL segment writer and reader compute a CRC-32C checksum over
every record payload for integrity checking.

**What was done:**
- ARM64: `Crc32.Arm64.ComputeCrc32C` — processes 8 bytes per instruction via the
  dedicated CRC32CD hardware instruction.
- x86-64: `Sse42.X64.Crc32` — 8-byte steps.
- x86-32: `Sse42.Crc32` — 4-byte steps.
- Scalar fallback: table-lookup soft CRC.

**Expected gain:** 8–20× vs. the software table path, effectively making CRC
cost negligible compared to disk I/O.

---

### 2.2 ANN Vector Distance Computations  (`SimdVectorMath.cs`)  ✅ Implemented

**Hot path:** `VectorSegment.ComputeDistance` is called O(beamWidth × neighbours)
times per ANN query — easily millions of calls when indexing thousands of vectors
in high-dimensional spaces.

Three distance metrics are used:

| Metric      | Operations per dimension                              |
|-------------|-------------------------------------------------------|
| Cosine      | 3 multiplies + 3 adds (dot, normA, normB), 1 sqrt    |
| Dot product | 1 multiply + 1 add                                    |
| Euclidean   | 1 subtract + 1 multiply + 1 add, 1 sqrt              |

All three reduce to one or more **dot-product-like inner loops** — exactly what
FMA is designed for.

**What was done (in `SimdVectorMath.cs`):**

| Platform          | Path                               | Width          |
|-------------------|------------------------------------|----------------|
| x86 with FMA+AVX  | `Fma.MultiplyAdd` + `Avx.Subtract` | 256-bit/8×f32  |
| ARM with AdvSimd  | `AdvSimd.FusedMultiplyAdd`         | 128-bit/4×f32  |
| All others        | `System.Numerics.Vector<float>`    | JIT-selected   |

The portable `Vector<float>` path is the safest fallback: the JIT selects AVX2
(8 floats), SSE2 (4 floats), or NEON (4 floats) at startup.

**Expected gain (approximate, Release build):**

| Dimension | Scalar (ns) | SIMD (ns) | Speedup |
|----------:|------------:|----------:|--------:|
|        64 |        ~40  |       ~8  |   ~5×   |
|       256 |       ~140  |      ~25  |   ~5.5× |
|      1536 |       ~830  |     ~140  |   ~6×   |

Run `VectorDistanceBenchmarks` in the `BareMetalWeb.Benchmarks` project to
measure on your hardware:

```
dotnet run -c Release --project BareMetalWeb.Benchmarks -- --filter *VectorDistance*
```

**How to query capabilities at runtime:**

```csharp
var cap = SimdCapabilities.Current;
logger.LogInfo(cap.ToLogLine());
// Example: "SIMD best-tier=AVX2+FMA, 8×float | x86=[AVX2+FMA POPCNT LZCNT BMI1 BMI2] | ARM=[none]"
```

---

## 3. Further Opportunities (not yet implemented)

### 3.1 Bloom Filter Bit Queries  (`SearchIndexing.cs`)

**Current:** `bool[]` array indexed by three hash functions per token lookup.

**Opportunity:** Pack bits into `ulong[]` and use `POPCNT` / `Bmi1.TrailingZeroCount`
to reduce false-positive rate analysis and accelerate bulk membership probes in
batch search scenarios.  Estimated win: ~3× for the membership test itself, though
the test is rarely the bottleneck compared to the `Dictionary` lookup that follows.

### 3.2 Template Token Scanning  (`HtmlRenderer.cs`)

**Current:** `ReadOnlySpan<char>` scanned with a `while` loop looking for `{{` pairs.

**Opportunity:** Use `IndexOf` overloads backed by SSE2/NEON vectorized string
search (already available via .NET's `MemoryExtensions.IndexOf`, which is SIMD-
accelerated in the runtime). Replacing the manual two-character match with
`span.IndexOf("{{".AsSpan())` is sufficient to capture this win without any
custom intrinsics code.

### 3.3 FNV-1a Schema Hash  (`BinaryObjectSerializer.cs`)

**Current:** Character-at-a-time FNV-1a over ASCII member-name strings.

**Opportunity:** Switch to `System.IO.Hashing.XxHash3` or `XxHash64` (available
in .NET 8+, hardware-accelerated on x86 via AESNI/SSE4 and on ARM via NEON).
XxHash3 over the raw UTF-8 bytes would be ~10× faster and still serves purely as
a structural-change detector (not a cryptographic hash). This path runs only at
schema registration time (not per-request) so the impact is low.

### 3.4 AES-NI Encryption  (`SynchronousEncryption.cs`)

**Current:** Delegates to .NET's `Aes.Create()` which already selects AES-NI
hardware under the hood on supported platforms.  No action required.

### 3.5 SHA-256 Cookie / Session Signing  (`BinaryObjectSerializer.cs` — HMAC)

**Current:** `IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, ...)` which
already uses `SHA-NI` (x86) or `SHA256` (ARM) hardware acceleration via the
.NET crypto provider.  No action required.

### 3.6 AVX-512 Float16 / DP-INT8 for Quantized Vectors

**Future (not yet in scope):** When `QuantizationType.Float16` or
`QuantizationType.ProductQuantization` is implemented, consider:
- x86 AVX-512FP16: native half-precision arithmetic (2× throughput vs. FP32 AVX2)
- ARM DP: int8 dot product (4× throughput vs. FP32 NEON) for quantized indices

---

## 4. Capability Detection at Startup

`SimdCapabilities.Current` (in `BareMetalWeb.Data`) detects all features at
first access and exposes a log-friendly summary string.  Wire it into your
startup log:

```csharp
logger.LogInfo(SimdCapabilities.Current.ToLogLine());
```

This lets you verify at a glance which SIMD tier is active in production.

---

_Status: implemented in commit **{HEAD}**_
