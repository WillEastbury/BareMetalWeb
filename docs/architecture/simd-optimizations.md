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

## 3. Implemented Optimizations (continued)

### 3.1 Bloom Filter Bit Queries  (`SearchIndexing.cs`)  ✅ Implemented

**Was:** `BitArray` (boolean array) indexed by three hash functions per token lookup.

**What was done:**
- Replaced `BitArray Bits` with `ulong[] Bits` — 64-bit words make better use of
  cache lines and align perfectly with the hardware POPCNT instruction.
- `SetBit(int bitIndex)` / `TestBit(int bitIndex)` helpers use `>> 6` / `& 63`
  bit-addressing with a single `|=` or `&` on a `ulong` word (zero branching).
- `PopulationCount()` iterates over the `ulong[]` with `BitOperations.PopCount`
  (maps to the single-cycle `POPCNT` instruction on x86 and equivalent CNT on ARM)
  to expose the filter fill-rate for false-positive diagnostics.

**Expected gain:** ~3× for the membership test inner loop; the bigger win is the
improved cache footprint (64× fewer array words for the same bit count).

### 3.2 Template Token Scanning  (`HtmlRenderer.cs`)  ✅ Implemented

**Was:** `ReadOnlySpan<char>` scanned character-by-character in a `for` loop
looking for `{{` pairs; single characters written one at a time.

**What was done:**
- The outer `for` loop is replaced with a `while` loop that calls
  `span.Slice(pos).IndexOf("{{".AsSpan())` to locate the next opening delimiter.
  The .NET runtime routes this through SSE2 / NEON vector search automatically.
- The closing `}}` is likewise found with `span.Slice(bodyStart).IndexOf("}}")`.
- Literal text segments between tokens are written as a **single contiguous slice**
  (`Write(writer, span.Slice(pos, openIdx))`) instead of character by character,
  eliminating the per-character UTF-8 encoding overhead.

**Expected gain:** 2–4× for template-heavy pages (large static segments between
few tokens); up to 10× for the token-detection portion alone on modern CPUs.

### 3.3 FNV-1a Schema Hash  (`BinaryObjectSerializer.cs`)  ✅ Implemented

**Was:** Character-at-a-time FNV-1a over the ASCII member-name strings.

**What was done:**
- `GetSignatureHash` and `GetBlittableSignatureHash` now use
  `System.IO.Hashing.XxHash64` (available without a separate NuGet reference on
  .NET 8+ as part of the shared framework; added as a package reference for
  compatibility with `net10.0`).
- The 64-bit XxHash64 digest is folded to 32 bits via `(uint)(h64 ^ (h64 >> 32))`
  to preserve the full avalanche quality in a `uint` schema fingerprint.
- The FNV-1a `Fnv1a` helper is removed; `EmptySchemaHash` is a `static readonly`
  field computed once from an empty member list to replace the hard-coded FNV seed
  `2166136261` used for primitive and empty-object schemas.
- Added `DataLayerCapabilities.SchemaHashPath` and `BloomFilterPath` properties,
  and both appear in `DataLayerCapabilities.Describe()`.

**Expected gain:** ~10× for schema registration throughput. The hash runs only at
type-registration time (not per-request) so the observable impact is at startup,
not steady-state latency.

---

## 4. Implemented Optimizations (continued)

### 3.4 AVX2 Byte Scanner  (`SimdByteScanner.cs`)  ✅ Implemented

**Hot path:** Any code that must find the first occurrence of a specific byte in
a large `ReadOnlySpan<byte>` buffer — binary protocol parsing, WAL record scanning,
static-file content inspection, and pre-screening UTF-8 template buffers for the
`{` (0x7B) delimiter byte before full token parsing.

**Method signature:**
```csharp
public static int FindByte(ReadOnlySpan<byte> data, byte target)
```
Returns the zero-based index of the first match, or `-1` if not found.
Zero allocations; no `unsafe` blocks required (uses `Vector*.LoadUnsafe` and
`MemoryMarshal.GetReference`).

**What was done:**

| Priority | Platform         | Path                                                    | Width   |
|----------|------------------|---------------------------------------------------------|---------|
| 1        | x86-64 with AVX2 | `Avx2.CompareEqual` + `Avx2.MoveMask` + `TrailingZeroCount` | 256-bit / 32 bytes/iter |
| 2        | ARM64 NEON       | `AdvSimd.CompareEqual` + `AdvSimd.Arm64.MaxAcross`     | 128-bit / 16 bytes/iter |
| 3        | All (portable)   | `Vector<byte>` — JIT selects AVX2 (32) or SSE2/NEON (16) | JIT-selected |
| 4        | Scalar fallback  | Plain `for` loop — one byte/iteration                  | 1 byte/iter |

**AVX2 algorithm (32 bytes per iteration):**
1. Broadcast `target` byte into all 32 lanes of a `Vector256<byte>` with `Vector256.Create(target)`.
2. Load 32 bytes from the current position via `Vector256.LoadUnsafe(ref origin, (nuint)i)`.
3. Compare all 32 lanes simultaneously with `Avx2.CompareEqual` — each matching lane becomes `0xFF`.
4. Pack the high bit of each 8-bit lane into a 32-bit mask with `Avx2.MoveMask`.
5. If `mask != 0`, `BitOperations.TrailingZeroCount(mask)` gives the lane index of the first match.
6. Repeat until the buffer is exhausted; remaining `< 32` bytes use a scalar tail.

**Where it is used in the codebase:**
- `SpanReader.IndexOfByte(byte marker)` — SIMD-accelerated search in the current read window
  without advancing the reader position.
- `SpanReader.SkipToMarker(byte marker)` — advances the reader to the next occurrence of a
  specific sentinel byte, useful for binary record parsing in the WAL reader.
- **Template engine** — `HtmlFragmentStore.ZeroAllocationReplaceCopy` and
  `ZeroAllocationReplaceCopyAndWrite` were updated to replace the old char-by-char outer scan
  with `span.IndexOf("{{".AsSpan())`, which routes through the .NET runtime's own SSE2/NEON
  vector search.  For UTF-8 pre-encoded template byte buffers, callers can use
  `SimdByteScanner.FindByte(utf8Bytes, (byte)'{')` as a fast pre-screen before full token parsing.

**Performance goal:** scan buffers > 1 MB at memory-bandwidth speeds (~20+ GB/s on AVX2).

**Benchmark:**
```
dotnet run -c Release --project BareMetalWeb.Benchmarks -- --filter *ByteScanner*
```

**Expected results (1 MB buffer, AVX2 machine):**

| Method                        | Mean    | Ratio |
|-------------------------------|---------|-------|
| Scalar – no match             | ~300 µs | 1.00  |
| Span.IndexOf – no match       | ~80  µs | 0.27  |
| SimdByteScanner – no match    | ~60  µs | 0.20  |
| SimdByteScanner – match at mid| ~30  µs | 0.10  |

---

## 5. Remaining Opportunities (not yet implemented)

### 3.5 AES-NI Encryption  (`SynchronousEncryption.cs`)

**Current:** Delegates to .NET's `Aes.Create()` which already selects AES-NI
hardware under the hood on supported platforms.  No action required.

### 3.6 SHA-256 Cookie / Session Signing  (`BinaryObjectSerializer.cs` — HMAC)

**Current:** `IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, ...)` which
already uses `SHA-NI` (x86) or `SHA256` (ARM) hardware acceleration via the
.NET crypto provider.  No action required.

### 3.7 AVX-512 Float16 / DP-INT8 for Quantized Vectors

**Future (not yet in scope):** When `QuantizationType.Float16` or
`QuantizationType.ProductQuantization` is implemented, consider:
- x86 AVX-512FP16: native half-precision arithmetic (2× throughput vs. FP32 AVX2)
- ARM DP: int8 dot product (4× throughput vs. FP32 NEON) for quantized indices

---

## 5. Capability Detection at Startup

`SimdCapabilities.Current` (in `BareMetalWeb.Data`) detects all features at
first access and exposes a log-friendly summary string.  Wire it into your
startup log:

```csharp
logger.LogInfo(SimdCapabilities.Current.ToLogLine());
```

`DataLayerCapabilities.Describe()` now reports all seven acceleration paths:

```
Portable SIMD width : 256-bit (8 floats/iter, Vector<float> baseline)
Vector distance     : x86 FMA+AVX (256-bit/8×f32)
CRC-32C             : x86 SSE4.2 CRC32Q (64-bit, hardware)
Key comparison      : Direct ulong word comparison (4 × 64-bit, zero allocation)
Bloom filter        : ulong[] bit-packing + BitOperations.PopCount (hardware POPCNT / NEON CNT)
Schema hash         : XxHash64 (hardware-accelerated on x86 via AES/SSE4 and ARM via NEON)
Byte scanner        : x86 AVX2 (256-bit / 32 bytes per iteration)
```

This lets you verify at a glance which SIMD tier is active in production.

---

_Status: 3.1–3.3 implemented in commit **bc095a0**; 3.4 (AVX2 byte scanner) implemented; 3.5–3.6 no action required; 3.7 future scope_

---

## 6. Intelligence Engine — Ternary Dot Product  ✅ Implemented

See [Intelligence Engine Architecture](intelligence.md) for full details.

**Hot path:** `NativeTernaryMatrix.DotProduct` — the inner loop of every
transformer layer forward pass (attention projections and FFN).

**What was done:**

| Priority | Platform | Path | Width |
|----------|----------|------|-------|
| 1 | x86 AVX2 | `DotProductAvx2` — decode 4 packed bytes → `Vector256<int>` | 256-bit / 16 weights per iteration |
| 2 | ARM NEON | _(stub added, implementation pending)_ | 128-bit / 8 weights per iteration |
| 3 | All | Scalar fallback with zero-byte skip | 4 weights per iteration |

**Additional optimizations:**
- **Zero-skip:** 4-byte groups (`uint32`) equal to zero are skipped entirely.
- **Prefetch:** `Sse.Prefetch0(rowPtr + b + 128)` — 2 cache lines ahead.
- **32-byte row alignment:** rows padded to 32-byte stride for cache-line and
  SIMD-width alignment.
