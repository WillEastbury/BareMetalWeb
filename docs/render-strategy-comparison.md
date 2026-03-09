# Rendering Strategy Comparison

## Strategies Evaluated

| Strategy | Description | Allocations | PipeWriter Calls | Code Complexity |
|---|---|---|---|---|
| **Baseline** | Current `HtmlRenderer.RenderToStreamAsync` — scans template for `{{tokens}}`, writes char spans to PipeWriter via `Encoding.UTF8.GetBytes`. Multiple `GetSpan`/`Advance` per token. | Low (fixed arrays, span slicing) | O(tokens × 2) `GetSpan`+`Advance` per section, 1 `FlushAsync` | Low — single recursive method |
| **A) UTF-8 Fragment** | Replace all string usage with pre-encoded `ReadOnlyMemory<byte>` fragments using `u8` literals. Format dynamic values with `Utf8Formatter`. | Zero in hot path | Similar to baseline | Moderate — requires pre-encoding all static content |
| **B) Arena Renderer** | Per-request `ArrayPool<byte>` arena. Render full response into pooled buffer, single PipeWriter write. | One pool rent/return | 1 `GetSpan` + 1 `Advance` + 1 `FlushAsync` | Moderate — buffer management |
| **C) Compiled Renderer** | Generate per-entity `Action<PipeWriter, string[]>` delegates at startup. Remove runtime field iteration. | Zero in hot path | Fixed per entity | High — startup codegen |
| **D) Template-with-holes** | Precompile templates into `RenderSegment[]` (static byte fragments + field index placeholders). Execute as sequential copy/format. | Zero in hot path | O(segments) `GetSpan`+`Advance`, 1 `FlushAsync` | Moderate — upfront compilation |

## Recommendation

**Strategy D (Template-with-holes)** offers the best balance:
- Zero allocations during rendering
- Predictable, linear execution (no branching on token types)
- Static fragments are pre-encoded UTF-8 bytes — no runtime encoding
- Dynamic values formatted directly into PipeWriter buffer
- Can be further optimised with SIMD fragment copying (#1308) and single-span output (#1309)

## Instrumentation Framework

The `RenderInstrumentation` class and `InstrumentedPipeWriter` wrapper capture:
- Total render time (Stopwatch-based)
- `PipeWriter.GetSpan` call count
- `PipeWriter.FlushAsync` call count  
- Fragment copy count
- Allocation delta (via `GC.GetAllocatedBytesForCurrentThread`)

Use `RenderBenchmark.BenchmarkAsync()` to compare strategies with warm-up and averaging.
