using System.Runtime.CompilerServices;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Integer-only token sampling for BitNet inference.
///
/// Provides:
///   • ArgMax      — greedy / deterministic (temperature = 0)
///   • SampleTopK  — stochastic top-K with integer temperature scaling
///
/// Design notes:
///   • No floating-point on the hot path.
///   • No per-call heap allocations (caller supplies scratch buffer).
///   • Temperature is expressed as a fixed-point divisor: tempQ8 = 256 means T=1.0,
///     tempQ8 = 128 means T=0.5 (sharper), tempQ8 = 512 means T=2.0 (flatter).
///     Set tempQ8 = 0 for deterministic greedy argmax.
/// </summary>
public static class Sampling
{
    /// <summary>
    /// Greedy argmax over integer logits — O(n), no allocations.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int ArgMax(ReadOnlySpan<int> logits)
    {
        int best    = 0;
        int bestVal = logits[0];
        for (int i = 1; i < logits.Length; i++)
        {
            if (logits[i] > bestVal)
            {
                bestVal = logits[i];
                best    = i;
            }
        }
        return best;
    }

    /// <summary>
    /// Top-K sampling with integer temperature scaling.
    ///
    /// Algorithm:
    ///   1. Apply temperature: logit' = (logit * 256) / tempQ8  (integer divide)
    ///   2. Find the K-th largest logit (partial selection sort — O(K·n)).
    ///   3. Build a weight vector: weight[i] = max(0, logit'[i] - threshold)
    ///      where threshold is the K-th largest value.
    ///   4. Weighted random sample (Knuth alias-free, integer CDF).
    ///
    /// Parameters:
    ///   logits   — raw output logits
    ///   topK     — number of candidates (default 8; clamped to [1, logits.Length])
    ///   tempQ8   — temperature in Q8 fixed-point (256 = T=1.0, 0 = greedy)
    ///   rng      — caller-supplied random source (pass Random.Shared for hot path)
    ///   scratch  — caller-supplied int buffer of length ≥ logits.Length (no alloc)
    /// </summary>
    public static int SampleTopK(
        ReadOnlySpan<int> logits,
        int               topK   = 8,
        int               tempQ8 = 256,
        Random?           rng    = null,
        Span<int>         scratch = default)
    {
        if (tempQ8 <= 0 || topK <= 1)
            return ArgMax(logits);

        int n = logits.Length;
        topK  = Math.Clamp(topK, 1, n);
        rng ??= Random.Shared;

        // ── 1. Temperature-scaled logits ─────────────────────────────────────
        // Use caller scratch if big enough, otherwise fall back to stack alloc
        // for small n, or heap alloc for larger (rare).
        bool useScratch = scratch.Length >= n;
        Span<int> scaled = useScratch ? scratch.Slice(0, n) : (n <= 512 ? stackalloc int[n] : new int[n]);

        for (int i = 0; i < n; i++)
            scaled[i] = (int)((long)logits[i] * 256 / tempQ8);

        // ── 2. Find K-th largest via partial selection sort ───────────────────
        // We only need the threshold value — copy top-K candidates into a tiny buffer.
        int kBuf = Math.Min(topK, 32); // cap to avoid large stack alloc
        Span<int> top = stackalloc int[kBuf];
        int filled = 0;
        int minTop = int.MaxValue;

        for (int i = 0; i < n; i++)
        {
            int v = scaled[i];
            if (filled < kBuf)
            {
                top[filled++] = v;
                if (filled == kBuf)
                {
                    // Sort descending so top[kBuf-1] = current minimum
                    SortDescending(top.Slice(0, kBuf));
                    minTop = top[kBuf - 1];
                }
            }
            else if (v > minTop)
            {
                top[kBuf - 1] = v;
                SortDescending(top.Slice(0, kBuf));
                minTop = top[kBuf - 1];
            }
        }
        int threshold = filled < kBuf ? MinOf(top.Slice(0, filled)) : minTop;

        // ── 3. Build weight vector (values above threshold) ──────────────────
        long totalWeight = 0;
        for (int i = 0; i < n; i++)
        {
            int w = scaled[i] > threshold ? scaled[i] - threshold : 0;
            scaled[i]   = w;
            totalWeight += w;
        }
        if (totalWeight == 0)
            return ArgMax(logits); // degenerate: fall back to greedy

        // ── 4. Weighted random sample (integer CDF walk) ──────────────────────
        long target = (long)(rng.NextInt64() % totalWeight);
        if (target < 0) target += totalWeight;

        long cumulative = 0;
        for (int i = 0; i < n; i++)
        {
            cumulative += scaled[i];
            if (cumulative > target)
                return i;
        }
        return ArgMax(logits); // numerical fallback
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int MinOf(ReadOnlySpan<int> s)
    {
        int m = s[0];
        for (int i = 1; i < s.Length; i++)
            if (s[i] < m) m = s[i];
        return m;
    }

    /// <summary>Insertion sort (descending) — fast for tiny spans (K ≤ 32).</summary>
    private static void SortDescending(Span<int> s)
    {
        for (int i = 1; i < s.Length; i++)
        {
            int key = s[i];
            int j   = i - 1;
            while (j >= 0 && s[j] < key)
            {
                s[j + 1] = s[j];
                j--;
            }
            s[j + 1] = key;
        }
    }
}
