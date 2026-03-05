using System.Buffers;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// Request-scoped bump allocator backed by <see cref="ArrayPool{T}.Shared"/>.
/// Provides fast temporary buffer allocation with zero per-allocation overhead.
/// Call <see cref="Reset"/> at the end of each request to reclaim all memory,
/// or <see cref="Dispose"/> to return the backing buffer to the pool.
/// </summary>
public sealed class RequestArena : IDisposable
{
    private byte[] _buffer;
    private int _offset;
    private readonly int _initialCapacity;
    private List<byte[]>? _overflow;

    public RequestArena(int initialCapacity = 8192)
    {
        _initialCapacity = initialCapacity;
        _buffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
        _offset = 0;
    }

    /// <summary>
    /// Allocates a span of <paramref name="size"/> bytes from the arena.
    /// Falls back to a new pooled chunk if the current buffer is exhausted.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public Span<byte> Allocate(int size)
    {
        if (_offset + size <= _buffer.Length)
        {
            var span = _buffer.AsSpan(_offset, size);
            _offset += size;
            return span;
        }

        return AllocateSlow(size);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private Span<byte> AllocateSlow(int size)
    {
        // Current buffer is exhausted — rent a new chunk
        _overflow ??= new List<byte[]>(4);
        _overflow.Add(_buffer);

        int newSize = Math.Max(_buffer.Length * 2, size);
        _buffer = ArrayPool<byte>.Shared.Rent(newSize);
        _offset = size;
        return _buffer.AsSpan(0, size);
    }

    /// <summary>Allocates and copies the source span into the arena.</summary>
    public Span<byte> AllocateCopy(ReadOnlySpan<byte> source)
    {
        var dest = Allocate(source.Length);
        source.CopyTo(dest);
        return dest;
    }

    /// <summary>Resets the arena for reuse without returning memory to the pool.</summary>
    public void Reset()
    {
        _offset = 0;
        if (_overflow != null)
        {
            foreach (var buf in _overflow)
                ArrayPool<byte>.Shared.Return(buf);
            _overflow.Clear();
        }
    }

    /// <summary>Returns all memory to the pool.</summary>
    public void Dispose()
    {
        ArrayPool<byte>.Shared.Return(_buffer);
        if (_overflow != null)
        {
            foreach (var buf in _overflow)
                ArrayPool<byte>.Shared.Return(buf);
            _overflow = null;
        }
    }

    /// <summary>Total bytes allocated from the arena in the current request.</summary>
    public int BytesAllocated => _offset;
}
