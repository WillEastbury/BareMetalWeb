using System.Buffers;

namespace BareMetalWeb.Data;

/// <summary>
/// Lightweight wrapper around <see cref="ArrayPool{T}.Shared"/> that returns the
/// rented buffer on dispose. Use in a <c>using</c> block for deterministic return.
/// </summary>
public struct BmwBuffer : IDisposable
{
    private byte[]? _array;

    public readonly byte[] Array => _array!;
    public readonly int Length { get; }
    public readonly Span<byte> Span => _array.AsSpan(0, Length);
    public readonly Memory<byte> Memory => _array.AsMemory(0, Length);

    private BmwBuffer(byte[] array, int length)
    {
        _array = array;
        Length = length;
    }

    /// <summary>Rents a buffer of at least <paramref name="minimumLength"/> bytes.</summary>
    public static BmwBuffer Rent(int minimumLength)
    {
        var arr = ArrayPool<byte>.Shared.Rent(minimumLength);
        return new BmwBuffer(arr, minimumLength);
    }

    /// <summary>Returns the buffer to the pool. Safe to call multiple times.</summary>
    public void Dispose()
    {
        var arr = _array;
        if (arr != null)
        {
            _array = null;
            ArrayPool<byte>.Shared.Return(arr);
        }
    }
}

/// <summary>
/// Typed pooled buffer wrapper for any unmanaged or reference type array.
/// </summary>
public struct BmwBuffer<T> : IDisposable
{
    private T[]? _array;

    public readonly T[] Array => _array!;
    public readonly int Length { get; }
    public readonly Span<T> Span => _array.AsSpan(0, Length);
    public readonly Memory<T> Memory => _array.AsMemory(0, Length);

    private BmwBuffer(T[] array, int length)
    {
        _array = array;
        Length = length;
    }

    /// <summary>Rents a buffer of at least <paramref name="minimumLength"/> elements.</summary>
    public static BmwBuffer<T> Rent(int minimumLength)
    {
        var arr = ArrayPool<T>.Shared.Rent(minimumLength);
        return new BmwBuffer<T>(arr, minimumLength);
    }

    /// <summary>Returns the buffer to the pool. Safe to call multiple times.</summary>
    public void Dispose()
    {
        var arr = _array;
        if (arr != null)
        {
            _array = null;
            ArrayPool<T>.Shared.Return(arr);
        }
    }
}
