using System.Buffers;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// Stack-friendly pooled list backed by <see cref="ArrayPool{T}.Shared"/>.
/// Use in place of <see cref="List{T}"/> for short-lived, high-frequency collections
/// on hot paths to avoid GC pressure. Dispose to return the backing array to the pool.
/// </summary>
public struct BmwValueList<T> : IDisposable
{
    private T[]? _items;
    private int _count;
    private const int DefaultCapacity = 8;

    public readonly int Count => _count;
    public readonly ReadOnlySpan<T> Span => _items.AsSpan(0, _count);

    public BmwValueList(int capacity)
    {
        _items = ArrayPool<T>.Shared.Rent(Math.Max(capacity, DefaultCapacity));
        _count = 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Add(T item)
    {
        _items ??= ArrayPool<T>.Shared.Rent(DefaultCapacity);

        if (_count == _items.Length)
            Grow();

        _items[_count++] = item;
    }

    public readonly T this[int index]
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _items![index];
    }

    /// <summary>Copies the contents to a new array. Use sparingly — prefer <see cref="Span"/>.</summary>
    public readonly T[] ToArray()
    {
        if (_count == 0) return [];
        var result = new T[_count];
        _items.AsSpan(0, _count).CopyTo(result);
        return result;
    }

    public void Clear() => _count = 0;

    private void Grow()
    {
        int newCap = _items!.Length * 2;
        var newArr = ArrayPool<T>.Shared.Rent(newCap);
        _items.AsSpan(0, _count).CopyTo(newArr);
        ArrayPool<T>.Shared.Return(_items);
        _items = newArr;
    }

    /// <summary>Returns the backing buffer to the pool.</summary>
    public void Dispose()
    {
        var arr = _items;
        if (arr != null)
        {
            _items = null;
            _count = 0;
            ArrayPool<T>.Shared.Return(arr, clearArray: RuntimeHelpers.IsReferenceOrContainsReferences<T>());
        }
    }

    /// <summary>Returns a struct enumerator (allocation-free).</summary>
    public readonly Enumerator GetEnumerator() => new(this);

    public ref struct Enumerator
    {
        private readonly ReadOnlySpan<T> _span;
        private int _index;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal Enumerator(BmwValueList<T> list)
        {
            _span = list.Span;
            _index = -1;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool MoveNext() => ++_index < _span.Length;

        public readonly T Current
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => _span[_index];
        }
    }
}
