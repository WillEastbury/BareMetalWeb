using System.Buffers.Binary;
namespace BareMetalWeb.Data;

    public ref struct SpanReader
    {
        private readonly ReadOnlySpan<byte> _buffer;
        private int _offset;

        public SpanReader(ReadOnlySpan<byte> buffer)
        {
            _buffer = buffer;
            _offset = 0;
        }

        public byte ReadByte()
        {
            EnsureAvailable(1);
            return _buffer[_offset++];
        }

        public sbyte ReadSByte() => unchecked((sbyte)ReadByte());

        public bool ReadBoolean() => ReadByte() != 0;

        public short ReadInt16()
        {
            EnsureAvailable(2);
            var value = BinaryPrimitives.ReadInt16LittleEndian(_buffer.Slice(_offset, 2));
            _offset += 2;
            return value;
        }

        public ushort ReadUInt16()
        {
            EnsureAvailable(2);
            var value = BinaryPrimitives.ReadUInt16LittleEndian(_buffer.Slice(_offset, 2));
            _offset += 2;
            return value;
        }

        public int ReadInt32()
        {
            EnsureAvailable(4);
            var value = BinaryPrimitives.ReadInt32LittleEndian(_buffer.Slice(_offset, 4));
            _offset += 4;
            return value;
        }

        public uint ReadUInt32()
        {
            EnsureAvailable(4);
            var value = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.Slice(_offset, 4));
            _offset += 4;
            return value;
        }

        public long ReadInt64()
        {
            EnsureAvailable(8);
            var value = BinaryPrimitives.ReadInt64LittleEndian(_buffer.Slice(_offset, 8));
            _offset += 8;
            return value;
        }

        public ulong ReadUInt64()
        {
            EnsureAvailable(8);
            var value = BinaryPrimitives.ReadUInt64LittleEndian(_buffer.Slice(_offset, 8));
            _offset += 8;
            return value;
        }

        public float ReadSingle()
        {
            var value = ReadInt32();
            return BitConverter.Int32BitsToSingle(value);
        }

        public double ReadDouble()
        {
            var value = ReadInt64();
            return BitConverter.Int64BitsToDouble(value);
        }

        public decimal ReadDecimal()
        {
            var lo = ReadInt32();
            var mid = ReadInt32();
            var hi = ReadInt32();
            var flags = ReadInt32();
            var isNegative = (flags & unchecked((int)0x80000000)) != 0;
            var scale = (byte)((flags >> 16) & 0xFF);
            return new decimal(lo, mid, hi, isNegative, scale);
        }

        public char ReadChar() => (char)ReadUInt16();

        public void ReadBytes(scoped Span<byte> destination)
        {
            EnsureAvailable(destination.Length);
            _buffer.Slice(_offset, destination.Length).CopyTo(destination);
            _offset += destination.Length;
        }

        private void EnsureAvailable(int size)
        {
            if (_offset + size > _buffer.Length)
                throw new EndOfStreamException();
        }
    }