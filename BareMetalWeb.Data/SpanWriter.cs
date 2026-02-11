using System.Buffers;
using System.Buffers.Binary;
namespace BareMetalWeb.Data;

    public ref struct SpanWriter
    {
        private readonly IBufferWriter<byte> _writer;
        private Span<byte> _buffer;
        private int _index;
        private int _totalWritten;

        public SpanWriter(IBufferWriter<byte> writer)
        {
            _writer = writer ?? throw new ArgumentNullException(nameof(writer));
            _buffer = writer.GetSpan();
            _index = 0;
            _totalWritten = 0;
        }

        public int Commit()
        {
            if (_index > 0)
            {
                _writer.Advance(_index);
                _totalWritten += _index;
                _index = 0;
            }

            return _totalWritten;
        }

        public void WriteByte(byte value)
        {
            Ensure(1);
            _buffer[_index++] = value;
        }

        public void WriteSByte(sbyte value) => WriteByte(unchecked((byte)value));

        public void WriteBoolean(bool value) => WriteByte(value ? (byte)1 : (byte)0);

        public void WriteInt16(short value)
        {
            Ensure(2);
            BinaryPrimitives.WriteInt16LittleEndian(_buffer.Slice(_index, 2), value);
            _index += 2;
        }

        public void WriteUInt16(ushort value)
        {
            Ensure(2);
            BinaryPrimitives.WriteUInt16LittleEndian(_buffer.Slice(_index, 2), value);
            _index += 2;
        }

        public void WriteInt32(int value)
        {
            Ensure(4);
            BinaryPrimitives.WriteInt32LittleEndian(_buffer.Slice(_index, 4), value);
            _index += 4;
        }

        public void WriteUInt32(uint value)
        {
            Ensure(4);
            BinaryPrimitives.WriteUInt32LittleEndian(_buffer.Slice(_index, 4), value);
            _index += 4;
        }

        public void WriteInt64(long value)
        {
            Ensure(8);
            BinaryPrimitives.WriteInt64LittleEndian(_buffer.Slice(_index, 8), value);
            _index += 8;
        }

        public void WriteUInt64(ulong value)
        {
            Ensure(8);
            BinaryPrimitives.WriteUInt64LittleEndian(_buffer.Slice(_index, 8), value);
            _index += 8;
        }

        public void WriteSingle(float value)
        {
            WriteInt32(BitConverter.SingleToInt32Bits(value));
        }

        public void WriteDouble(double value)
        {
            WriteInt64(BitConverter.DoubleToInt64Bits(value));
        }

        public void WriteDecimal(decimal value)
        {
            var bits = decimal.GetBits(value);
            WriteInt32(bits[0]);
            WriteInt32(bits[1]);
            WriteInt32(bits[2]);
            WriteInt32(bits[3]);
        }

        public void WriteChar(char value) => WriteUInt16(value);

        public void WriteBytes(scoped ReadOnlySpan<byte> source)
        {
            var remaining = source.Length;
            var offset = 0;

            while (remaining > 0)
            {
                var available = _buffer.Length - _index;
                if (available == 0)
                {
                    FlushBuffer();
                    available = _buffer.Length - _index;
                }

                var toCopy = Math.Min(available, remaining);
                source.Slice(offset, toCopy).CopyTo(_buffer.Slice(_index, toCopy));
                _index += toCopy;
                offset += toCopy;
                remaining -= toCopy;
            }
        }

        private void Ensure(int size)
        {
            if (_buffer.Length - _index < size)
            {
                FlushBuffer();
                if (_buffer.Length < size)
                    _buffer = _writer.GetSpan(size);
            }
        }

        private void FlushBuffer()
        {
            if (_index > 0)
            {
                _writer.Advance(_index);
                _totalWritten += _index;
                _index = 0;
            }

            _buffer = _writer.GetSpan();
        }
    }