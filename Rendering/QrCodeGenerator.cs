using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace BareMetalWeb.Rendering;

public static class QrCodeGenerator
{
    private const int MaxVersion = 10;

    public static string GenerateSvgDataUri(string text, int pixelsPerModule = 4, int border = 4)
    {
        if (string.IsNullOrEmpty(text))
            throw new ArgumentException("QR text cannot be null or empty.", nameof(text));
        if (pixelsPerModule <= 0)
            throw new ArgumentOutOfRangeException(nameof(pixelsPerModule));
        if (border < 0)
            throw new ArgumentOutOfRangeException(nameof(border));

        var qr = QrCode.EncodeText(text, EccLevel.M);
        var svg = qr.ToSvgString(pixelsPerModule, border);
        var bytes = Encoding.UTF8.GetBytes(svg);
        return "data:image/svg+xml;base64," + Convert.ToBase64String(bytes);
    }

    private enum EccLevel
    {
        M = 0
    }

    private sealed class QrCode
    {
        private readonly int _version;
        private readonly int _size;
        private readonly bool[,] _modules;
        private readonly bool[,] _isFunction;

        private QrCode(int version)
        {
            _version = version;
            _size = 17 + 4 * version;
            _modules = new bool[_size, _size];
            _isFunction = new bool[_size, _size];
        }

        public static QrCode EncodeText(string text, EccLevel ecc)
        {
            var data = Encoding.UTF8.GetBytes(text);
            int version = 0;
            int dataCodewords = 0;
            for (int v = 1; v <= MaxVersion; v++)
            {
                dataCodewords = RsBlockTable.GetDataCodewords(v, ecc);
                int capacityBits = dataCodewords * 8;
                int countBits = v <= 9 ? 8 : 16;
                int requiredBits = 4 + countBits + data.Length * 8;
                if (requiredBits <= capacityBits)
                {
                    version = v;
                    break;
                }
            }

            if (version == 0)
                throw new InvalidOperationException("QR payload too large for supported versions.");

            var bb = new BitBuffer();
            bb.AppendBits(0b0100, 4); // byte mode
            bb.AppendBits(data.Length, version <= 9 ? 8 : 16);
            foreach (var b in data)
                bb.AppendBits(b, 8);

            int capacity = dataCodewords * 8;
            int terminator = Math.Min(4, capacity - bb.Length);
            bb.AppendBits(0, terminator);
            while (bb.Length % 8 != 0)
                bb.AppendBits(0, 1);

            var padBytes = new[] { 0xEC, 0x11 };
            int padIndex = 0;
            while (bb.Length < capacity)
            {
                bb.AppendBits(padBytes[padIndex & 1], 8);
                padIndex++;
            }

            var dataCodewordsBytes = bb.ToBytes();
            var allCodewords = AddErrorCorrection(version, ecc, dataCodewordsBytes);

            var qr = new QrCode(version);
            qr.DrawFunctionPatterns();
            qr.DrawCodewords(allCodewords);
            int bestMask = qr.ApplyBestMask(ecc);
            qr.DrawFormatBits(ecc, bestMask);
            return qr;
        }

        public string ToSvgString(int pixelsPerModule, int border)
        {
            int dimension = (_size + border * 2) * pixelsPerModule;
            var sb = new StringBuilder(1024);
            sb.Append($"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{dimension}\" height=\"{dimension}\" viewBox=\"0 0 {dimension} {dimension}\" shape-rendering=\"crispEdges\">");
            sb.Append("<rect width=\"100%\" height=\"100%\" fill=\"#fff\"/>");

            for (int y = 0; y < _size; y++)
            {
                for (int x = 0; x < _size; x++)
                {
                    if (_modules[x, y])
                    {
                        int rx = (x + border) * pixelsPerModule;
                        int ry = (y + border) * pixelsPerModule;
                        sb.Append($"<rect x=\"{rx}\" y=\"{ry}\" width=\"{pixelsPerModule}\" height=\"{pixelsPerModule}\" fill=\"#000\"/>");
                    }
                }
            }

            sb.Append("</svg>");
            return sb.ToString();
        }

        private void DrawFunctionPatterns()
        {
            DrawFinderPattern(3, 3);
            DrawFinderPattern(_size - 4, 3);
            DrawFinderPattern(3, _size - 4);

            DrawTimingPatterns();
            DrawAlignmentPatterns();

            if (_version >= 7)
                DrawVersionBits();

            SetFunctionModule(8, _size - 8, true); // dark module

            for (int i = 0; i < 9; i++)
            {
                if (i != 6)
                {
                    SetFunctionModule(8, i, false);
                    SetFunctionModule(i, 8, false);
                }
            }
            for (int i = _size - 8; i < _size; i++)
            {
                SetFunctionModule(8, i, false);
                SetFunctionModule(i, 8, false);
            }
        }

        private void DrawVersionBits()
        {
            int versionInfo = GetVersionBits(_version);
            for (int i = 0; i < 18; i++)
            {
                bool bit = ((versionInfo >> i) & 1) != 0;
                int a = i % 3;
                int b = i / 3;

                // Top-right
                SetFunctionModule(_size - 11 + a, b, bit);
                // Bottom-left
                SetFunctionModule(b, _size - 11 + a, bit);
            }
        }

        private static int GetVersionBits(int version)
        {
            int data = version << 12;
            const int generator = 0x1F25;
            for (int i = 17; i >= 12; i--)
            {
                if (((data >> i) & 1) != 0)
                    data ^= generator << (i - 12);
            }
            return (version << 12) | (data & 0xFFF);
        }

        private void DrawFinderPattern(int x, int y)
        {
            for (int dy = -4; dy <= 4; dy++)
            {
                for (int dx = -4; dx <= 4; dx++)
                {
                    int xx = x + dx;
                    int yy = y + dy;
                    if (0 <= xx && xx < _size && 0 <= yy && yy < _size)
                    {
                        bool on = Math.Max(Math.Abs(dx), Math.Abs(dy)) switch
                        {
                            4 => false,
                            3 => true,
                            2 => false,
                            1 => true,
                            0 => true,
                            _ => false
                        };
                        SetFunctionModule(xx, yy, on);
                    }
                }
            }
        }

        private void DrawTimingPatterns()
        {
            for (int i = 8; i < _size - 8; i++)
            {
                bool on = (i % 2) == 0;
                SetFunctionModule(i, 6, on);
                SetFunctionModule(6, i, on);
            }
        }

        private void DrawAlignmentPatterns()
        {
            var positions = AlignmentPatternPositions(_version);
            if (positions.Length == 0)
                return;

            foreach (var y in positions)
            {
                foreach (var x in positions)
                {
                    if ((x == 6 && (y == 6 || y == _size - 7)) || (y == 6 && x == _size - 7))
                        continue;
                    DrawAlignmentPattern(x, y);
                }
            }
        }

        private void DrawAlignmentPattern(int x, int y)
        {
            for (int dy = -2; dy <= 2; dy++)
            {
                for (int dx = -2; dx <= 2; dx++)
                {
                    SetFunctionModule(x + dx, y + dy, Math.Max(Math.Abs(dx), Math.Abs(dy)) != 1);
                }
            }
        }

        private void SetFunctionModule(int x, int y, bool isBlack)
        {
            _modules[x, y] = isBlack;
            _isFunction[x, y] = true;
        }

        private void DrawCodewords(byte[] data)
        {
            int i = 0;
            int direction = -1;
            for (int x = _size - 1; x >= 1; x -= 2)
            {
                if (x == 6)
                    x--;

                for (int y = (direction == -1 ? _size - 1 : 0);
                     0 <= y && y < _size;
                     y += direction)
                {
                    for (int dx = 0; dx < 2; dx++)
                    {
                        int xx = x - dx;
                        if (_isFunction[xx, y])
                            continue;

                        bool bit = false;
                        if (i < data.Length * 8)
                        {
                            bit = ((data[i >> 3] >> (7 - (i & 7))) & 1) != 0;
                            i++;
                        }
                        _modules[xx, y] = bit;
                    }
                }
                direction = -direction;
            }
        }

        private int ApplyBestMask(EccLevel ecc)
        {
            int bestMask = 0;
            int bestPenalty = int.MaxValue;
            var original = (bool[,])_modules.Clone();

            for (int mask = 0; mask < 8; mask++)
            {
                ApplyMask(mask);
                DrawFormatBits(ecc, mask);
                int penalty = GetPenaltyScore();
                if (penalty < bestPenalty)
                {
                    bestPenalty = penalty;
                    bestMask = mask;
                }
                Array.Copy(original, _modules, original.Length);
            }

            ApplyMask(bestMask);
            return bestMask;
        }

        private void ApplyMask(int mask)
        {
            for (int y = 0; y < _size; y++)
            {
                for (int x = 0; x < _size; x++)
                {
                    if (_isFunction[x, y])
                        continue;

                    bool invert = mask switch
                    {
                        0 => (x + y) % 2 == 0,
                        1 => y % 2 == 0,
                        2 => x % 3 == 0,
                        3 => (x + y) % 3 == 0,
                        4 => ((y / 2) + (x / 3)) % 2 == 0,
                        5 => (x * y) % 2 + (x * y) % 3 == 0,
                        6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
                        7 => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
                        _ => false
                    };

                    if (invert)
                        _modules[x, y] = !_modules[x, y];
                }
            }
        }

        private void DrawFormatBits(EccLevel ecc, int mask)
        {
            int data = (ecc == EccLevel.M ? 0b00 : 0b00) << 3 | mask;
            int bits = data << 10;
            const int generator = 0x537;
            for (int i = 4; i >= 0; i--)
            {
                if (((bits >> (i + 10)) & 1) != 0)
                    bits ^= generator << i;
            }
            int format = ((data << 10) | bits) ^ 0x5412;

            bool GetBit(int value, int index) => ((value >> index) & 1) != 0;

            for (int i = 0; i <= 5; i++)
                SetFunctionModule(8, i, GetBit(format, i));
            SetFunctionModule(8, 7, GetBit(format, 6));
            SetFunctionModule(8, 8, GetBit(format, 7));
            SetFunctionModule(7, 8, GetBit(format, 8));
            for (int i = 9; i < 15; i++)
                SetFunctionModule(14 - i, 8, GetBit(format, i));

            for (int i = 0; i < 8; i++)
                SetFunctionModule(_size - 1 - i, 8, GetBit(format, i));
            for (int i = 8; i < 15; i++)
                SetFunctionModule(8, _size - 15 + i, GetBit(format, i));
        }

        private int GetPenaltyScore()
        {
            int penalty = 0;

            for (int y = 0; y < _size; y++)
            {
                int runColor = 0;
                int runLength = 0;
                for (int x = 0; x < _size; x++)
                {
                    int color = _modules[x, y] ? 1 : 0;
                    if (x == 0 || color != runColor)
                    {
                        if (runLength >= 5)
                            penalty += 3 + (runLength - 5);
                        runColor = color;
                        runLength = 1;
                    }
                    else
                    {
                        runLength++;
                    }
                }
                if (runLength >= 5)
                    penalty += 3 + (runLength - 5);
            }

            for (int x = 0; x < _size; x++)
            {
                int runColor = 0;
                int runLength = 0;
                for (int y = 0; y < _size; y++)
                {
                    int color = _modules[x, y] ? 1 : 0;
                    if (y == 0 || color != runColor)
                    {
                        if (runLength >= 5)
                            penalty += 3 + (runLength - 5);
                        runColor = color;
                        runLength = 1;
                    }
                    else
                    {
                        runLength++;
                    }
                }
                if (runLength >= 5)
                    penalty += 3 + (runLength - 5);
            }

            for (int y = 0; y < _size - 1; y++)
            {
                for (int x = 0; x < _size - 1; x++)
                {
                    bool c = _modules[x, y];
                    if (c == _modules[x + 1, y] && c == _modules[x, y + 1] && c == _modules[x + 1, y + 1])
                        penalty += 3;
                }
            }

            int[] pattern = { 1, 0, 1, 1, 1, 0, 1 };
            for (int y = 0; y < _size; y++)
            {
                for (int x = 0; x < _size - 6; x++)
                {
                    bool match = true;
                    for (int k = 0; k < 7; k++)
                    {
                        if ((_modules[x + k, y] ? 1 : 0) != pattern[k])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                        penalty += 40;
                }
            }
            for (int x = 0; x < _size; x++)
            {
                for (int y = 0; y < _size - 6; y++)
                {
                    bool match = true;
                    for (int k = 0; k < 7; k++)
                    {
                        if ((_modules[x, y + k] ? 1 : 0) != pattern[k])
                        {
                            match = false;
                            break;
                        }
                    }
                    if (match)
                        penalty += 40;
                }
            }

            int dark = 0;
            for (int y = 0; y < _size; y++)
                for (int x = 0; x < _size; x++)
                    if (_modules[x, y]) dark++;

            int total = _size * _size;
            int k2 = Math.Abs(dark * 20 - total * 10) / total;
            penalty += k2 * 10;

            return penalty;
        }

        private static byte[] AddErrorCorrection(int version, EccLevel ecc, byte[] data)
        {
            var blocks = RsBlockTable.GetBlocks(version, ecc);
            var dataBlocks = new List<byte[]>();
            var ecBlocks = new List<byte[]>();

            int offset = 0;
            foreach (var block in blocks)
            {
                var dataBlock = new byte[block.DataCodewords];
                Array.Copy(data, offset, dataBlock, 0, block.DataCodewords);
                offset += block.DataCodewords;
                var ecBlock = ReedSolomonCompute(dataBlock, block.EccCodewords);
                dataBlocks.Add(dataBlock);
                ecBlocks.Add(ecBlock);
            }

            int maxDataLen = dataBlocks.Max(b => b.Length);
            int maxEcLen = ecBlocks.Max(b => b.Length);
            var result = new List<byte>(data.Length + ecBlocks.Sum(b => b.Length));

            for (int i = 0; i < maxDataLen; i++)
            {
                foreach (var block in dataBlocks)
                {
                    if (i < block.Length)
                        result.Add(block[i]);
                }
            }

            for (int i = 0; i < maxEcLen; i++)
            {
                foreach (var block in ecBlocks)
                {
                    if (i < block.Length)
                        result.Add(block[i]);
                }
            }

            return result.ToArray();
        }

        private static byte[] ReedSolomonCompute(byte[] data, int ecLength)
        {
            var result = new byte[ecLength];
            var gen = ReedSolomonGenerator(ecLength);

            foreach (var b in data)
            {
                byte factor = (byte)(b ^ result[0]);
                Array.Copy(result, 1, result, 0, ecLength - 1);
                result[ecLength - 1] = 0;
                for (int i = 0; i < ecLength; i++)
                {
                    result[i] = (byte)(result[i] ^ GfMultiply(gen[i], factor));
                }
            }

            return result;
        }

        private static byte[] ReedSolomonGenerator(int degree)
        {
            var gen = new byte[degree];
            gen[degree - 1] = 1;
            byte root = 1;
            for (int i = 0; i < degree; i++)
            {
                for (int j = 0; j < degree; j++)
                {
                    gen[j] = (byte)GfMultiply(gen[j], root);
                    if (j + 1 < degree)
                        gen[j] ^= gen[j + 1];
                }
                root = (byte)GfMultiply(root, 2);
            }
            return gen;
        }

        private static int GfMultiply(int x, int y)
        {
            int z = 0;
            for (int i = 0; i < 8; i++)
            {
                if (((y >> i) & 1) != 0)
                    z ^= x << i;
            }
            for (int i = 15; i >= 8; i--)
            {
                if (((z >> i) & 1) != 0)
                    z ^= 0x11D << (i - 8);
            }
            return z & 0xFF;
        }

        private static int[] AlignmentPatternPositions(int version)
        {
            return version switch
            {
                1 => Array.Empty<int>(),
                2 => new[] { 6, 18 },
                3 => new[] { 6, 22 },
                4 => new[] { 6, 26 },
                5 => new[] { 6, 30 },
                6 => new[] { 6, 34 },
                7 => new[] { 6, 22, 38 },
                8 => new[] { 6, 24, 42 },
                9 => new[] { 6, 26, 46 },
                10 => new[] { 6, 28, 50 },
                _ => Array.Empty<int>()
            };
        }
    }

    private readonly struct BlockInfo
    {
        public BlockInfo(int dataCodewords, int eccCodewords)
        {
            DataCodewords = dataCodewords;
            EccCodewords = eccCodewords;
        }

        public int DataCodewords { get; }
        public int EccCodewords { get; }
    }

    private static class RsBlockTable
    {
        public static int GetDataCodewords(int version, EccLevel ecc)
            => GetBlocks(version, ecc).Sum(b => b.DataCodewords);

        public static BlockInfo[] GetBlocks(int version, EccLevel ecc)
        {
            if (ecc != EccLevel.M)
                throw new NotSupportedException("Only ECC level M is supported.");

            return version switch
            {
                1 => CreateBlocks(1, 16, 10),
                2 => CreateBlocks(1, 28, 16),
                3 => CreateBlocks(1, 44, 26),
                4 => CreateBlocks(2, 32, 18),
                5 => CreateBlocks(2, 43, 24),
                6 => CreateBlocks(4, 27, 16),
                7 => CreateBlocks(4, 31, 18),
                8 => CreateBlocks(2, 38, 22, 2, 39, 22),
                9 => CreateBlocks(3, 36, 22, 2, 37, 22),
                10 => CreateBlocks(4, 43, 26, 1, 44, 26),
                _ => throw new NotSupportedException("QR version not supported.")
            };
        }

        private static BlockInfo[] CreateBlocks(int count, int data, int ecc)
        {
            var result = new BlockInfo[count];
            for (int i = 0; i < count; i++)
                result[i] = new BlockInfo(data, ecc);
            return result;
        }

        private static BlockInfo[] CreateBlocks(int count1, int data1, int ecc1, int count2, int data2, int ecc2)
        {
            var result = new BlockInfo[count1 + count2];
            int idx = 0;
            for (int i = 0; i < count1; i++)
                result[idx++] = new BlockInfo(data1, ecc1);
            for (int i = 0; i < count2; i++)
                result[idx++] = new BlockInfo(data2, ecc2);
            return result;
        }
    }

    private sealed class BitBuffer
    {
        private readonly List<bool> _bits = new();
        public int Length => _bits.Count;

        public void AppendBits(int value, int length)
        {
            for (int i = length - 1; i >= 0; i--)
                _bits.Add(((value >> i) & 1) != 0);
        }

        public byte[] ToBytes()
        {
            int byteCount = (_bits.Count + 7) / 8;
            var result = new byte[byteCount];
            for (int i = 0; i < _bits.Count; i++)
            {
                if (_bits[i])
                    result[i >> 3] |= (byte)(1 << (7 - (i & 7)));
            }
            return result;
        }
    }
}
