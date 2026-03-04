using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public sealed class WalEncryptionTests : IDisposable
{
    private readonly string _dir;

    public WalEncryptionTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"wal_enc_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, true);
    }

    private static byte[] GenerateKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    [Fact]
    public void EnvelopeEncryption_RoundTrips()
    {
        var kek = GenerateKey();
        var enc = WalEnvelopeEncryption.ForTesting(kek);
        var plaintext = Encoding.UTF8.GetBytes("hello envelope encryption");

        var encrypted = enc.Encrypt(plaintext);
        Assert.NotEqual(plaintext, encrypted);
        Assert.True(encrypted.Length > plaintext.Length);

        var decrypted = enc.Decrypt(encrypted);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EnvelopeEncryption_WrongKey_Throws()
    {
        var kek1 = GenerateKey();
        var kek2 = GenerateKey();
        var enc1 = WalEnvelopeEncryption.ForTesting(kek1);
        var enc2 = WalEnvelopeEncryption.ForTesting(kek2);

        var encrypted = enc1.Encrypt(Encoding.UTF8.GetBytes("secret"));
        Assert.ThrowsAny<CryptographicException>(() => enc2.Decrypt(encrypted));
    }

    [Fact]
    public void EnvelopeEncryption_Disabled_Throws()
    {
        var enc = WalEnvelopeEncryption.ForTesting(null);
        Assert.False(enc.IsEnabled);
        Assert.Throws<InvalidOperationException>(() => enc.Encrypt(new byte[] { 1 }));
        Assert.Throws<InvalidOperationException>(() => enc.Decrypt(new byte[100]));
    }

    [Fact]
    public void PayloadCodec_WithEncryption_RoundTripsSmallPayload()
    {
        var kek = GenerateKey();
        var enc = WalEnvelopeEncryption.ForTesting(kek);

        var input = Encoding.UTF8.GetBytes("short"); // below compression threshold
        var compressed = WalPayloadCodec.TryCompress(input, out ushort codec, out uint uncompressedLen, enc);

        Assert.Equal(WalConstants.CodecEncryptedNone, codec);
        Assert.Equal((uint)input.Length, uncompressedLen);

        var result = WalPayloadCodec.Decompress(compressed, codec, uncompressedLen, enc);
        Assert.Equal(input, result.ToArray());
    }

    [Fact]
    public void PayloadCodec_WithEncryption_RoundTripsLargePayload()
    {
        var kek = GenerateKey();
        var enc = WalEnvelopeEncryption.ForTesting(kek);

        var input = new byte[1024];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 16);

        var compressed = WalPayloadCodec.TryCompress(input, out ushort codec, out uint uncompressedLen, enc);

        Assert.Equal(WalConstants.CodecEncryptedBrotli, codec);
        Assert.Equal((uint)input.Length, uncompressedLen);

        var result = WalPayloadCodec.Decompress(compressed, codec, uncompressedLen, enc);
        Assert.Equal(input, result.ToArray());
    }

    [Fact]
    public async Task WalStore_WithEncryption_RoundTrips()
    {
        var kek = GenerateKey();
        var enc = WalEnvelopeEncryption.ForTesting(kek);

        var payload = Encoding.UTF8.GetBytes("encrypted WAL record payload");
        ulong key = WalConstants.PackKey(100, 1);
        ulong ptr;
        {
            using var store = new WalStore(_dir, encryption: enc);
            ptr = await store.CommitAsync(new[] { WalOp.Upsert(key, payload, encryption: enc) });
        }

        using var store2 = new WalStore(_dir, encryption: enc);
        Assert.True(store2.TryGetHead(key, out ulong recovered));
        Assert.Equal(ptr, recovered);
        Assert.True(store2.TryReadOpPayload(recovered, key, out var got));
        Assert.Equal(payload, got.ToArray());
    }

    [Fact]
    public async Task WalStore_WithEncryption_LargePayloadRoundTrips()
    {
        var kek = GenerateKey();
        var enc = WalEnvelopeEncryption.ForTesting(kek);

        var payload = new byte[2048];
        for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(i % 32);

        ulong key = WalConstants.PackKey(101, 1);
        ulong ptr;
        {
            using var store = new WalStore(_dir, encryption: enc);
            ptr = await store.CommitAsync(new[] { WalOp.Upsert(key, payload, encryption: enc) });
        }

        using var store2 = new WalStore(_dir, encryption: enc);
        Assert.True(store2.TryGetHead(key, out ulong recovered));
        Assert.True(store2.TryReadOpPayload(recovered, key, out var got));
        Assert.Equal(payload, got.ToArray());
    }

    [Fact]
    public async Task WalStore_EncryptedPayload_NotReadableWithoutKey()
    {
        var kek = GenerateKey();
        var enc = WalEnvelopeEncryption.ForTesting(kek);

        var payload = Encoding.UTF8.GetBytes("secret data");
        ulong key = WalConstants.PackKey(102, 1);
        ulong ptr;
        {
            using var store = new WalStore(_dir, encryption: enc);
            ptr = await store.CommitAsync(new[] { WalOp.Upsert(key, payload, encryption: enc) });
        }

        // Try to read with wrong key
        var wrongKek = GenerateKey();
        var wrongEnc = WalEnvelopeEncryption.ForTesting(wrongKek);

        using var store2 = new WalStore(_dir, encryption: wrongEnc);
        Assert.True(store2.TryGetHead(key, out ulong recovered));
        Assert.ThrowsAny<CryptographicException>(() =>
            store2.TryReadOpPayload(recovered, key, out _));
    }
}
