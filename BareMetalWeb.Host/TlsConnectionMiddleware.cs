using System.IO.Pipelines;
using System.Net.Security;
using System.Security.Authentication;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Http.Features;

namespace BareMetalWeb.Host;

/// <summary>
/// Kestrel connection middleware that wraps the raw TCP transport in an SslStream.
/// Bypasses Kestrel's UseHttps() (which requires DI) by doing TLS at the connection layer directly.
/// </summary>
internal sealed class TlsConnectionMiddleware(
    ConnectionDelegate next,
    SslServerAuthenticationOptions sslOptions)
{
    public async Task OnConnectionAsync(ConnectionContext context)
    {
        var inputStream = context.Transport.Input.AsStream();
        var outputStream = context.Transport.Output.AsStream();
        var innerStream = new DuplexStream(inputStream, outputStream);
        var sslStream = new SslStream(innerStream, leaveInnerStreamOpen: false);

        try
        {
            await sslStream.AuthenticateAsServerAsync(sslOptions, context.ConnectionClosed);

            // Wrap SslStream as PipeReader/PipeWriter and hand directly to Kestrel
            var sslReader = PipeReader.Create(sslStream, new StreamPipeReaderOptions(leaveOpen: true));
            var sslWriter = PipeWriter.Create(sslStream, new StreamPipeWriterOptions(leaveOpen: true));

            var original = context.Transport;
            context.Transport = new SslDuplexPipe(sslReader, sslWriter);
            context.Features.Set<ITlsConnectionFeature>(new TlsFeature(sslStream));

            // One nonce per connection — avoids per-request RNG call
            var (slotIndex, epoch, nonce) = ConnectionNoncePool.Rent();
            context.Features.Set<IConnectionNonceFeature>(new ConnectionNonceFeature(slotIndex, epoch, nonce));

            try
            {
                await next(context);
            }
            finally
            {
                ConnectionNoncePool.Return(slotIndex, epoch);
                context.Transport = original;
                await sslReader.CompleteAsync();
                await sslWriter.CompleteAsync();
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
        catch (AuthenticationException ex)
        {
            Console.WriteLine($"[BMW TLS] Handshake failed: {ex.Message}");
        }
        finally
        {
            await sslStream.DisposeAsync();
        }
    }

    private sealed class SslDuplexPipe(PipeReader reader, PipeWriter writer) : IDuplexPipe
    {
        public PipeReader Input => reader;
        public PipeWriter Output => writer;
    }

    private sealed class TlsFeature(SslStream ssl) : ITlsConnectionFeature
    {
        public System.Security.Cryptography.X509Certificates.X509Certificate2? ClientCertificate
        {
            get => ssl.RemoteCertificate as System.Security.Cryptography.X509Certificates.X509Certificate2;
            set { }
        }

        public Task<System.Security.Cryptography.X509Certificates.X509Certificate2?> GetClientCertificateAsync(CancellationToken ct)
            => Task.FromResult(ClientCertificate);
    }
}

/// <summary>
/// Combines a read-only stream and a write-only stream into a single bidirectional stream.
/// </summary>
internal sealed class DuplexStream(Stream readStream, Stream writeStream) : Stream
{
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) => readStream.Read(buffer, offset, count);
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => readStream.ReadAsync(buffer, offset, count, ct);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => readStream.ReadAsync(buffer, ct);

    public override void Write(byte[] buffer, int offset, int count) => writeStream.Write(buffer, offset, count);
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) => writeStream.WriteAsync(buffer, offset, count, ct);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default) => writeStream.WriteAsync(buffer, ct);

    public override void Flush() => writeStream.Flush();
    public override Task FlushAsync(CancellationToken ct) => writeStream.FlushAsync(ct);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
