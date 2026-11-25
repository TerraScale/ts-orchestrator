using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Microsoft.AspNetCore.Connections;

namespace TsOrch.Edge;

public sealed partial class PostgresSniConnectionHandler(
    EdgeRouteTable routes,
    TlsCertificateStore certificates,
    UpstreamCircuitBreaker circuitBreaker,
    EdgeMetricsCollector metrics,
    TimeProvider timeProvider,
    ILogger<PostgresSniConnectionHandler> logger) : ConnectionHandler
{
    private const int MaxConnections = 1_024;
    private const int MaxConnectionsPerPeer = 128;
    private const int MaxHandshakes = 128;
    private const int MaxHandshakesPerPeer = 32;
    private const int CopyBufferSize = 16 * 1024;
    private const int NegotiationLength = 8;
    private const int SslRequestCode = 80877103;
    private const int GssEncRequestCode = 80877104;
    private const byte TlsHandshakeRecord = 0x16;

    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan IdleCheckInterval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan AdmissionWarningInterval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(3);
    private static readonly byte[] SslAccepted = [(byte)'S'];
    private static readonly byte[] EncryptionDeclined = [(byte)'N'];
    private static readonly byte[] TlsRequiredError = BuildErrorResponse(
        "28000",
        "ts-orch edge requires TLS with SNI for Postgres connections; connect with sslmode=require or stronger");

    private readonly Lock _connectionGate = new();
    private readonly Dictionary<IPAddress, AdmissionCounts> _admissionByPeer = [];
    private AdmissionCounts _admission;
    private long? _lastAdmissionWarning;

    public override async Task OnConnectedAsync(ConnectionContext connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (connection.RemoteEndPoint is not IPEndPoint remote)
        {
            return;
        }

        var peer = remote.Address.IsIPv4MappedToIPv6 ? remote.Address.MapToIPv4() : remote.Address;
        if (!TryAdmit(peer))
        {
            return;
        }

        metrics.PostgresConnectionOpened();
        try
        {
            var outcome = await NegotiateAsync(connection, peer);
            await (outcome switch
            {
                NegotiationRejected rejected => RejectAsync(connection, rejected),
                TlsSessionNegotiated negotiated => ForwardAsync(connection, negotiated),
            });
        }
        catch (OperationCanceledException) when (connection.ConnectionClosed.IsCancellationRequested)
        {
            LogClientClosed(logger, connection.ConnectionId);
        }
        finally
        {
            metrics.PostgresConnectionClosed();
            ReleaseConnection(peer);
        }
    }

    private bool TryAdmit(IPAddress peer)
    {
        AdmissionCounts total;
        AdmissionCounts peerCounts;
        lock (_connectionGate)
        {
            total = _admission;
            peerCounts = _admissionByPeer.GetValueOrDefault(peer);
            if (total.Connections < MaxConnections && peerCounts.Connections < MaxConnectionsPerPeer
                && total.Handshakes < MaxHandshakes && peerCounts.Handshakes < MaxHandshakesPerPeer)
            {
                _admission = new(total.Connections + 1, total.Handshakes + 1);
                _admissionByPeer[peer] = new(peerCounts.Connections + 1, peerCounts.Handshakes + 1);
                return true;
            }

            var now = timeProvider.GetTimestamp();
            if (_lastAdmissionWarning is { } last && timeProvider.GetElapsedTime(last, now) < AdmissionWarningInterval)
            {
                return false;
            }

            _lastAdmissionWarning = now;
        }

        LogAdmissionRejected(logger, total.Connections, peerCounts.Connections, total.Handshakes, peerCounts.Handshakes);
        return false;
    }

    private void ReleaseHandshake(IPAddress peer)
    {
        lock (_connectionGate)
        {
            var peerCounts = _admissionByPeer[peer];
            _admissionByPeer[peer] = peerCounts with { Handshakes = peerCounts.Handshakes - 1 };
            _admission = _admission with { Handshakes = _admission.Handshakes - 1 };
        }
    }

    private void ReleaseConnection(IPAddress peer)
    {
        lock (_connectionGate)
        {
            var peerCounts = _admissionByPeer[peer];
            if (peerCounts.Connections == 1)
            {
                _admissionByPeer.Remove(peer);
            }
            else
            {
                _admissionByPeer[peer] = peerCounts with { Connections = peerCounts.Connections - 1 };
            }

            _admission = _admission with { Connections = _admission.Connections - 1 };
        }
    }

    private Task RejectAsync(ConnectionContext connection, NegotiationRejected rejected)
    {
        LogNegotiationRejected(logger, connection.ConnectionId, rejected.Reason);
        return Task.CompletedTask;
    }

    private async Task<Negotiation> NegotiateAsync(ConnectionContext connection, IPAddress peer)
    {
        using var timeout = new CancellationTokenSource(HandshakeTimeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, connection.ConnectionClosed);
        try
        {
            var sslReady = await NegotiatePostgresTlsAsync(connection.Transport, linked.Token);
            if (sslReady is not null)
            {
                return sslReady;
            }

            return await AuthenticateClientTlsAsync(connection.Transport, linked.Token);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !connection.ConnectionClosed.IsCancellationRequested)
        {
            return new NegotiationRejected("client did not complete TLS handshake before the timeout");
        }
        finally
        {
            ReleaseHandshake(peer);
        }
    }

    private static async Task<NegotiationRejected?> NegotiatePostgresTlsAsync(IDuplexPipe transport, CancellationToken cancellationToken)
    {
        var input = transport.Input;
        while (true)
        {
            var read = await input.ReadAsync(cancellationToken);
            var buffer = read.Buffer;
            if (!buffer.IsEmpty && buffer.FirstSpan[0] == TlsHandshakeRecord)
            {
                input.AdvanceTo(buffer.Start);
                return null;
            }

            if (buffer.Length < NegotiationLength)
            {
                input.AdvanceTo(buffer.Start, buffer.End);
                if (read.IsCompleted)
                {
                    return new NegotiationRejected("client closed during Postgres negotiation");
                }

                continue;
            }

            var (length, code) = ReadNegotiation(buffer);
            if (length != NegotiationLength || code is not (SslRequestCode or GssEncRequestCode))
            {
                input.AdvanceTo(buffer.Start);
                await transport.Output.WriteAsync(TlsRequiredError, cancellationToken);
                return new NegotiationRejected("client did not request TLS");
            }

            input.AdvanceTo(buffer.GetPosition(NegotiationLength));
            var accepted = code == SslRequestCode;
            await transport.Output.WriteAsync(accepted ? SslAccepted : EncryptionDeclined, cancellationToken);
            if (accepted)
            {
                return null;
            }
        }
    }

    private async Task<Negotiation> AuthenticateClientTlsAsync(IDuplexPipe transport, CancellationToken cancellationToken)
    {
        var duplex = new DuplexPipeStream(transport);
        var sslStream = new SslStream(duplex, leaveInnerStreamOpen: true);
        var transferred = false;
        string? serverName = null;
        try
        {
            await sslStream.AuthenticateAsServerAsync(
                (_, clientHelloInfo, _, _) =>
                {
                    serverName = clientHelloInfo.ServerName;
                    var serverOptions = certificates.CreateServerOptions();
                    serverOptions.ApplicationProtocols = [new SslApplicationProtocol("postgresql")];
                    return ValueTask.FromResult(serverOptions);
                },
                null,
                cancellationToken);
            if (serverName is null || !TlsClientHello.IsValidServerName(serverName))
            {
                return new NegotiationRejected("TLS ClientHello requires a valid SNI hostname");
            }

            transferred = true;
            return new TlsSessionNegotiated(serverName, sslStream, duplex);
        }
        catch (Exception exception) when (exception is AuthenticationException or IOException or InvalidOperationException)
        {
            return new NegotiationRejected("TLS handshake failed");
        }
        finally
        {
            if (!transferred)
            {
                await sslStream.DisposeAsync();
                await duplex.DisposeAsync();
            }
        }
    }

    private static (int Length, int Code) ReadNegotiation(ReadOnlySequence<byte> buffer)
    {
        Span<byte> header = stackalloc byte[NegotiationLength];
        buffer.Slice(0, NegotiationLength).CopyTo(header);
        return (BinaryPrimitives.ReadInt32BigEndian(header), BinaryPrimitives.ReadInt32BigEndian(header[4..]));
    }

    private async Task ForwardAsync(ConnectionContext connection, TlsSessionNegotiated negotiated)
    {
        await using (negotiated.Duplex)
        await using (negotiated.TlsStream)
        {
            if (routes.Current.FindPostgresRoute(negotiated.ServerName) is not { } route)
            {
                LogNoRoute(logger, connection.ConnectionId, negotiated.ServerName);
                return;
            }

            if (await ConnectAsync(route, connection.ConnectionClosed) is not { } upstream)
            {
                LogNoUpstream(logger, connection.ConnectionId, route.ServiceName);
                return;
            }

            await using (upstream.Stream)
            using (circuitBreaker.Acquire(upstream.Upstream))
            {
                await PumpAsync(negotiated.TlsStream, upstream, connection.ConnectionClosed);
            }
        }
    }

    private async Task<UpstreamConnection?> ConnectAsync(EdgeRoute route, CancellationToken cancellationToken)
    {
        var failed = new EdgeUpstream[route.Upstreams.Length];
        var failedCount = 0;
        while (circuitBreaker.Select(route.Upstreams, failed.AsSpan(0, failedCount)) is { } upstream)
        {
            if (await TryConnectAsync(upstream, cancellationToken) is { } connection)
            {
                circuitBreaker.ReportSuccess(upstream);
                return connection;
            }

            circuitBreaker.ReportFailure(upstream);
            failed[failedCount++] = upstream;
        }

        return null;
    }

    private async Task<UpstreamConnection?> TryConnectAsync(EdgeUpstream upstream, CancellationToken cancellationToken)
    {
        Socket? socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        NetworkStream? stream = null;
        try
        {
            using var timeout = new CancellationTokenSource(ConnectTimeout, timeProvider);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, cancellationToken);
            await socket.ConnectAsync(upstream.Address, upstream.Port, linked.Token);
            stream = new NetworkStream(socket, ownsSocket: true);
            var connection = new UpstreamConnection(upstream, socket, stream);
            socket = null;
            stream = null;
            return connection;
        }
        catch (Exception exception) when (exception is SocketException or IOException
            || (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            LogUpstreamConnectFailed(logger, upstream.Address, upstream.Port, exception);
            return null;
        }
        finally
        {
            if (stream is not null)
            {
                await stream.DisposeAsync();
            }
            else
            {
                socket?.Dispose();
            }
        }
    }

    private async Task PumpAsync(SslStream client, UpstreamConnection upstream, CancellationToken cancellationToken)
    {
        using var abort = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var lastActivity = timeProvider.GetTimestamp();
        await using var idle = timeProvider.CreateTimer(_ =>
        {
            if (timeProvider.GetElapsedTime(Volatile.Read(ref lastActivity)) >= IdleTimeout)
            {
                abort.Cancel();
            }
        }, null, IdleTimeout, IdleCheckInterval);

        void MarkActivity() => Volatile.Write(ref lastActivity, timeProvider.GetTimestamp());

        await Task.WhenAll(
            CopyStreamAsync(client, upstream.Stream, () => HalfClose(upstream.Socket), abortWhenDone: false, MarkActivity, abort),
            CopyStreamAsync(upstream.Stream, client, static () => { }, abortWhenDone: true, MarkActivity, abort));
    }

    private static void HalfClose(Socket socket)
    {
        try
        {
            socket.Shutdown(SocketShutdown.Send);
        }
        catch (Exception exception) when (exception is SocketException or ObjectDisposedException)
        {
        }
    }

    private static async Task CopyStreamAsync(
        Stream source,
        Stream destination,
        Action halfClose,
        bool abortWhenDone,
        Action markActivity,
        CancellationTokenSource abort)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        try
        {
            var memory = buffer.AsMemory(0, CopyBufferSize);
            while (await source.ReadAsync(memory, abort.Token) is var read && read > 0)
            {
                await destination.WriteAsync(memory[..read], abort.Token);
                markActivity();
            }

            await destination.FlushAsync(abort.Token);
            halfClose();
            if (abortWhenDone)
            {
                await abort.CancelAsync();
            }
        }
        catch (Exception exception) when (exception is IOException or SocketException or ObjectDisposedException)
        {
            await abort.CancelAsync();
        }
        catch (OperationCanceledException) when (abort.IsCancellationRequested)
        {
            await abort.CancelAsync();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static byte[] BuildErrorResponse(string sqlState, string message)
    {
        var body = new ArrayBufferWriter<byte>();
        WriteField(body, 'S', "FATAL");
        WriteField(body, 'V', "FATAL");
        WriteField(body, 'C', sqlState);
        WriteField(body, 'M', message);
        body.Write([(byte)0]);
        var response = new byte[1 + sizeof(int) + body.WrittenCount];
        response[0] = (byte)'E';
        BinaryPrimitives.WriteInt32BigEndian(response.AsSpan(1), sizeof(int) + body.WrittenCount);
        body.WrittenSpan.CopyTo(response.AsSpan(1 + sizeof(int)));
        return response;
    }

    private static void WriteField(ArrayBufferWriter<byte> writer, char code, string value)
    {
        writer.Write([(byte)code]);
        writer.Write(Encoding.UTF8.GetBytes(value));
        writer.Write([(byte)0]);
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Postgres admission rejected at a connection or handshake limit. Connections: {Connections} total, {PeerConnections} for peer. Handshakes: {Handshakes} total, {PeerHandshakes} for peer.")]
    private static partial void LogAdmissionRejected(ILogger logger, int connections, int peerConnections, int handshakes, int peerHandshakes);

    [LoggerMessage(Level = LogLevel.Information, Message = "Postgres connection {ConnectionId} rejected: {Reason}")]
    private static partial void LogNegotiationRejected(ILogger logger, string connectionId, string reason);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Postgres connection {ConnectionId} closed by the client or shutdown")]
    private static partial void LogClientClosed(ILogger logger, string connectionId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Postgres connection {ConnectionId} names unknown SNI host {ServerName}")]
    private static partial void LogNoRoute(ILogger logger, string connectionId, string serverName);

    [LoggerMessage(Level = LogLevel.Error, Message = "Postgres connection {ConnectionId} found no reachable upstream for {ServiceName}")]
    private static partial void LogNoUpstream(ILogger logger, string connectionId, string serviceName);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Postgres upstream {Address}:{Port} connect failed")]
    private static partial void LogUpstreamConnectFailed(ILogger logger, string address, int port, Exception exception);

    private readonly record struct AdmissionCounts(int Connections, int Handshakes);

    private closed record class Negotiation;

    private sealed record class TlsSessionNegotiated(string ServerName, SslStream TlsStream, DuplexPipeStream Duplex) : Negotiation;

    private sealed record class NegotiationRejected(string Reason) : Negotiation;

    private sealed record class UpstreamConnection(EdgeUpstream Upstream, Socket Socket, NetworkStream Stream);

    private sealed class DuplexPipeStream(IDuplexPipe pipe) : Stream
    {
        private readonly Stream _input = pipe.Input.AsStream(leaveOpen: true);
        private readonly Stream _output = pipe.Output.AsStream(leaveOpen: true);

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => _output.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => _output.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count) => _input.Read(buffer, offset, count);

        public override int Read(Span<byte> buffer) => _input.Read(buffer);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            _input.ReadAsync(buffer, offset, count, cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            _input.ReadAsync(buffer, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count) => _output.Write(buffer, offset, count);

        public override void Write(ReadOnlySpan<byte> buffer) => _output.Write(buffer);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            _output.WriteAsync(buffer, offset, count, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
            _output.WriteAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _input.Dispose();
                _output.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await _input.DisposeAsync();
            await _output.DisposeAsync();
            await base.DisposeAsync();
        }
    }
}
