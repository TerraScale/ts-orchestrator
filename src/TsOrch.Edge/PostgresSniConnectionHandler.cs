using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Connections;

namespace TsOrch.Edge;

public sealed partial class PostgresSniConnectionHandler(
    EdgeRouteTable routes,
    UpstreamCircuitBreaker circuitBreaker,
    EdgeMetricsCollector metrics,
    TimeProvider timeProvider,
    ILogger<PostgresSniConnectionHandler> logger) : ConnectionHandler
{
    private const int NegotiationLength = 8;
    private const int SslRequestCode = 80877103;
    private const int GssEncRequestCode = 80877104;
    private const byte TlsHandshakeRecord = 0x16;
    private const int MaxClientHelloBytes = 80 * 1024;

    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(3);
    private static readonly byte[] SslRequest = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
    private static readonly byte[] SslAccepted = [(byte)'S'];
    private static readonly byte[] EncryptionDeclined = [(byte)'N'];
    private static readonly byte[] TlsRequiredError = BuildErrorResponse(
        "28000",
        "ts-orch edge routes Postgres by TLS SNI; connect with sslmode=require or stronger");

    public override async Task OnConnectedAsync(ConnectionContext connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        metrics.PostgresConnectionOpened();
        try
        {
            await (await NegotiateAsync(connection) switch
            {
                NegotiationRejected rejected => RejectAsync(connection, rejected),
                SniNegotiated negotiated => ForwardAsync(connection, negotiated.ServerName),
            });
        }
        catch (OperationCanceledException) when (connection.ConnectionClosed.IsCancellationRequested)
        {
            LogClientClosed(logger, connection.ConnectionId);
        }
        finally
        {
            metrics.PostgresConnectionClosed();
        }
    }

    private Task RejectAsync(ConnectionContext connection, NegotiationRejected rejected)
    {
        LogNegotiationRejected(logger, connection.ConnectionId, rejected.Reason);
        return Task.CompletedTask;
    }

    private async Task<Negotiation> NegotiateAsync(ConnectionContext connection)
    {
        using var timeout = new CancellationTokenSource(HandshakeTimeout, timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token, connection.ConnectionClosed);
        try
        {
            return await ReadClientHelloAsync(connection.Transport, linked.Token);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !connection.ConnectionClosed.IsCancellationRequested)
        {
            return new NegotiationRejected("client sent no TLS ClientHello before the handshake timeout");
        }
    }

    private static async Task<Negotiation> ReadClientHelloAsync(IDuplexPipe transport, CancellationToken cancellationToken)
    {
        var input = transport.Input;
        var tlsAccepted = false;
        while (true)
        {
            var read = await input.ReadAsync(cancellationToken);
            var buffer = read.Buffer;
            if (!tlsAccepted && !buffer.IsEmpty && buffer.FirstSpan[0] != TlsHandshakeRecord)
            {
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
                tlsAccepted = code == SslRequestCode;
                await transport.Output.WriteAsync(tlsAccepted ? SslAccepted : EncryptionDeclined, cancellationToken);
                continue;
            }

            var status = TlsClientHello.TryReadServerName(buffer, out var serverName);
            input.AdvanceTo(buffer.Start, status == ClientHelloStatus.NeedMoreData ? buffer.End : buffer.Start);
            if (status == ClientHelloStatus.NeedMoreData && !read.IsCompleted && buffer.Length <= MaxClientHelloBytes)
            {
                continue;
            }

            return status switch
            {
                ClientHelloStatus.Complete when serverName is null => new NegotiationRejected("TLS ClientHello carries no SNI server name"),
                ClientHelloStatus.Complete => new SniNegotiated(serverName),
                ClientHelloStatus.Invalid => new NegotiationRejected("malformed TLS ClientHello"),
                ClientHelloStatus.NeedMoreData => new NegotiationRejected("incomplete TLS ClientHello"),
                _ => throw new UnreachableException(),
            };
        }
    }

    private static (int Length, int Code) ReadNegotiation(ReadOnlySequence<byte> buffer)
    {
        Span<byte> header = stackalloc byte[NegotiationLength];
        buffer.Slice(0, NegotiationLength).CopyTo(header);
        return (BinaryPrimitives.ReadInt32BigEndian(header), BinaryPrimitives.ReadInt32BigEndian(header[4..]));
    }

    private async Task ForwardAsync(ConnectionContext connection, string serverName)
    {
        if (routes.Current.FindPostgresRoute(serverName) is not { } route)
        {
            LogNoRoute(logger, connection.ConnectionId, serverName);
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
            await PumpAsync(connection.Transport, upstream, connection.ConnectionClosed);
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
            await stream.WriteAsync(SslRequest, linked.Token);
            var reply = new byte[1];
            await stream.ReadExactlyAsync(reply, linked.Token);
            if (reply[0] != SslAccepted[0])
            {
                LogUpstreamDeclinedTls(logger, upstream.Address, upstream.Port);
                return null;
            }

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

    private static async Task PumpAsync(IDuplexPipe client, UpstreamConnection upstream, CancellationToken cancellationToken)
    {
        using var abort = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var upstreamReader = PipeReader.Create(upstream.Stream, new StreamPipeReaderOptions(leaveOpen: true));
        var upstreamWriter = PipeWriter.Create(upstream.Stream, new StreamPipeWriterOptions(leaveOpen: true));
        await Task.WhenAll(
            CopyAsync(client.Input, upstreamWriter, () => upstream.Socket.Shutdown(SocketShutdown.Send), abortWhenDone: false, abort),
            CopyAsync(upstreamReader, client.Output, static () => { }, abortWhenDone: true, abort));
    }

    private static async Task CopyAsync(
        PipeReader source,
        PipeWriter destination,
        Action halfClose,
        bool abortWhenDone,
        CancellationTokenSource abort)
    {
        try
        {
            await source.CopyToAsync(destination, abort.Token);
            await destination.CompleteAsync();
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
            await source.CompleteAsync();
            await destination.CompleteAsync();
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

    [LoggerMessage(Level = LogLevel.Information, Message = "Postgres connection {ConnectionId} rejected: {Reason}")]
    private static partial void LogNegotiationRejected(ILogger logger, string connectionId, string reason);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Postgres connection {ConnectionId} closed by the client or shutdown")]
    private static partial void LogClientClosed(ILogger logger, string connectionId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Postgres connection {ConnectionId} names unknown SNI host {ServerName}")]
    private static partial void LogNoRoute(ILogger logger, string connectionId, string serverName);

    [LoggerMessage(Level = LogLevel.Error, Message = "Postgres connection {ConnectionId} found no reachable upstream for {ServiceName}")]
    private static partial void LogNoUpstream(ILogger logger, string connectionId, string serviceName);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Postgres upstream {Address}:{Port} declined TLS negotiation")]
    private static partial void LogUpstreamDeclinedTls(ILogger logger, string address, int port);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Postgres upstream {Address}:{Port} connect failed")]
    private static partial void LogUpstreamConnectFailed(ILogger logger, string address, int port, Exception exception);

    private closed record class Negotiation;

    private sealed record class SniNegotiated(string ServerName) : Negotiation;

    private sealed record class NegotiationRejected(string Reason) : Negotiation;

    private sealed record class UpstreamConnection(EdgeUpstream Upstream, Socket Socket, NetworkStream Stream);
}
