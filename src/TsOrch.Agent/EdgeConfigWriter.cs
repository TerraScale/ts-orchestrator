using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace TsOrch.Agent;

public sealed class EdgeConfigWriter(RouteObserver routes, IOptions<AgentOptions> options, ILogger<EdgeConfigWriter> logger)
{
    private readonly AgentOptions _options = options.Value;
    private long _tlsRevision = long.MinValue;

    public async ValueTask WriteRoutesAsync(SyncRoutes message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (routes.Current is { } current && current.Revision > message.Revision)
        {
            logger.StaleRoutesIgnored(message.Revision, current.Revision);
            return;
        }

        var snapshot = new EdgeRoutesSnapshot(message.Revision, message.HttpRoutes, message.PostgresRoutes);
        try
        {
            await UnixFiles.WriteAtomicAsync(
                _options.RoutesFile,
                JsonSerializer.SerializeToUtf8Bytes(snapshot, EdgeJsonContext.Default.EdgeRoutesSnapshot),
                UnixFiles.WorldReadable,
                cancellationToken);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            logger.EdgeWriteFailed(_options.RoutesFile, exception.Message);
            return;
        }

        routes.TryPublish(snapshot);
        logger.RoutesWritten(message.Revision);
    }

    public async ValueTask WriteTlsAsync(SyncTls message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (message.Revision < Interlocked.Read(ref _tlsRevision))
        {
            logger.StaleTlsIgnored(message.Revision);
            return;
        }

        var bundle = new TlsBundle(message.Domains, message.CertPem, message.KeyPem, message.NotAfter);
        try
        {
            UnixFiles.CreatePrivateDirectory(_options.TlsDirectory);
            await UnixFiles.WriteAtomicAsync(
                _options.TlsKeyFile,
                Encoding.UTF8.GetBytes(message.KeyPem),
                UnixFiles.OwnerReadWrite,
                cancellationToken);
            await UnixFiles.WriteAtomicAsync(
                _options.TlsCertificateFile,
                Encoding.UTF8.GetBytes(message.CertPem),
                UnixFiles.OwnerReadWrite,
                cancellationToken);
            await UnixFiles.WriteAtomicAsync(
                _options.TlsBundleFile,
                JsonSerializer.SerializeToUtf8Bytes(bundle, EdgeJsonContext.Default.TlsBundle),
                UnixFiles.OwnerReadWrite,
                cancellationToken);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            logger.EdgeWriteFailed(_options.TlsBundleFile, exception.Message);
            return;
        }

        Interlocked.Exchange(ref _tlsRevision, message.Revision);
        logger.TlsWritten(message.Revision);
    }
}
