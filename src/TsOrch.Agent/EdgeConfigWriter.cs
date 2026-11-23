using System.Text;
using System.Text.Json;

namespace TsOrch.Agent;

public sealed class EdgeConfigWriter(RouteObserver routes, AgentOptions options, ILogger<EdgeConfigWriter> logger)
{
    private long _tlsRevision = long.MinValue;

    public async ValueTask WriteRoutesAsync(SyncRoutes message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (routes.Current is { } current && current.Revision > message.Revision)
        {
            AgentLog.StaleRoutesIgnored(logger, message.Revision, current.Revision);
            return;
        }

        var snapshot = new EdgeRoutesSnapshot(message.Revision, message.HttpRoutes, message.PostgresRoutes);
        routes.TryPublish(snapshot);
        var written = await UnixFiles.WriteAtomicAsync(
            options.RoutesFile,
            JsonSerializer.SerializeToUtf8Bytes(snapshot, EdgeJsonContext.Default.EdgeRoutesSnapshot),
            UnixFiles.WorldReadable,
            cancellationToken);
        var failure = written switch
        {
            AtomicWriteCompleted => null,
            AtomicWriteFailed failed => failed.Message,
        };
        if (failure is not null)
        {
            AgentLog.EdgeWriteFailed(logger, options.RoutesFile, failure);
            return;
        }

        AgentLog.RoutesWritten(logger, message.Revision);
    }

    public async ValueTask WriteTlsAsync(SyncTls message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (message.Revision < Interlocked.Read(ref _tlsRevision))
        {
            AgentLog.StaleTlsIgnored(logger, message.Revision);
            return;
        }

        var bundle = new TlsBundle(message.Domains, message.CertPem, message.KeyPem, message.NotAfter);
        var written = await UnixFiles.WriteAtomicAsync(
            [options.TlsDirectory],
            [
                new AtomicWrite(options.TlsKeyFile, Encoding.UTF8.GetBytes(message.KeyPem), UnixFiles.OwnerReadWrite),
                new AtomicWrite(options.TlsCertificateFile, Encoding.UTF8.GetBytes(message.CertPem), UnixFiles.OwnerReadWrite),
                new AtomicWrite(options.TlsBundleFile, JsonSerializer.SerializeToUtf8Bytes(bundle, EdgeJsonContext.Default.TlsBundle), UnixFiles.OwnerReadWrite),
            ],
            cancellationToken);
        var failure = written switch
        {
            AtomicWriteCompleted => null,
            AtomicWriteFailed failed => failed.Message,
        };
        if (failure is not null)
        {
            AgentLog.EdgeWriteFailed(logger, options.TlsBundleFile, failure);
            return;
        }

        Interlocked.Exchange(ref _tlsRevision, message.Revision);
        AgentLog.TlsWritten(logger, message.Revision);
    }
}
