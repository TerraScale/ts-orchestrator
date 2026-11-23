using System.Text.Json;
using TsOrch.Protocol;

namespace TsOrch.Edge;

public sealed partial class EdgeRouteTable(
    EdgeServerOptions options,
    UpstreamCircuitBreaker circuitBreaker,
    TimeProvider timeProvider,
    ILogger<EdgeRouteTable> logger) : BackgroundService
{
    private EdgeRouteSnapshot _current = EdgeRouteSnapshot.Empty;
    private FileStamp _stamp;

    public EdgeRouteSnapshot Current => Volatile.Read(ref _current);

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await ReloadAsync(cancellationToken);
        await base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var directory = Path.GetDirectoryName(options.RoutesFile)
            ?? throw new InvalidOperationException($"Routes file '{options.RoutesFile}' has no parent directory.");
        using var monitor = new FileChangeMonitor(directory, timeProvider);
        await ReloadAsync(stoppingToken);
        await foreach (var _ in monitor.ReadAllAsync(stoppingToken))
        {
            await ReloadAsync(stoppingToken);
        }
    }

    private async Task ReloadAsync(CancellationToken cancellationToken)
    {
        var stamp = FileStamp.Read(options.RoutesFile);
        if (!stamp.Exists || stamp == _stamp)
        {
            return;
        }

        _stamp = stamp;
        EdgeRoutesSnapshot? routes;
        try
        {
            await using var stream = new FileStream(
                options.RoutesFile,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            routes = await JsonSerializer.DeserializeAsync(stream, EdgeJsonContext.Default.EdgeRoutesSnapshot, cancellationToken);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            LogRoutesRejected(logger, options.RoutesFile, exception);
            return;
        }

        if (routes is null)
        {
            LogRoutesEmpty(logger, options.RoutesFile);
            return;
        }

        var snapshot = EdgeRouteSnapshot.From(routes);
        Interlocked.Exchange(ref _current, snapshot);
        circuitBreaker.Retain(snapshot);
        LogRoutesLoaded(logger, snapshot.Revision, snapshot.HttpRoutes.Count, snapshot.PostgresRoutes.Count);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Loaded edge routes revision {Revision}: {HttpRoutes} HTTP, {PostgresRoutes} Postgres")]
    private static partial void LogRoutesLoaded(ILogger logger, long revision, int httpRoutes, int postgresRoutes);

    [LoggerMessage(Level = LogLevel.Error, Message = "Rejected edge routes file {Path}; keeping the previous routes")]
    private static partial void LogRoutesRejected(ILogger logger, string path, Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "Edge routes file {Path} holds a null document; keeping the previous routes")]
    private static partial void LogRoutesEmpty(ILogger logger, string path);
}
