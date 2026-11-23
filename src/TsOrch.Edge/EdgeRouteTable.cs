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
    private long? _acknowledgedRevision;

    public bool HasLoadedRoutes => !ReferenceEquals(Current, EdgeRouteSnapshot.Empty);

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
        if (stamp.Exists && stamp != _stamp)
        {
            _stamp = stamp;
            await LoadAsync(cancellationToken);
        }

        var snapshot = Current;
        if (HasLoadedRoutes && _acknowledgedRevision != snapshot.Revision)
        {
            if (await AcknowledgeAsync(snapshot.Revision, cancellationToken))
            {
                _acknowledgedRevision = snapshot.Revision;
            }
        }
    }

    private async Task LoadAsync(CancellationToken cancellationToken)
    {
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

    private async Task<bool> AcknowledgeAsync(long revision, CancellationToken cancellationToken)
    {
        var path = Path.Join(Path.GetDirectoryName(options.RoutesFile), NodePaths.AppliedRoutesFileName);
        var temporary = path + ".tmp";
        var document = new EdgeAppliedRoutes(revision, timeProvider.GetUtcNow().ToUnixTimeMilliseconds());
        try
        {
            await File.WriteAllBytesAsync(temporary, JsonSerializer.SerializeToUtf8Bytes(document, EdgeJsonContext.Default.EdgeAppliedRoutes), cancellationToken);
            File.Move(temporary, path, overwrite: true);
            return true;
        }
        catch (IOException exception)
        {
            LogAcknowledgementFailed(logger, revision, exception);
            return false;
        }
        catch (UnauthorizedAccessException exception)
        {
            LogAcknowledgementFailed(logger, revision, exception);
            return false;
        }
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "Could not acknowledge applied edge routes revision {Revision}")]
    private static partial void LogAcknowledgementFailed(ILogger logger, long revision, Exception exception);

    [LoggerMessage(Level = LogLevel.Information, Message = "Loaded edge routes revision {Revision}: {HttpRoutes} HTTP, {PostgresRoutes} Postgres")]
    private static partial void LogRoutesLoaded(ILogger logger, long revision, int httpRoutes, int postgresRoutes);

    [LoggerMessage(Level = LogLevel.Error, Message = "Rejected edge routes file {Path}; keeping the previous routes")]
    private static partial void LogRoutesRejected(ILogger logger, string path, Exception exception);

    [LoggerMessage(Level = LogLevel.Error, Message = "Edge routes file {Path} holds a null document; keeping the previous routes")]
    private static partial void LogRoutesEmpty(ILogger logger, string path);
}
