namespace TsOrch.Edge;

public sealed partial class EdgeDrainCoordinator(
    EdgeServerOptions options,
    TimeProvider timeProvider,
    ILogger<EdgeDrainCoordinator> logger) : IHostedLifecycleService
{
    public const string ReadinessPath = "/readyz";

    private int _draining;

    public bool IsDraining => Volatile.Read(ref _draining) == 1;

    public static bool IsReadinessProbe(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method))
            && request.Path.Equals(ReadinessPath, StringComparison.Ordinal);
    }

    public Task WriteReadinessAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        context.Response.Headers.CacheControl = "no-store";
        context.Response.StatusCode = IsDraining ? StatusCodes.Status503ServiceUnavailable : StatusCodes.Status200OK;
        return HttpMethods.IsHead(context.Request.Method)
            ? Task.CompletedTask
            : context.Response.WriteAsync(IsDraining ? "draining" : "ok", context.RequestAborted);
    }

    public void BeginDrain()
    {
        if (Interlocked.Exchange(ref _draining, 1) == 0)
        {
            LogDrainStarted(logger, options.DrainDelay);
        }
    }

    public async Task StoppingAsync(CancellationToken cancellationToken)
    {
        BeginDrain();
        await Task.Delay(options.DrainDelay, timeProvider, cancellationToken);
    }

    public Task StartingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    [LoggerMessage(Level = LogLevel.Warning, Message = "Edge draining: /readyz now returns 503; serving live traffic for {DrainDelay} before Kestrel drains")]
    private static partial void LogDrainStarted(ILogger logger, TimeSpan drainDelay);
}
