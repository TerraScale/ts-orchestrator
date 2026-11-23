using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.Http.Features;
using Yarp.ReverseProxy.Forwarder;

namespace TsOrch.Edge;

public sealed partial class EdgeProxy(
    EdgeRouteTable routes,
    UpstreamCircuitBreaker circuitBreaker,
    EdgeMetricsCollector metrics,
    IHttpForwarder forwarder,
    TimeProvider timeProvider,
    ILogger<EdgeProxy> logger) : IDisposable
{
    private static readonly ForwarderRequestConfig RequestConfig = new()
    {
        ActivityTimeout = TimeSpan.FromSeconds(100),
        Version = HttpVersion.Version11,
        VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
    };

    private readonly HttpMessageInvoker _invoker = new(
        new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            EnableMultipleHttp2Connections = true,
            ConnectTimeout = TimeSpan.FromSeconds(3),
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(90),
            ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current),
        },
        disposeHandler: true);

    public async Task ForwardAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (routes.Current.FindHttpRoute(context.Request.Host.Host) is not { } route)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var startedAt = timeProvider.GetTimestamp();
        metrics.RequestStarted(route.ServiceName);
        try
        {
            await ForwardToRouteAsync(context, route);
        }
        finally
        {
            metrics.RequestCompleted(
                route.ServiceName,
                context.Response.StatusCode,
                timeProvider.GetElapsedTime(startedAt),
                recordLatency: !context.WebSockets.IsWebSocketRequest);
        }
    }

    public void Dispose() => _invoker.Dispose();

    private async Task ForwardToRouteAsync(HttpContext context, EdgeRoute route)
    {
        if (circuitBreaker.Select(route.Upstreams, []) is not { } first)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return;
        }

        if (route.Upstreams.Length < 2 || !IsRetryable(context))
        {
            await ForwardOnceAsync(context, first, retry: null);
            return;
        }

        var retry = new EdgeRetryFeature { InterceptBadGateway = true };
        context.Features.Set(retry);
        if (await ForwardOnceAsync(context, first, retry) is ForwardOutcome.Completed)
        {
            return;
        }

        if (circuitBreaker.Select(route.Upstreams, [first]) is not { } sibling)
        {
            context.Response.StatusCode = StatusCodes.Status502BadGateway;
            return;
        }

        LogRetrying(logger, route.ServiceName, first.DestinationPrefix, sibling.DestinationPrefix);
        retry.InterceptBadGateway = false;
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Features.Set<IForwarderErrorFeature>(null);
        await ForwardOnceAsync(context, sibling, retry);
    }

    private async Task<ForwardOutcome> ForwardOnceAsync(HttpContext context, EdgeUpstream upstream, EdgeRetryFeature? retry)
    {
        retry?.BadGatewayIntercepted = false;
        ForwarderError error;
        using (circuitBreaker.Acquire(upstream))
        {
            error = await forwarder.SendAsync(context, upstream.DestinationPrefix, _invoker, RequestConfig, EdgeHttpTransformer.Instance);
        }

        var interceptedBadGateway = retry is { BadGatewayIntercepted: true };
        if (IsUpstreamFailure(error) || interceptedBadGateway || (error == ForwarderError.None && context.Response.StatusCode == StatusCodes.Status502BadGateway))
        {
            circuitBreaker.ReportFailure(upstream);
        }
        else if (error == ForwarderError.None)
        {
            circuitBreaker.ReportSuccess(upstream);
        }

        if (error != ForwarderError.None)
        {
            LogForwardFailed(logger, upstream.DestinationPrefix, error, context.Features.Get<IForwarderErrorFeature>()?.Exception);
        }

        var retryable = retry is not null
            && !context.Response.HasStarted
            && (interceptedBadGateway || error is ForwarderError.Request or ForwarderError.RequestTimedOut);
        return retryable ? ForwardOutcome.RetrySibling : ForwardOutcome.Completed;
    }

    private static bool IsRetryable(HttpContext context) =>
        (HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method))
        && !context.Features.GetRequiredFeature<IHttpRequestBodyDetectionFeature>().CanHaveBody;

    private static bool IsUpstreamFailure(ForwarderError error) => error switch
    {
        ForwarderError.None => false,
        ForwarderError.Request => true,
        ForwarderError.RequestTimedOut => true,
        ForwarderError.RequestCanceled => false,
        ForwarderError.RequestBodyCanceled => false,
        ForwarderError.RequestBodyClient => false,
        ForwarderError.RequestBodyDestination => true,
        ForwarderError.ResponseHeaders => false,
        ForwarderError.ResponseBodyCanceled => false,
        ForwarderError.ResponseBodyClient => false,
        ForwarderError.ResponseBodyDestination => true,
        ForwarderError.UpgradeRequestCanceled => false,
        ForwarderError.UpgradeRequestClient => false,
        ForwarderError.UpgradeRequestDestination => true,
        ForwarderError.UpgradeResponseCanceled => false,
        ForwarderError.UpgradeResponseClient => false,
        ForwarderError.UpgradeResponseDestination => true,
        ForwarderError.NoAvailableDestinations => false,
        ForwarderError.RequestCreation => false,
        ForwarderError.UpgradeActivityTimeout => false,
        _ => throw new UnreachableException(),
    };

    [LoggerMessage(Level = LogLevel.Warning, Message = "Retrying {ServiceName} request from {Failed} on sibling {Sibling}")]
    private static partial void LogRetrying(ILogger logger, string serviceName, string failed, string sibling);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Forwarding to {Destination} failed with {Error}")]
    private static partial void LogForwardFailed(ILogger logger, string destination, ForwarderError error, Exception? exception);

    private enum ForwardOutcome
    {
        Completed,
        RetrySibling,
    }
}
