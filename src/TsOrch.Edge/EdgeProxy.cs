using System.Diagnostics;
using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.Http.Features;
using Yarp.ReverseProxy.Forwarder;

namespace TsOrch.Edge;

public sealed partial class EdgeProxy(
    EdgeServerOptions options,
    EdgeRouteTable routes,
    UpstreamCircuitBreaker circuitBreaker,
    EdgeMetricsCollector metrics,
    IHttpForwarder forwarder,
    TimeProvider timeProvider,
    ILogger<EdgeProxy> logger) : IDisposable
{
    private const string EventStreamMediaType = "text/event-stream";

    private static readonly ForwarderRequestConfig RequestConfig = new()
    {
        ActivityTimeout = TimeSpan.FromSeconds(100),
        Version = HttpVersion.Version11,
        VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
    };

    private static readonly ForwarderRequestConfig InternalHttp2RequestConfig = new()
    {
        ActivityTimeout = TimeSpan.FromSeconds(100),
        Version = HttpVersion.Version20,
        VersionPolicy = HttpVersionPolicy.RequestVersionExact,
    };

    private static readonly ForwarderRequestConfig GrpcRequestConfig = new()
    {
        ActivityTimeout = Timeout.InfiniteTimeSpan,
        Version = HttpVersion.Version20,
        VersionPolicy = HttpVersionPolicy.RequestVersionExact,
    };

    private static readonly ForwarderRequestConfig EventStreamRequestConfig = new()
    {
        ActivityTimeout = TimeSpan.FromMinutes(5),
        Version = HttpVersion.Version11,
        VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
    };

    private static readonly ForwarderRequestConfig WebSocketRequestConfig = new()
    {
        ActivityTimeout = Timeout.InfiniteTimeSpan,
        Version = HttpVersion.Version11,
        VersionPolicy = HttpVersionPolicy.RequestVersionExact,
    };

    private readonly string _altSvcHeader = string.Create(CultureInfo.InvariantCulture, $"h3=\":{options.HttpsPort}\"; ma=86400");

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

    public Task ForwardAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (options.EnableHttp3 && context.Connection.LocalPort == options.HttpsPort)
        {
            context.Response.OnStarting(static state =>
            {
                var (httpContext, headerValue) = ((HttpContext, string))state;
                httpContext.Response.Headers.AltSvc = headerValue;
                return Task.CompletedTask;
            }, (context, _altSvcHeader));
        }

        var outcome = routes.ResolveHttpRoute(context.Request.Host.Host, context.Request.Method, context.Request.Path, context.Request.ContentType);
        return outcome switch
        {
            EdgeRoute route => ForwardMatchedAsync(context, route, forceHttp2: false),
            EdgeRouteBlocked => Respond(context, StatusCodes.Status403Forbidden),
            EdgeRouteNotFound => Respond(context, StatusCodes.Status404NotFound),
        };
    }

    public Task ForwardInternalAsync(HttpContext context, string serviceName, bool http2Upstream)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!IsPrivateAddress(context.Connection.RemoteIpAddress))
        {
            return Respond(context, StatusCodes.Status403Forbidden);
        }

        return routes.Current.FindInternalRoute(serviceName) is { } route
            ? ForwardMatchedAsync(context, route, forceHttp2: http2Upstream)
            : Respond(context, StatusCodes.Status503ServiceUnavailable);
    }

    internal static bool IsPrivateAddress(IPAddress? remote)
    {
        if (remote is null)
        {
            return false;
        }

        var address = remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote;
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        Span<byte> octets = stackalloc byte[4];
        if (!address.TryWriteBytes(octets, out var written) || written != 4)
        {
            return false;
        }

        return octets[0] == 10
            || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
            || (octets[0] == 192 && octets[1] == 168);
    }

    internal static bool IsEventStreamRequest(HttpRequest request)
    {
        foreach (var accept in request.Headers.Accept)
        {
            if (AcceptsEventStream(accept))
            {
                return true;
            }
        }

        return false;
    }

    private static bool AcceptsEventStream(ReadOnlySpan<char> accept)
    {
        foreach (var range in accept.Split(','))
        {
            var mediaRange = accept[range];
            var parametersStart = mediaRange.IndexOf(';');
            var mediaType = parametersStart < 0 ? mediaRange.Trim() : mediaRange[..parametersStart].Trim();
            if (mediaType.Equals(EventStreamMediaType, StringComparison.OrdinalIgnoreCase)
                && (parametersStart < 0 || HasNonZeroQuality(mediaRange[(parametersStart + 1)..])))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasNonZeroQuality(ReadOnlySpan<char> parameters)
    {
        foreach (var range in parameters.Split(';'))
        {
            var parameter = parameters[range];
            var separator = parameter.IndexOf('=');
            if (separator > 0 && parameter[..separator].Trim().Equals("q", StringComparison.OrdinalIgnoreCase))
            {
                return !double.TryParse(parameter[(separator + 1)..].Trim(), NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var quality)
                    || quality > 0;
            }
        }

        return true;
    }

    private static bool IsEventStreamResponse(HttpResponse response) =>
        response.ContentType?.StartsWith(EventStreamMediaType, StringComparison.OrdinalIgnoreCase) is true;

    private static Task Respond(HttpContext context, int statusCode)
    {
        context.Response.StatusCode = statusCode;
        return Task.CompletedTask;
    }

    private async Task ForwardMatchedAsync(HttpContext context, EdgeRoute route, bool forceHttp2)
    {
        var config = EdgeRouteSnapshot.IsGrpc(context.Request.ContentType)
            ? GrpcRequestConfig
            : forceHttp2
                ? InternalHttp2RequestConfig
                : context.WebSockets.IsWebSocketRequest
                    ? WebSocketRequestConfig
                    : IsEventStreamRequest(context.Request) ? EventStreamRequestConfig : RequestConfig;
        var startedAt = timeProvider.GetTimestamp();
        metrics.RequestStarted(route.ServiceName);
        try
        {
            await ForwardToRouteAsync(context, route, config);
        }
        finally
        {
            metrics.RequestCompleted(
                route.ServiceName,
                context.Response.StatusCode,
                timeProvider.GetElapsedTime(startedAt),
                recordLatency: !ReferenceEquals(config, GrpcRequestConfig)
                    && !ReferenceEquals(config, WebSocketRequestConfig)
                    && !IsEventStreamResponse(context.Response));
        }
    }

    public void Dispose() => _invoker.Dispose();

    private async Task ForwardToRouteAsync(HttpContext context, EdgeRoute route, ForwarderRequestConfig config)
    {
        if (circuitBreaker.Select(route.Upstreams, []) is not { } first)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return;
        }

        if (route.Upstreams.Length < 2 || ReferenceEquals(config, GrpcRequestConfig) || IsRetryable(context) is false)
        {
            await ForwardOnceAsync(context, first, config, retry: null);
            return;
        }

        var retry = new EdgeRetryFeature { InterceptBadGateway = true };
        context.Features.Set(retry);
        if (await ForwardOnceAsync(context, first, config, retry) is ForwardOutcome.Completed)
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
        await ForwardOnceAsync(context, sibling, config, retry);
    }

    private async Task<ForwardOutcome> ForwardOnceAsync(HttpContext context, EdgeUpstream upstream, ForwarderRequestConfig config, EdgeRetryFeature? retry)
    {
        retry?.BadGatewayIntercepted = false;
        ForwarderError error;
        using (circuitBreaker.Acquire(upstream))
        {
            error = await forwarder.SendAsync(context, upstream.DestinationPrefix, _invoker, config, EdgeHttpTransformer.Instance);
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
