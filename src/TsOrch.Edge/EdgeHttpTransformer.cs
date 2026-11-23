using System.Net;
using Yarp.ReverseProxy.Forwarder;

namespace TsOrch.Edge;

internal sealed class EdgeRetryFeature
{
    public bool InterceptBadGateway { get; set; }

    public bool BadGatewayIntercepted { get; set; }
}

internal sealed class EdgeHttpTransformer : HttpTransformer
{
    private const string ForwardedFor = "X-Forwarded-For";
    private const string ForwardedProto = "X-Forwarded-Proto";
    private const string ForwardedHost = "X-Forwarded-Host";

    public static EdgeHttpTransformer Instance { get; } = new();

    public override async ValueTask TransformRequestAsync(
        HttpContext httpContext,
        HttpRequestMessage proxyRequest,
        string destinationPrefix,
        CancellationToken cancellationToken)
    {
        await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix, cancellationToken);
        var host = httpContext.Request.Host.Value;
        proxyRequest.Headers.Host = host;
        proxyRequest.Headers.Remove(ForwardedFor);
        proxyRequest.Headers.Remove(ForwardedProto);
        proxyRequest.Headers.Remove(ForwardedHost);
        if (httpContext.Connection.RemoteIpAddress is { } remote)
        {
            proxyRequest.Headers.TryAddWithoutValidation(ForwardedFor, (remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote).ToString());
        }

        proxyRequest.Headers.TryAddWithoutValidation(ForwardedProto, httpContext.Request.Scheme);
        if (host is not null)
        {
            proxyRequest.Headers.TryAddWithoutValidation(ForwardedHost, host);
        }
    }

    public override ValueTask<bool> TransformResponseAsync(
        HttpContext httpContext,
        HttpResponseMessage? proxyResponse,
        CancellationToken cancellationToken)
    {
        if (proxyResponse is { StatusCode: HttpStatusCode.BadGateway }
            && httpContext.Features.Get<EdgeRetryFeature>() is { InterceptBadGateway: true } retry)
        {
            retry.BadGatewayIntercepted = true;
            return ValueTask.FromResult(false);
        }

        return base.TransformResponseAsync(httpContext, proxyResponse, cancellationToken);
    }
}
