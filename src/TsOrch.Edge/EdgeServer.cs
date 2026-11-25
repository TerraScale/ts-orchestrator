using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace TsOrch.Edge;

public static class EdgeServer
{
    public static WebApplication Build(EdgeServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var builder = WebApplication.CreateSlimBuilder();
        builder.Services.PostConfigure<LoggerFilterOptions>(ConfigureLogging);
        builder.Services.AddTsOrchEdge(options);
        builder.Services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, (bool Exempt, IPAddress? Peer)>(context =>
            {
                var port = context.Connection.LocalPort;
                if ((options.InternalTerraBasePort > 0 && port == options.InternalTerraBasePort)
                    || (options.InternalPlatformPort > 0 && port == options.InternalPlatformPort)
                    || (port == options.HttpPort && EdgeDrainCoordinator.IsReadinessProbe(context.Request)))
                {
                    return RateLimitPartition.GetNoLimiter<(bool Exempt, IPAddress? Peer)>((true, null));
                }

                return RateLimitPartition.GetTokenBucketLimiter((false, RateLimitPeer(context.Connection.RemoteIpAddress)),
                    static _ => new TokenBucketRateLimiterOptions
                    {
                        TokenLimit = 1_500,
                        TokensPerPeriod = 75,
                        ReplenishmentPeriod = TimeSpan.FromMilliseconds(100),
                        AutoReplenishment = false,
                        QueueLimit = 0,
                    });
            });
        });
        builder.Services.Configure<HostOptions>(host => host.ShutdownTimeout = options.DrainDelay + options.ShutdownTimeout);
        builder.WebHost.UseKestrelHttpsConfiguration();
        if (options.EnableHttp3)
        {
            builder.WebHost.UseQuic();
        }

        builder.WebHost.ConfigureKestrel(kestrel => ConfigureKestrel(kestrel, options));

        var app = builder.Build();
        var drain = app.Services.GetRequiredService<EdgeDrainCoordinator>();
        var proxy = app.Services.GetRequiredService<EdgeProxy>();
        app.UseRateLimiter();
        app.UseWebSockets();
        app.Run(context => DispatchAsync(context, options, drain, proxy));
        return app;
    }

    public static async Task RunAsync(EdgeServerOptions options, CancellationToken cancellationToken)
    {
        await using var app = Build(options);
        await app.RunAsync(cancellationToken);
    }

    private static IPAddress? RateLimitPeer(IPAddress? address)
    {
        if (address is not { AddressFamily: AddressFamily.InterNetworkV6 })
        {
            return address;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            return address.MapToIPv4();
        }

        Span<byte> prefix = stackalloc byte[16];
        address.TryWriteBytes(prefix, out _);
        prefix[8..].Clear();
        return new IPAddress(prefix);
    }

    private static void ConfigureLogging(LoggerFilterOptions filters)
    {
        filters.Rules.Insert(0, new LoggerFilterRule(null, null, filters.MinLevel, null));
        for (var index = 0; index < filters.Rules.Count; index++)
        {
            var rule = filters.Rules[index];
            filters.Rules[index] = new LoggerFilterRule(rule.ProviderName, rule.CategoryName, rule.LogLevel,
                (provider, category, level) => AllowsFrameworkLog(category, level)
                    && (rule.Filter is not { } filter || filter(provider, category, level)));
        }
    }

    private static bool AllowsFrameworkLog(string? category, LogLevel level) =>
        category is null || (!category.StartsWith("Yarp", StringComparison.OrdinalIgnoreCase)
            && !category.StartsWith("Microsoft.AspNetCore.Hosting.Diagnostics", StringComparison.OrdinalIgnoreCase)
            && !category.StartsWith("Microsoft.AspNetCore.HttpLogging", StringComparison.OrdinalIgnoreCase)
            && (level >= LogLevel.Warning || !category.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase)));

    private static Task DispatchAsync(HttpContext context, EdgeServerOptions options, EdgeDrainCoordinator drain, EdgeProxy proxy)
    {
        var localPort = context.Connection.LocalPort;
        if (options.InternalTerraBasePort > 0 && localPort == options.InternalTerraBasePort)
        {
            return proxy.ForwardInternalAsync(context, "terrabase", http2Upstream: true);
        }

        if (options.InternalPlatformPort > 0 && localPort == options.InternalPlatformPort)
        {
            return proxy.ForwardInternalAsync(context, "ts-platform", http2Upstream: false);
        }

        if (drain.IsReadinessRequest(context))
        {
            return drain.WriteReadinessAsync(context);
        }

        if (options.RedirectHttpToHttps && localPort == options.HttpPort)
        {
            return RedirectToHttps(context, options.HttpsPort);
        }

        return proxy.ForwardAsync(context);
    }

    private static Task RedirectToHttps(HttpContext context, int httpsPort)
    {
        var host = context.Request.Host.Host;
        if (string.IsNullOrWhiteSpace(host))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return Task.CompletedTask;
        }

        var authority = httpsPort == 443 ? host : string.Create(CultureInfo.InvariantCulture, $"{host}:{httpsPort}");
        var location = $"https://{authority}{context.Request.PathBase}{context.Request.Path}{context.Request.QueryString}";
        context.Response.StatusCode = StatusCodes.Status308PermanentRedirect;
        context.Response.Headers.Location = location;
        return Task.CompletedTask;
    }

    private static void ConfigureKestrel(KestrelServerOptions kestrel, EdgeServerOptions options)
    {
        kestrel.AddServerHeader = false;
        kestrel.Limits.MaxConcurrentConnections = 8_192;
        kestrel.Limits.MaxConcurrentUpgradedConnections = 2_048;
        kestrel.Limits.Http2.MaxStreamsPerConnection = 100;
        kestrel.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
        kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(15);
        kestrel.Limits.MaxRequestBodySize = 128L * 1024 * 1024;
        var address = IPAddress.Parse(options.BindAddress);
        var certificates = kestrel.ApplicationServices.GetRequiredService<TlsCertificateStore>();

        kestrel.Listen(address, options.HttpPort, listen => listen.Protocols = HttpProtocols.Http1);
        kestrel.Listen(address, options.HttpsPort, listen =>
        {
            listen.Protocols = options.EnableHttp3 ? HttpProtocols.Http1AndHttp2AndHttp3 : HttpProtocols.Http1AndHttp2;
            listen.UseHttps(new TlsHandshakeCallbackOptions
            {
                OnConnection = _ => ValueTask.FromResult(certificates.CreateServerOptions()),
            });
        });
        kestrel.Listen(address, options.PostgresPort, listen => listen.UseConnectionHandler<PostgresSniConnectionHandler>());
        if (options.InternalTerraBasePort > 0)
        {
            kestrel.Listen(address, options.InternalTerraBasePort, listen => listen.Protocols = HttpProtocols.Http2);
        }

        if (options.InternalPlatformPort > 0)
        {
            kestrel.Listen(address, options.InternalPlatformPort, listen => listen.Protocols = HttpProtocols.Http1);
        }
    }
}
