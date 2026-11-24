using System.Globalization;
using System.Net;
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
        builder.Services.AddTsOrchEdge(options);
        builder.Services.Configure<HostOptions>(host => host.ShutdownTimeout = options.DrainDelay + options.ShutdownTimeout);
        if (options.EnableHttp3)
        {
            builder.WebHost.UseQuic();
        }

        builder.WebHost.ConfigureKestrel(kestrel => ConfigureKestrel(kestrel, options));

        var app = builder.Build();
        var drain = app.Services.GetRequiredService<EdgeDrainCoordinator>();
        var proxy = app.Services.GetRequiredService<EdgeProxy>();
        app.UseWebSockets();
        app.Run(context => DispatchAsync(context, options, drain, proxy));
        return app;
    }

    public static async Task RunAsync(EdgeServerOptions options, CancellationToken cancellationToken)
    {
        await using var app = Build(options);
        await app.RunAsync(cancellationToken);
    }

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
        kestrel.Limits.MaxRequestBodySize = null;
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
