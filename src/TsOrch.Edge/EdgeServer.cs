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
        app.Run(context => EdgeDrainCoordinator.IsReadinessProbe(context.Request)
            ? drain.WriteReadinessAsync(context)
            : proxy.ForwardAsync(context));
        return app;
    }

    public static async Task RunAsync(EdgeServerOptions options, CancellationToken cancellationToken)
    {
        await using var app = Build(options);
        await app.RunAsync(cancellationToken);
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
    }
}
