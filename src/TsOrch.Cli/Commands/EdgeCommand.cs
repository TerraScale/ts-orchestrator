using System.Globalization;
using System.Net;
using TsOrch.Edge;

namespace TsOrch.Cli;

internal static class EdgeCommand
{
    public static IReadOnlyList<CliOption> Options { get; } =
    [
        new("runtime-dir", null, true),
        new("bind", null, true),
        new("http-port", null, true),
        new("https-port", null, true),
        new("postgres-port", null, true),
        new("drain-seconds", null, true),
        new("shutdown-seconds", null, true),
        new("http3", null, true),
    ];

    public static async Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (!arguments.ExpectPositionals(0, "ts-orch edge [options]").TryGetValue(out _, out var usageError))
        {
            return usageError;
        }

        if (!Configure(arguments).TryGetValue(out var options, out var error))
        {
            return error;
        }

        environment.Error.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"ts-orch edge: {options.BindAddress} http:{options.HttpPort} https:{options.HttpsPort} postgres:{options.PostgresPort} routes:{options.RoutesFile} tls:{options.TlsDirectory}"));
        await EdgeServer.RunAsync(options, cancellationToken);
        return ExitCodes.Ok;
    }

    private static OrchResult<EdgeServerOptions> Configure(CliArguments arguments)
    {
        var options = new EdgeServerOptions();
        if (arguments.Setting("runtime-dir", "TS_ORCH_RUNTIME_DIR") is { } runtimeDirectory)
        {
            if (!Path.IsPathRooted(runtimeDirectory))
            {
                return new Validation($"runtime directory must be an absolute path, got '{runtimeDirectory}'.");
            }

            options = options with
            {
                RoutesFile = Path.Combine(runtimeDirectory, Path.GetFileName(NodePaths.RoutesFile)),
                TlsDirectory = Path.Combine(runtimeDirectory, Path.GetFileName(NodePaths.TlsDirectory)),
                MetricsFile = Path.Combine(runtimeDirectory, Path.GetFileName(NodePaths.EdgeMetricsFile)),
            };
        }

        if (arguments.Setting("bind", "TS_ORCH_EDGE_BIND") is { } bind)
        {
            if (!IPAddress.TryParse(bind, out _))
            {
                return new Validation($"edge bind address must be an IP address, got '{bind}'.");
            }

            options = options with { BindAddress = bind };
        }

        if (arguments.Setting("http-port", "TS_ORCH_EDGE_HTTP_PORT") is { } httpPortText)
        {
            if (!ParsePort("http port", httpPortText).TryGetValue(out var httpPort, out var httpError))
            {
                return httpError;
            }

            options = options with { HttpPort = httpPort };
        }

        if (arguments.Setting("https-port", "TS_ORCH_EDGE_HTTPS_PORT") is { } httpsPortText)
        {
            if (!ParsePort("https port", httpsPortText).TryGetValue(out var httpsPort, out var httpsError))
            {
                return httpsError;
            }

            options = options with { HttpsPort = httpsPort };
        }

        if (arguments.Setting("postgres-port", "TS_ORCH_EDGE_POSTGRES_PORT") is { } postgresPortText)
        {
            if (!ParsePort("postgres port", postgresPortText).TryGetValue(out var postgresPort, out var postgresError))
            {
                return postgresError;
            }

            options = options with { PostgresPort = postgresPort };
        }

        if (arguments.Setting("drain-seconds", "TS_ORCH_EDGE_DRAIN_SECONDS") is { } drainText)
        {
            if (!CliArguments.ParseInt("drain seconds", drainText, 0, 3_600).TryGetValue(out var drainSeconds, out var drainError))
            {
                return drainError;
            }

            options = options with { DrainDelay = TimeSpan.FromSeconds(drainSeconds) };
        }

        if (arguments.Setting("shutdown-seconds", "TS_ORCH_EDGE_SHUTDOWN_SECONDS") is { } shutdownText)
        {
            if (!CliArguments.ParseInt("shutdown seconds", shutdownText, 0, 3_600).TryGetValue(out var shutdownSeconds, out var shutdownError))
            {
                return shutdownError;
            }

            options = options with { ShutdownTimeout = TimeSpan.FromSeconds(shutdownSeconds) };
        }

        if (arguments.Setting("http3", "TS_ORCH_EDGE_HTTP3") is { } http3Text)
        {
            if (!CliArguments.ParseBool("http3", http3Text).TryGetValue(out var http3, out var http3Error))
            {
                return http3Error;
            }

            options = options with { EnableHttp3 = http3 };
        }

        return options;
    }

    private static OrchResult<int> ParsePort(string label, string text) => CliArguments.ParseInt(label, text, 1, IPEndPoint.MaxPort);
}
