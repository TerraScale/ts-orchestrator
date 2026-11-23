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

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch edge [options]") switch
        {
            Done => Configure(arguments) switch
            {
                EdgeServerOptions options => await ServeAsync(options, environment, cancellationToken),
                Validation failure => environment.Fail(failure),
            },
            Validation failure => environment.Fail(failure),
        };

    private static async Task<int> ServeAsync(EdgeServerOptions options, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        environment.Error.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"ts-orch edge: {options.BindAddress} http:{options.HttpPort} https:{options.HttpsPort} postgres:{options.PostgresPort} routes:{options.RoutesFile} tls:{options.TlsDirectory}"));
        await EdgeServer.RunAsync(options, cancellationToken);
        return ExitCodes.Ok;
    }

    private static Result<EdgeServerOptions, Validation> Configure(CliArguments arguments)
    {
        List<Validation> failures = [];
        var runtimeDirectory = arguments.Setting("runtime-dir", "TS_ORCH_RUNTIME_DIR");
        if (runtimeDirectory is not null && !Path.IsPathRooted(runtimeDirectory))
        {
            failures.Add(new Validation($"runtime directory must be an absolute path, got '{runtimeDirectory}'."));
        }

        var bind = arguments.Setting("bind", "TS_ORCH_EDGE_BIND");
        if (bind is not null && !IPAddress.TryParse(bind, out _))
        {
            failures.Add(new Validation($"edge bind address must be an IP address, got '{bind}'."));
        }

        var httpPort = Number(arguments.Setting("http-port", "TS_ORCH_EDGE_HTTP_PORT"), "http port", 1, IPEndPoint.MaxPort, failures);
        var httpsPort = Number(arguments.Setting("https-port", "TS_ORCH_EDGE_HTTPS_PORT"), "https port", 1, IPEndPoint.MaxPort, failures);
        var postgresPort = Number(arguments.Setting("postgres-port", "TS_ORCH_EDGE_POSTGRES_PORT"), "postgres port", 1, IPEndPoint.MaxPort, failures);
        var drainSeconds = Number(arguments.Setting("drain-seconds", "TS_ORCH_EDGE_DRAIN_SECONDS"), "drain seconds", 0, 3_600, failures);
        var shutdownSeconds = Number(arguments.Setting("shutdown-seconds", "TS_ORCH_EDGE_SHUTDOWN_SECONDS"), "shutdown seconds", 0, 3_600, failures);
        var http3 = Flag(arguments.Setting("http3", "TS_ORCH_EDGE_HTTP3"), "http3", failures);
        if (failures is [var first, ..])
        {
            return first;
        }

        var defaults = new EdgeServerOptions();
        return defaults with
        {
            RoutesFile = runtimeDirectory is null ? defaults.RoutesFile : Path.Combine(runtimeDirectory, Path.GetFileName(NodePaths.RoutesFile)),
            TlsDirectory = runtimeDirectory is null ? defaults.TlsDirectory : Path.Combine(runtimeDirectory, Path.GetFileName(NodePaths.TlsDirectory)),
            MetricsFile = runtimeDirectory is null ? defaults.MetricsFile : Path.Combine(runtimeDirectory, Path.GetFileName(NodePaths.EdgeMetricsFile)),
            BindAddress = bind ?? defaults.BindAddress,
            HttpPort = httpPort ?? defaults.HttpPort,
            HttpsPort = httpsPort ?? defaults.HttpsPort,
            PostgresPort = postgresPort ?? defaults.PostgresPort,
            DrainDelay = drainSeconds is { } drain ? TimeSpan.FromSeconds(drain) : defaults.DrainDelay,
            ShutdownTimeout = shutdownSeconds is { } shutdown ? TimeSpan.FromSeconds(shutdown) : defaults.ShutdownTimeout,
            EnableHttp3 = http3 ?? defaults.EnableHttp3,
        };
    }

    private static int? Number(string? text, string label, int min, int max, List<Validation> failures) =>
        text is null
            ? null
            : CliArguments.ParseInt(label, text, min, max) switch
            {
                int value => value,
                Validation failure => RejectNumber(failures, failure),
            };

    private static bool? Flag(string? text, string label, List<Validation> failures) =>
        text is null
            ? null
            : CliArguments.ParseBool(label, text) switch
            {
                bool value => value,
                Validation failure => RejectFlag(failures, failure),
            };

    private static int? RejectNumber(List<Validation> failures, Validation failure)
    {
        failures.Add(failure);
        return null;
    }

    private static bool? RejectFlag(List<Validation> failures, Validation failure)
    {
        failures.Add(failure);
        return null;
    }
}
