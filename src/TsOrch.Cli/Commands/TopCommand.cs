using static System.FormattableString;

namespace TsOrch.Cli;

internal static class TopCommand
{
    private const string ClearScreen = "\u001b[H\u001b[2J";
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(2);

    public static IReadOnlyList<CliOption> Options { get; } = [new("region", null, true), new("once", null, false)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch top [--region R] [--once]") switch
        {
            Done => await WatchAsync(Query.Build("/api/top", ("region", arguments.Value("region"))), !arguments.Flag("once"), environment, cancellationToken),
            Validation failure => environment.Fail(failure),
        };

    private static async Task<int> WatchAsync(string path, bool live, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(RefreshInterval, environment.TimeProvider);
        do
        {
            var exitCode = await environment.Api.GetAsync(path, ApiJsonContext.Default.TopResponse, cancellationToken) switch
            {
                TopResponse top => Show(top, live, environment),
                Validation failure => environment.Fail(failure),
                NotFound failure => environment.Fail(failure),
                Unauthorized failure => environment.Fail(failure),
                Forbidden failure => environment.Fail(failure),
                Unavailable failure => environment.Fail(failure),
            };
            if (exitCode is { } failed)
            {
                return failed;
            }

            await environment.Out.FlushAsync(cancellationToken);
        }
        while (live && await timer.WaitForNextTickAsync(cancellationToken));

        return ExitCodes.Ok;
    }

    private static int? Show(TopResponse top, bool live, CommandEnvironment environment)
    {
        if (live && environment.Console.OutputIsTerminal)
        {
            environment.Out.Write(ClearScreen);
        }

        Render(top, environment.Out);
        return null;
    }

    private static void Render(TopResponse top, TextWriter output)
    {
        output.WriteLine($"ts-orch top  {Display.Time(top.Ts)}  {top.Nodes.Count} node(s)");
        output.WriteLine();
        var table = new TextTable("NODE", "CPU%", "CPU PSI", "MEM MiB", "MEM PSI", "DISK%", "NET RX", "NET TX", "RPS", "P95 ms", "5XX%", "CONTAINERS");
        foreach (var node in top.Nodes)
        {
            var edge = node.Edge?.Services ?? [];
            var requests = edge.Sum(static service => service.Requests);
            var failures = edge.Sum(static service => service.Responses5xx);
            table.Add(
                node.NodeId,
                Display.Fixed(node.CpuPct),
                Display.Fixed(node.CpuPsi10),
                Display.Integer(node.MemUsedMiB),
                Display.Fixed(node.MemPsi10),
                Display.Fixed(node.DiskUsedPct),
                Display.Rate(node.NetRxBps),
                Display.Rate(node.NetTxBps),
                node.Edge is null ? "-" : Display.Fixed(edge.Sum(static service => service.Rps)),
                edge.Count == 0 ? "-" : Display.Fixed(edge.Max(static service => service.P95Ms)),
                requests == 0 ? "-" : Invariant($"{failures * 100.0 / requests:F2}"),
                Display.Integer(node.Containers.Count));
        }

        table.WriteTo(output);
    }
}
