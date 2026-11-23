using static System.FormattableString;

namespace TsOrch.Cli;

internal static class TopCommand
{
    private const string ClearScreen = "\u001b[H\u001b[2J";
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(2);

    public static IReadOnlyList<CliOption> Options { get; } = [new("region", null, true), new("once", null, false)];

    public static async Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (!arguments.ExpectPositionals(0, "ts-orch top [--region R] [--once]").TryGetValue(out _, out var usageError))
        {
            return usageError;
        }

        var path = Query.Build("/api/top", ("region", arguments.Value("region")));
        var live = !arguments.Flag("once");
        using var timer = new PeriodicTimer(RefreshInterval, environment.TimeProvider);
        do
        {
            var result = await environment.Api.GetAsync(path, ApiJsonContext.Default.TopResponse, cancellationToken);
            if (!result.TryGetValue(out var top, out var error))
            {
                return error;
            }

            if (live && environment.Console.OutputIsTerminal)
            {
                environment.Out.Write(ClearScreen);
            }

            Render(top, environment.Out);
            await environment.Out.FlushAsync(cancellationToken);
        }
        while (live && await timer.WaitForNextTickAsync(cancellationToken));

        return ExitCodes.Ok;
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
