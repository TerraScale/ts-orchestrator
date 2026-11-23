namespace TsOrch.Cli;

internal static class LogsCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("node", null, true), new("tail", null, true), new("follow", 'f', false)];

    public static async Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (!arguments.ExpectPositionals(1, "ts-orch logs <service> [--node ID] [--tail N] [-f]").TryGetValue(out _, out var usageError))
        {
            return usageError;
        }

        if (!arguments.Int("tail", 100, 0, 10_000).TryGetValue(out var tail, out var tailError))
        {
            return tailError;
        }

        var node = arguments.Value("node");
        var output = environment.Out;
        var streamed = await environment.Api.StreamAsync(
            Path(arguments.Positionals[0], node, tail, arguments.Flag("follow")),
            CliJsonContext.Default.LogLine,
            async (line, token) =>
            {
                await output.WriteLineAsync((node is null ? $"{line.NodeId} | {line.Line}" : line.Line).AsMemory(), token);
                await output.FlushAsync(token);
            },
            cancellationToken);
        return streamed switch
        {
            Done => ExitCodes.Ok,
            OrchError error => error,
        };
    }

    public static string Path(string service, string? node, int tail, bool follow) =>
        Query.Build(
            "/api/logs",
            ("service", service),
            ("node", node),
            ("tail", Display.Integer(tail)),
            ("follow", follow ? "1" : null));
}
