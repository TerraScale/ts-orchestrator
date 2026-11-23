namespace TsOrch.Cli;

internal static class LogsCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("node", null, true), new("tail", null, true), new("follow", 'f', false)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(1, "ts-orch logs <service> [--node ID] [--tail N] [-f]") switch
        {
            Done => arguments.Int("tail", 100, 0, 10_000) switch
            {
                int tail => await StreamAsync(arguments, tail, environment, cancellationToken),
                Validation failure => environment.Fail(failure),
            },
            Validation failure => environment.Fail(failure),
        };

    public static string Path(string service, string? node, int tail, bool follow) =>
        Query.Build(
            "/api/logs",
            ("service", service),
            ("node", node),
            ("tail", Display.Integer(tail)),
            ("follow", follow ? "1" : null));

    private static async Task<int> StreamAsync(CliArguments arguments, int tail, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var node = arguments.Value("node");
        var output = environment.Out;
        return await environment.Api.StreamAsync(
            Path(arguments.Positionals[0], node, tail, arguments.Flag("follow")),
            CliJsonContext.Default.LogLine,
            async (line, token) =>
            {
                await output.WriteLineAsync((node is null ? $"{line.NodeId} | {line.Line}" : line.Line).AsMemory(), token);
                await output.FlushAsync(token);
            },
            cancellationToken) switch
        {
            Done => ExitCodes.Ok,
            Validation failure => environment.Fail(failure),
            NotFound failure => environment.Fail(failure),
            Unauthorized failure => environment.Fail(failure),
            Forbidden failure => environment.Fail(failure),
            Unavailable failure => environment.Fail(failure),
        };
    }
}
