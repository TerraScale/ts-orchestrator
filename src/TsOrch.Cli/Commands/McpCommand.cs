namespace TsOrch.Cli;

internal static class McpCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [];

    public static async Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (!arguments.ExpectPositionals(0, "ts-orch mcp").TryGetValue(out _, out var usageError))
        {
            return usageError;
        }

        await environment.Error.WriteLineAsync($"ts-orch mcp {CliApp.Version}: serving read-only tools on stdio".AsMemory(), cancellationToken);
        await new McpServer(new McpTools(environment.Api), environment.Console).RunAsync(cancellationToken);
        return ExitCodes.Ok;
    }
}
