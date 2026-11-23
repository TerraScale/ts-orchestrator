namespace TsOrch.Cli;

internal static class McpCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(0, "ts-orch mcp") switch
        {
            CommandPositionalsAccepted => await ServeAsync(environment, cancellationToken),
            CommandPositionalsInvalid invalid => environment.Usage($"usage: {invalid.Usage}"),
        };

    private static async Task<int> ServeAsync(CommandEnvironment environment, CancellationToken cancellationToken)
    {
        await environment.Error.WriteLineAsync($"ts-orch mcp {CliApp.Version}: serving read-only tools on stdio".AsMemory(), cancellationToken);
        await new McpServer(new McpTools(environment.Api), environment.Console).RunAsync(cancellationToken);
        return ExitCodes.Ok;
    }
}
