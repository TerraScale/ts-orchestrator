namespace TsOrch.Cli;

internal sealed record class CommandEnvironment(CliConsole Console, TimeProvider TimeProvider, OrchHttp Http, OrchApi Api)
{
    public TextWriter Out => Console.Out;

    public TextWriter Error => Console.Error;
}

internal sealed record class CliCommand(
    string Name,
    string Usage,
    string Summary,
    IReadOnlyList<CliOption> Options,
    Func<CliArguments, CommandEnvironment, CancellationToken, Task<OrchResult<int>>> RunAsync,
    bool InteractiveSigning = true);

internal static class CommandArguments
{
    extension(CliArguments arguments)
    {
        public OrchResult<Done> ExpectPositionals(int count, string usage) =>
            arguments.Positionals.Count == count && arguments.Trailing.Count == 0
                ? new Done()
                : new Validation($"usage: {usage}");
    }
}
