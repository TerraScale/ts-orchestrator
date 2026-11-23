namespace TsOrch.Cli;

internal sealed record class CommandEnvironment(string CommandName, CliConsole Console, TimeProvider TimeProvider, OrchHttp Http, OrchApi Api)
{
    public TextWriter Out => Console.Out;

    public TextWriter Error => Console.Error;

    public int Fail(NotFound failure) => Report(failure.Message, ExitCodes.Failure);

    public int Fail(Validation failure) => Report(failure.Message, ExitCodes.Usage);

    public int Fail(Conflict failure) => Report(failure.Message, ExitCodes.Failure);

    public int Fail(Unauthorized failure) => Report(failure.Message, ExitCodes.NoPermission);

    public int Fail(Forbidden failure) => Report(failure.Message, ExitCodes.NoPermission);

    public int Fail(Unavailable failure) => Report(failure.Message, ExitCodes.ServiceUnavailable);

    public int Fail(RequestTimeout failure) => Report(failure.Message, ExitCodes.ServiceUnavailable);

    public int Fail(InternalFailure failure) => Report(failure.Message, ExitCodes.InternalError);

    private int Report(string message, int exitCode)
    {
        Error.WriteLine($"ts-orch {CommandName}: {message}");
        return exitCode;
    }
}

internal sealed record class CliCommand(
    string Name,
    string Usage,
    string Summary,
    IReadOnlyList<CliOption> Options,
    Func<CliArguments, CommandEnvironment, CancellationToken, Task<int>> RunAsync,
    bool InteractiveSigning = true);

internal static class CommandArguments
{
    extension(CliArguments arguments)
    {
        public Result<Done, Validation> ExpectPositionals(int count, string usage) =>
            arguments.Positionals.Count == count && arguments.Trailing.Count == 0
                ? new Done()
                : new Validation($"usage: {usage}");
    }
}
