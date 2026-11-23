using System.Net;

namespace TsOrch.Cli;

internal sealed record class CliDiagnostic(string Code, string Message, int ExitCode)
{
    public static CliDiagnostic Usage(string message) => new("validation", message, ExitCodes.Usage);

    public static CliDiagnostic Missing(string message) => new("not_found", message, ExitCodes.Failure);

    public static CliDiagnostic Permission(string message) => new("unauthorized", message, ExitCodes.NoPermission);

    public static CliDiagnostic Unavailable(string message) => new("unavailable", message, ExitCodes.ServiceUnavailable);

    public static CliDiagnostic From(BackplaneProblem failure, bool unexpectedConflict = false) => failure switch
    {
        BackplaneRequestRejected { Status: HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableContent } rejected => Usage(rejected.Message),
        BackplaneRequestRejected { Status: HttpStatusCode.Unauthorized } rejected => Permission(rejected.Message),
        BackplaneRequestRejected { Status: HttpStatusCode.Forbidden } rejected => new("forbidden", rejected.Message, ExitCodes.NoPermission),
        BackplaneRequestRejected { Status: HttpStatusCode.NotFound } rejected => Missing(rejected.Message),
        BackplaneRequestRejected { Status: HttpStatusCode.Conflict } rejected => unexpectedConflict
            ? Unavailable($"The backplane answered a read with an unexpected conflict: {rejected.Message}")
            : new("conflict", rejected.Message, ExitCodes.Failure),
        BackplaneRequestRejected rejected => Unavailable(rejected.Message),
        BackplaneTransportFailed transport => Unavailable(transport.Message),
        BackplaneResponseInvalid invalid => Unavailable(invalid.Message),
        BackplaneAuthenticationFailed auth => auth.Diagnostic,
    };
}

internal sealed record class CommandEnvironment(string CommandName, CliConsole Console, TimeProvider TimeProvider, OrchHttp Http, OrchApi Api)
{
    public TextWriter Out => Console.Out;

    public TextWriter Error => Console.Error;

    public int Fail(CliDiagnostic failure)
    {
        Error.WriteLine($"ts-orch {CommandName}: {failure.Message}");
        return failure.ExitCode;
    }

    public int Fail(BackplaneProblem failure) => Fail(CliDiagnostic.From(failure));

    public int FailRead(BackplaneProblem failure) => Fail(CliDiagnostic.From(failure, unexpectedConflict: true));

    public int Usage(string message) => Fail(CliDiagnostic.Usage(message));
}

internal sealed record class CliCommand(
    string Name,
    string Usage,
    string Summary,
    IReadOnlyList<CliOption> Options,
    Func<CliArguments, CommandEnvironment, CancellationToken, Task<int>> RunAsync,
    bool InteractiveSigning = true);

internal readonly record struct CommandPositionalsAccepted;

internal sealed record class CommandPositionalsInvalid(string Usage);

internal readonly union CommandPositionals(CommandPositionalsAccepted, CommandPositionalsInvalid);

internal static class CommandArguments
{
    extension(CliArguments arguments)
    {
        public CommandPositionals ExpectPositionals(int count, string usage) =>
            arguments.Positionals.Count == count && arguments.Trailing.Count == 0
                ? new CommandPositionalsAccepted()
                : new CommandPositionalsInvalid(usage);
    }
}
