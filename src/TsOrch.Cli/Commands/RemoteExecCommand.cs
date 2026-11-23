namespace TsOrch.Cli;

internal static class RemoteExecCommand
{
    private const int MaxTimeoutSeconds = 120;
    private static readonly TimeSpan ResponseAllowance = TimeSpan.FromSeconds(15);

    public static IReadOnlyList<CliOption> Options { get; } = [new("timeout", null, true)];

    public static async Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (arguments.Positionals is not [var nodeId, var service] || arguments.Trailing.Count == 0)
        {
            return new Validation("usage: ts-orch exec <node> <service> [--timeout S] -- <cmd...>");
        }

        if (!arguments.Int("timeout", 30, 1, MaxTimeoutSeconds).TryGetValue(out var timeoutSeconds, out var timeoutError))
        {
            return timeoutError;
        }

        var executed = await environment.Api.PostAsync(
            "/api/exec",
            new ExecRequest(nodeId, service, arguments.Trailing, timeoutSeconds),
            ApiJsonContext.Default.ExecRequest,
            ApiJsonContext.Default.ExecResponse,
            TimeSpan.FromSeconds(timeoutSeconds) + ResponseAllowance,
            cancellationToken);
        if (!executed.TryGetValue(out var response, out var error))
        {
            return error;
        }

        await environment.Out.WriteAsync(response.Stdout.AsMemory(), cancellationToken);
        await environment.Error.WriteAsync(response.Stderr.AsMemory(), cancellationToken);
        await environment.Out.FlushAsync(cancellationToken);
        await environment.Error.FlushAsync(cancellationToken);
        return response.ExitCode;
    }
}
