namespace TsOrch.Cli;

internal static class RemoteExecCommand
{
    private const int MaxTimeoutSeconds = 120;
    private static readonly TimeSpan ResponseAllowance = TimeSpan.FromSeconds(15);

    public static IReadOnlyList<CliOption> Options { get; } = [new("timeout", null, true)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (arguments.Positionals is not [var nodeId, var service] || arguments.Trailing.Count == 0)
        {
            return environment.Fail(new Validation("usage: ts-orch exec <node> <service> [--timeout S] -- <cmd...>"));
        }

        return arguments.Int("timeout", 30, 1, MaxTimeoutSeconds) switch
        {
            int timeoutSeconds => await ExecuteAsync(new ExecRequest(nodeId, service, arguments.Trailing, timeoutSeconds), environment, cancellationToken),
            Validation failure => environment.Fail(failure),
        };
    }

    private static async Task<int> ExecuteAsync(ExecRequest request, CommandEnvironment environment, CancellationToken cancellationToken) =>
        await environment.Api.PostAsync(
            "/api/exec",
            request,
            ApiJsonContext.Default.ExecRequest,
            ApiJsonContext.Default.ExecResponse,
            TimeSpan.FromSeconds(request.TimeoutSeconds) + ResponseAllowance,
            cancellationToken) switch
        {
            ExecResponse response => await PrintAsync(response, environment, cancellationToken),
            Validation failure => environment.Fail(failure),
            NotFound failure => environment.Fail(failure),
            Conflict failure => environment.Fail(failure),
            Unauthorized failure => environment.Fail(failure),
            Forbidden failure => environment.Fail(failure),
            Unavailable failure => environment.Fail(failure),
        };

    private static async Task<int> PrintAsync(ExecResponse response, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        await environment.Out.WriteAsync(response.Stdout.AsMemory(), cancellationToken);
        await environment.Error.WriteAsync(response.Stderr.AsMemory(), cancellationToken);
        await environment.Out.FlushAsync(cancellationToken);
        await environment.Error.FlushAsync(cancellationToken);
        return response.ExitCode;
    }
}
