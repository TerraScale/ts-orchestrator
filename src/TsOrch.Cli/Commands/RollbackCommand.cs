namespace TsOrch.Cli;

internal static class RollbackCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("region", null, true)];

    public static async Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (!arguments.ExpectPositionals(1, "ts-orch rollback <service> [--region R]").TryGetValue(out _, out var usageError))
        {
            return usageError;
        }

        var rolledBack = await environment.Api.PostAsync(
            "/api/rollback",
            new RollbackRequest(arguments.Positionals[0], arguments.Value("region")),
            ApiJsonContext.Default.RollbackRequest,
            ApiJsonContext.Default.RolloutInfo,
            cancellationToken);
        if (!rolledBack.TryGetValue(out var rollout, out var error))
        {
            return error;
        }

        environment.Out.WriteLine(RolloutStates.Describe(rollout));
        return ExitCodes.Ok;
    }
}
