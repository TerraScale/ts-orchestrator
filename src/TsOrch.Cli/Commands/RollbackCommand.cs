namespace TsOrch.Cli;

internal static class RollbackCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("region", null, true), new("wait", null, false)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(1, "ts-orch rollback <service> [--region R] [--wait]") switch
        {
            CommandPositionalsAccepted => await environment.Api.PostAsync(
                "/api/rollback",
                new RollbackRequest(arguments.Positionals[0], arguments.Value("region")),
                ApiJsonContext.Default.RollbackRequest,
                ApiJsonContext.Default.RolloutInfo,
                rollout => CompletedAsync(rollout, arguments.Value("region"), arguments.Flag("wait"), environment, cancellationToken), environment.Fail, cancellationToken),
            CommandPositionalsInvalid invalid => environment.Usage($"usage: {invalid.Usage}"),
        };

    private static async Task<int> CompletedAsync(RolloutInfo rollout, string? region, bool wait, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        environment.Out.WriteLine(RolloutStates.Describe(rollout));
        return wait && rollout.PreviousImage is { Length: > 0 } previous
            ? await RolloutStates.WaitForImageConvergenceAsync(rollout.ServiceName, previous, region ?? rollout.Region, environment, cancellationToken)
            : ExitCodes.Ok;
    }
}
