namespace TsOrch.Cli;

internal static class DeployCommand
{
    private const string UsageText = "ts-orch deploy <service> <image> [--region R] [--wait]";

    public static IReadOnlyList<CliOption> Options { get; } = [new("region", null, true), new("wait", null, false)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(2, UsageText) switch
        {
            CommandPositionalsAccepted => await environment.Api.PostAsync(
                "/api/deploy",
                new DeployRequest(arguments.Positionals[0], arguments.Positionals[1], arguments.Value("region")),
                ApiJsonContext.Default.DeployRequest,
                ApiJsonContext.Default.RolloutInfo,
                rollout => StartedAsync(rollout, arguments.Flag("wait"), environment, cancellationToken), environment.Fail, cancellationToken),
            CommandPositionalsInvalid invalid => environment.Usage($"usage: {invalid.Usage}"),
        };

    private static async Task<int> StartedAsync(RolloutInfo rollout, bool wait, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        environment.Out.WriteLine(RolloutStates.Describe(rollout));
        return wait ? await RolloutStates.WaitForRolloutAsync(rollout.Id, rollout, environment, cancellationToken) : ExitCodes.Ok;
    }
}
