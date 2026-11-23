namespace TsOrch.Cli;

internal static class RollbackCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("region", null, true)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(1, "ts-orch rollback <service> [--region R]") switch
        {
            CommandPositionalsAccepted => await environment.Api.PostAsync(
                "/api/rollback",
                new RollbackRequest(arguments.Positionals[0], arguments.Value("region")),
                ApiJsonContext.Default.RollbackRequest,
                ApiJsonContext.Default.RolloutInfo,
                rollout => Task.FromResult(Report(rollout, environment.Out)), environment.Fail, cancellationToken),
            CommandPositionalsInvalid invalid => environment.Usage($"usage: {invalid.Usage}"),
        };

    private static int Report(RolloutInfo rollout, TextWriter output)
    {
        output.WriteLine(RolloutStates.Describe(rollout));
        return ExitCodes.Ok;
    }
}
