namespace TsOrch.Cli;

internal static class RollbackCommand
{
    public static IReadOnlyList<CliOption> Options { get; } = [new("region", null, true)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(1, "ts-orch rollback <service> [--region R]") switch
        {
            Done => await environment.Api.PostAsync(
                "/api/rollback",
                new RollbackRequest(arguments.Positionals[0], arguments.Value("region")),
                ApiJsonContext.Default.RollbackRequest,
                ApiJsonContext.Default.RolloutInfo,
                cancellationToken) switch
            {
                RolloutInfo rollout => Report(rollout, environment.Out),
                Validation failure => environment.Fail(failure),
                NotFound failure => environment.Fail(failure),
                Conflict failure => environment.Fail(failure),
                Unauthorized failure => environment.Fail(failure),
                Forbidden failure => environment.Fail(failure),
                Unavailable failure => environment.Fail(failure),
            },
            Validation failure => environment.Fail(failure),
        };

    private static int Report(RolloutInfo rollout, TextWriter output)
    {
        output.WriteLine(RolloutStates.Describe(rollout));
        return ExitCodes.Ok;
    }
}
