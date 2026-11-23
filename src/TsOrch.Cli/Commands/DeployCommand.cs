namespace TsOrch.Cli;

internal static class DeployCommand
{
    private const string UsageText = "ts-orch deploy <service> <image> [--region R] [--wait]";
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);

    public static IReadOnlyList<CliOption> Options { get; } = [new("region", null, true), new("wait", null, false)];

    public static async Task<int> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken) =>
        arguments.ExpectPositionals(2, UsageText) switch
        {
            Done => await environment.Api.PostAsync(
                "/api/deploy",
                new DeployRequest(arguments.Positionals[0], arguments.Positionals[1], arguments.Value("region")),
                ApiJsonContext.Default.DeployRequest,
                ApiJsonContext.Default.RolloutInfo,
                cancellationToken) switch
            {
                RolloutInfo rollout => await StartedAsync(rollout, arguments.Flag("wait"), environment, cancellationToken),
                Validation failure => environment.Fail(failure),
                NotFound failure => environment.Fail(failure),
                Conflict failure => environment.Fail(failure),
                Unauthorized failure => environment.Fail(failure),
                Forbidden failure => environment.Fail(failure),
                Unavailable failure => environment.Fail(failure),
            },
            Validation failure => environment.Fail(failure),
        };

    private static async Task<int> StartedAsync(RolloutInfo rollout, bool wait, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        environment.Out.WriteLine(RolloutStates.Describe(rollout));
        return wait ? await WaitAsync(rollout, environment, cancellationToken) : ExitCodes.Ok;
    }

    private static async Task<int> WaitAsync(RolloutInfo rollout, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var current = rollout;
        var last = RolloutStates.Describe(current);
        using var timer = new PeriodicTimer(PollInterval, environment.TimeProvider);
        while (!RolloutStates.IsTerminal(current.Phase) && await timer.WaitForNextTickAsync(cancellationToken))
        {
            var exitCode = await environment.Api.GetAsync("/api/rollouts", CliJsonContext.Default.RolloutListResponse, cancellationToken) switch
            {
                RolloutListResponse list when list.Rollouts.FirstOrDefault(item => item.Id == rollout.Id) is { } refreshed => Advance(refreshed),
                RolloutListResponse => environment.Fail(new NotFound($"Rollout {rollout.Id} is no longer listed by the backplane.")),
                Validation failure => environment.Fail(failure),
                NotFound failure => environment.Fail(failure),
                Unauthorized failure => environment.Fail(failure),
                Forbidden failure => environment.Fail(failure),
                Unavailable failure => environment.Fail(failure),
            };
            if (exitCode is { } failed)
            {
                return failed;
            }
        }

        var result = RolloutStates.ExitCode(current.Phase);
        if (result != ExitCodes.Ok)
        {
            environment.Error.WriteLine($"ts-orch deploy: {RolloutStates.Describe(current)}");
        }

        return result;

        int? Advance(RolloutInfo refreshed)
        {
            current = refreshed;
            var line = RolloutStates.Describe(current);
            if (line != last)
            {
                environment.Out.WriteLine(line);
                last = line;
            }

            return null;
        }
    }
}
