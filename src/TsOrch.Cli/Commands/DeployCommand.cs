namespace TsOrch.Cli;

internal static class DeployCommand
{
    private const string UsageText = "ts-orch deploy <service> <image> [--region R] [--wait]";
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);

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
        return wait ? await WaitAsync(rollout, environment, cancellationToken) : ExitCodes.Ok;
    }

    private static async Task<int> WaitAsync(RolloutInfo rollout, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var current = rollout;
        var last = RolloutStates.Describe(current);
        using var timer = new PeriodicTimer(PollInterval, environment.TimeProvider);
        while (!RolloutStates.IsTerminal(current.Phase) && await timer.WaitForNextTickAsync(cancellationToken))
        {
            var exitCode = await environment.Api.GetAsync("/api/rollouts", CliJsonContext.Default.RolloutListResponse,
                list => Task.FromResult(list.Rollouts.FirstOrDefault(item => item.Id == rollout.Id) is { } refreshed
                    ? Advance(refreshed)
                    : environment.Fail(CliDiagnostic.Missing($"Rollout {rollout.Id} is no longer listed by the backplane."))),
                failure => (int?)environment.FailRead(failure), cancellationToken);
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
