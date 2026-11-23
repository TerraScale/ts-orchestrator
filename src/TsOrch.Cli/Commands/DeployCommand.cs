namespace TsOrch.Cli;

internal static class DeployCommand
{
    private const string UsageText = "ts-orch deploy <service> <image> [--region R] [--wait]";
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);

    public static IReadOnlyList<CliOption> Options { get; } = [new("region", null, true), new("wait", null, false)];

    public static async Task<OrchResult<int>> RunAsync(CliArguments arguments, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        if (!arguments.ExpectPositionals(2, UsageText).TryGetValue(out _, out var usageError))
        {
            return usageError;
        }

        var started = await environment.Api.PostAsync(
            "/api/deploy",
            new DeployRequest(arguments.Positionals[0], arguments.Positionals[1], arguments.Value("region")),
            ApiJsonContext.Default.DeployRequest,
            ApiJsonContext.Default.RolloutInfo,
            cancellationToken);
        if (!started.TryGetValue(out var rollout, out var error))
        {
            return error;
        }

        environment.Out.WriteLine(RolloutStates.Describe(rollout));
        return arguments.Flag("wait")
            ? await WaitAsync(rollout, environment, cancellationToken)
            : ExitCodes.Ok;
    }

    private static async Task<OrchResult<int>> WaitAsync(RolloutInfo rollout, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var current = rollout;
        var last = RolloutStates.Describe(current);
        using var timer = new PeriodicTimer(PollInterval, environment.TimeProvider);
        while (!RolloutStates.IsTerminal(current.Phase) && await timer.WaitForNextTickAsync(cancellationToken))
        {
            var listed = await environment.Api.GetAsync("/api/rollouts", CliJsonContext.Default.RolloutListResponse, cancellationToken);
            if (!listed.TryGetValue(out var list, out var error))
            {
                return error;
            }

            if (list.Rollouts.FirstOrDefault(item => item.Id == rollout.Id) is not { } refreshed)
            {
                return new NotFound($"Rollout {rollout.Id} is no longer listed by the backplane.");
            }

            current = refreshed;
            var line = RolloutStates.Describe(current);
            if (line != last)
            {
                environment.Out.WriteLine(line);
                last = line;
            }
        }

        var exitCode = RolloutStates.ExitCode(current.Phase);
        if (exitCode != ExitCodes.Ok)
        {
            environment.Error.WriteLine($"ts-orch deploy: {RolloutStates.Describe(current)}");
        }

        return exitCode;
    }
}
