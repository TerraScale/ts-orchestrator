using System.Diagnostics;
using System.Net;
using static System.FormattableString;

namespace TsOrch.Cli;

internal static class RolloutStates
{
    private const int MaxTransientFailures = 5;
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);

    public static bool IsTerminal(RolloutPhase phase) => phase switch
    {
        RolloutPhase.Pending or RolloutPhase.Canary or RolloutPhase.Baking or RolloutPhase.Waves => false,
        RolloutPhase.Succeeded or RolloutPhase.RolledBack or RolloutPhase.Failed => true,
        _ => throw new UnreachableException(),
    };

    public static int ExitCode(RolloutPhase phase) => phase switch
    {
        RolloutPhase.Succeeded => ExitCodes.Ok,
        RolloutPhase.RolledBack or RolloutPhase.Failed => ExitCodes.Failure,
        RolloutPhase.Pending or RolloutPhase.Canary or RolloutPhase.Baking or RolloutPhase.Waves => throw new UnreachableException(),
        _ => throw new UnreachableException(),
    };

    public static string Describe(RolloutInfo rollout)
    {
        ArgumentNullException.ThrowIfNull(rollout);
        var location = rollout switch
        {
            { ActiveRegions: { Count: > 1 } regions } => $" in {string.Join(" + ", regions)}",
            { CurrentRegion: { } current } => $" in {current}",
            { Region: { } scoped } => $" in {scoped}",
            _ => string.Empty,
        };
        var failure = rollout.Error is null ? string.Empty : $": {rollout.Error}";
        return Invariant($"rollout {rollout.Id} {rollout.ServiceName} -> {rollout.TargetImage}: {rollout.Phase.WireName}, wave {rollout.CurrentWave}/{rollout.TotalWaves}{location}{failure}");
    }

    public static bool IsTransient(BackplaneProblem problem) => problem switch
    {
        BackplaneRequestRejected { Status: HttpStatusCode.TooManyRequests or >= HttpStatusCode.InternalServerError } => true,
        BackplaneTransportFailed => true,
        BackplaneRequestRejected or BackplaneResponseInvalid or BackplaneAuthenticationFailed => false,
    };

    public static async Task<int> WaitForRolloutAsync(string rolloutId, RolloutInfo? initial, CommandEnvironment environment, CancellationToken cancellationToken)
    {
        var current = initial;
        var last = current is null ? string.Empty : Describe(current);
        var transientErrors = 0;
        using var timer = new PeriodicTimer(PollInterval, environment.TimeProvider);
        while ((current is null || !IsTerminal(current.Phase)) && await timer.WaitForNextTickAsync(cancellationToken))
        {
            var exitCode = await environment.Api.GetAsync(
                "/api/rollouts",
                CliJsonContext.Default.RolloutListResponse,
                list => Task.FromResult(HandleList(list)),
                HandleFailure,
                cancellationToken);
            if (exitCode is { } failed)
            {
                return failed;
            }
        }

        if (current is null)
        {
            return environment.Fail(CliDiagnostic.Missing($"Rollout {rolloutId} was not observed."));
        }

        var result = ExitCode(current.Phase);
        if (result != ExitCodes.Ok)
        {
            environment.Error.WriteLine($"ts-orch {environment.CommandName}: {Describe(current)}");
        }

        return result;

        int? HandleList(RolloutListResponse list)
        {
            transientErrors = 0;
            if (list.Rollouts.FirstOrDefault(item => item.Id == rolloutId) is not { } refreshed)
            {
                return environment.Fail(CliDiagnostic.Missing($"Rollout {rolloutId} is no longer listed by the backplane."));
            }

            current = refreshed;
            var line = Describe(current);
            if (line != last)
            {
                environment.Out.WriteLine(line);
                last = line;
            }

            return null;
        }

        int? HandleFailure(BackplaneProblem failure)
        {
            if (IsTransient(failure) && ++transientErrors <= MaxTransientFailures)
            {
                return null;
            }

            return environment.FailRead(failure);
        }
    }

    public static async Task<int> WaitForImageConvergenceAsync(
        string serviceName,
        string expectedImage,
        string? region,
        CommandEnvironment environment,
        CancellationToken cancellationToken)
    {
        var path = Query.Build("/api/status", ("region", region));
        var transientErrors = 0;
        using var timer = new PeriodicTimer(PollInterval, environment.TimeProvider);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            var result = await environment.Api.GetAsync(
                path,
                ApiJsonContext.Default.StatusResponse,
                status => Task.FromResult(CheckStatus(status)),
                HandleFailure,
                cancellationToken);
            if (result is { } exitCode)
            {
                return exitCode;
            }
        }

        return ExitCodes.Failure;

        int? CheckStatus(StatusResponse status)
        {
            transientErrors = 0;
            var active = status.Placements
                .Where(p => p.ServiceName == serviceName && p.State != PlacementState.Stopped && (region is null || p.Region == region))
                .ToList();
            if (active.Count == 0)
            {
                return ExitCodes.Ok;
            }

            var failed = active.FirstOrDefault(p => p.State == PlacementState.Failed || (p.CandidateImage == expectedImage && p.CandidateError is not null));
            if (failed is not null)
            {
                return environment.Fail(CliDiagnostic.Unavailable($"Placement {failed.Id} failed while reverting to {expectedImage}: {failed.CandidateError ?? "placement failed"}"));
            }

            if (active.All(p => p.State == PlacementState.Ready && p.ActiveImage == expectedImage))
            {
                environment.Out.WriteLine(Invariant($"{serviceName}: {active.Count}/{active.Count} placements ready on {expectedImage}"));
                return ExitCodes.Ok;
            }

            return null;
        }

        int? HandleFailure(BackplaneProblem failure)
        {
            if (IsTransient(failure) && ++transientErrors <= MaxTransientFailures)
            {
                return null;
            }

            return environment.FailRead(failure);
        }
    }
}
