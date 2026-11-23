using System.Diagnostics;
using static System.FormattableString;

namespace TsOrch.Cli;

internal static class RolloutStates
{
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
        var region = rollout.CurrentRegion ?? rollout.Region;
        var location = region is null ? string.Empty : $" in {region}";
        var failure = rollout.Error is null ? string.Empty : $": {rollout.Error}";
        return Invariant($"rollout {rollout.Id} {rollout.ServiceName} -> {rollout.TargetImage}: {rollout.Phase.WireName}, wave {rollout.CurrentWave}/{rollout.TotalWaves}{location}{failure}");
    }
}
