using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.Delivery;

public enum NativeGitOpsChangeKind
{
    Unspecified,
    Create,
    Update,
    Suspend,
    Resume,
    GuardedRetirement,
}

public enum NativeGitOpsDiffError
{
    Unspecified,
    InvalidPlan,
    StaleGeneration,
    ConflictingGeneration,
    ImmutableIdentityChanged,
}

public sealed class NativeGitOpsDiffException : InvalidOperationException
{
    internal NativeGitOpsDiffException(NativeGitOpsDiffError code, string message) : base(message) =>
        Code = code;

    public NativeGitOpsDiffError Code { get; }
}

public sealed record NativeGitOpsChange(
    NativeGitOpsChangeKind Kind,
    string WorkloadId,
    NativeGitOpsWorkloadPlan? Accepted,
    NativeGitOpsWorkloadPlan? Proposed,
    GitOpsChildOwnership ChildOwnership,
    GitOpsRemovalPolicy RemovalPolicy);

public sealed record NativeGitOpsDiffPlan(
    long? AcceptedGeneration,
    string? AcceptedDigest,
    long ProposedGeneration,
    string ProposedDigest,
    IReadOnlyList<NativeGitOpsChange> Changes)
{
    public bool IsNoOp => Changes.Count == 0;
}

/// <summary>
/// Produces a deterministic REQ-O014 plan/diff without granting Git direct prune authority over
/// regional-journal children. Retirement is always a guarded regional operation.
/// </summary>
public static class NativeGitOpsDiff
{
    public static NativeGitOpsDiffPlan Compare(NativeGitOpsPlan? accepted, NativeGitOpsPlan proposed)
    {
        ArgumentNullException.ThrowIfNull(proposed);
        ValidateHeader(proposed);
        if (accepted is null)
        {
            return Result(
                null,
                proposed,
                proposed.Workloads.Select(workload => Change(NativeGitOpsChangeKind.Create, null, workload)));
        }

        ValidateHeader(accepted);
        if (proposed.Generation < accepted.Generation)
            throw new NativeGitOpsDiffException(
                NativeGitOpsDiffError.StaleGeneration,
                "A stale native GitOps generation cannot replace accepted desired state.");
        if (proposed.Generation == accepted.Generation)
        {
            if (!StringComparer.Ordinal.Equals(proposed.Digest, accepted.Digest))
                throw new NativeGitOpsDiffException(
                    NativeGitOpsDiffError.ConflictingGeneration,
                    "One native GitOps generation cannot identify two desired-state plans.");
            return Result(accepted, proposed, []);
        }

        var acceptedById = accepted.Workloads.ToDictionary(workload => workload.Id, StringComparer.Ordinal);
        var proposedById = proposed.Workloads.ToDictionary(workload => workload.Id, StringComparer.Ordinal);
        var changes = new List<NativeGitOpsChange>();
        var suspensions = new Dictionary<string, NativeGitOpsChange>(StringComparer.Ordinal);

        foreach (var workload in proposed.Workloads)
        {
            if (!acceptedById.TryGetValue(workload.Id, out var previous))
            {
                changes.Add(Change(NativeGitOpsChangeKind.Create, null, workload));
                continue;
            }
            if (previous.Role != workload.Role)
                throw new NativeGitOpsDiffException(
                    NativeGitOpsDiffError.ImmutableIdentityChanged,
                    "A native GitOps workload identity cannot change its admitted role.");
            if (Same(previous, workload, includeSuspension: true)) continue;
            var kind = Same(previous, workload, includeSuspension: false)
                ? workload.Suspended
                    ? NativeGitOpsChangeKind.Suspend
                    : NativeGitOpsChangeKind.Resume
                : NativeGitOpsChangeKind.Update;
            var change = Change(kind, previous, workload);
            if (kind == NativeGitOpsChangeKind.Suspend) suspensions.Add(workload.Id, change);
            else changes.Add(change);
        }

        foreach (var workload in proposed.Workloads.Reverse())
        {
            if (suspensions.TryGetValue(workload.Id, out var suspension)) changes.Add(suspension);
        }

        foreach (var workload in accepted.Workloads.Reverse())
        {
            if (!proposedById.ContainsKey(workload.Id))
                changes.Add(Change(NativeGitOpsChangeKind.GuardedRetirement, workload, null));
        }

        return Result(accepted, proposed, changes);
    }

    private static NativeGitOpsDiffPlan Result(
        NativeGitOpsPlan? accepted,
        NativeGitOpsPlan proposed,
        IEnumerable<NativeGitOpsChange> changes) => new(
            accepted?.Generation,
            accepted?.Digest,
            proposed.Generation,
            proposed.Digest,
            new ReadOnlyCollection<NativeGitOpsChange>(changes.ToArray()));

    private static NativeGitOpsChange Change(
        NativeGitOpsChangeKind kind,
        NativeGitOpsWorkloadPlan? accepted,
        NativeGitOpsWorkloadPlan? proposed)
    {
        var workload = proposed ?? accepted ?? throw new ArgumentException("A GitOps change requires a workload.");
        return new(
            kind,
            workload.Id,
            accepted,
            proposed,
            GitOpsChildOwnership.RegionalJournal,
            GitOpsRemovalPolicy.GuardedRetirement);
    }

    private static bool Same(
        NativeGitOpsWorkloadPlan accepted,
        NativeGitOpsWorkloadPlan proposed,
        bool includeSuspension) =>
        accepted.Role == proposed.Role &&
        accepted.ArtifactDigest == proposed.ArtifactDigest &&
        accepted.Runtime == proposed.Runtime &&
        accepted.Replicas == proposed.Replicas &&
        accepted.Cells.SequenceEqual(proposed.Cells, StringComparer.Ordinal) &&
        accepted.DependsOn.SequenceEqual(proposed.DependsOn, StringComparer.Ordinal) &&
        accepted.ChildOwnership == proposed.ChildOwnership &&
        accepted.RemovalPolicy == proposed.RemovalPolicy &&
        (!includeSuspension || accepted.Suspended == proposed.Suspended);

    private static void ValidateHeader(NativeGitOpsPlan plan)
    {
        if (plan.ApiVersion != NativeGitOpsManifest.ApiVersion || plan.Kind != NativeGitOpsManifest.Kind ||
            plan.Generation <= 0 || plan.Digest.Length != 64 ||
            plan.Digest.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')) ||
            plan.Workloads.Count > NativeGitOpsManifest.MaximumWorkloads ||
            plan.Workloads.Select(workload => workload.Id).Distinct(StringComparer.Ordinal).Count() != plan.Workloads.Count ||
            plan.Workloads.Any(workload =>
                workload.ChildOwnership != GitOpsChildOwnership.RegionalJournal ||
                workload.RemovalPolicy != GitOpsRemovalPolicy.GuardedRetirement))
            throw new NativeGitOpsDiffException(
                NativeGitOpsDiffError.InvalidPlan,
                "The native GitOps diff input is not a compiled closed-role plan.");
    }
}

