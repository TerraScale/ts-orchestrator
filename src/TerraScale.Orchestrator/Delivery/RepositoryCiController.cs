using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.ControlPlane.Providers;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiControllerDisposition
{
    Unspecified,
    Active,
    Succeeded,
    Failed,
    NotDispatchable,
    AuthorityLost,
}

internal sealed record RepositoryCiControllerReceipt(
    RepositoryCiControllerDisposition Disposition,
    RepositoryCiPipelinePlan? Pipeline);

/// <summary>
/// Connects durable pipeline ticks to a bounded pool of standalone OCI preemptible runners and
/// does not acknowledge the originating Forgejo event until both jobs and idle-node cleanup settle.
/// </summary>
internal sealed class RepositoryCiController : IAsyncDisposable
{
    private readonly RepositoryCiPipelineJournal pipelines;
    private readonly RepositoryCiPipelineCoordinator pipelineCoordinator;
    private readonly RepositoryCiJobJournal jobs;
    private readonly RepositoryCiPipelineRunCoordinator runs;
    private readonly OciCiRunnerAvailability availability;
    private readonly Func<string, string, CancellationToken, Task> reconcileConsumer;
    private readonly Func<string, ForgejoCommitStatusState, CancellationToken, Task> reportStatus;
    private readonly OciCiRunnerPoolConfiguration pool;
    private readonly IOciCiRunnerCapacityAdapter capacity;
    private readonly Func<RegionalAuthoritySnapshot> authority;
    private readonly string controllerId;
    private readonly TimeProvider timeProvider;
    private readonly IAsyncDisposable? ownedSource;
    private readonly Dictionary<string, DateTimeOffset> activity = new(StringComparer.Ordinal);

    internal RepositoryCiController(
        RepositoryCiPipelineJournal pipelines,
        RepositoryCiPipelineCoordinator pipelineCoordinator,
        RepositoryCiJobJournal jobs,
        RepositoryCiPipelineRunCoordinator runs,
        OciCiRunnerAvailability availability,
        Func<string, string, CancellationToken, Task> reconcileConsumer,
        Func<string, ForgejoCommitStatusState, CancellationToken, Task> reportStatus,
        OciCiRunnerPoolConfiguration pool,
        IOciCiRunnerCapacityAdapter capacity,
        Func<RegionalAuthoritySnapshot> authority,
        string controllerId,
        TimeProvider? timeProvider = null,
        IAsyncDisposable? ownedSource = null)
    {
        this.pipelines = pipelines ?? throw new ArgumentNullException(nameof(pipelines));
        this.pipelineCoordinator = pipelineCoordinator ?? throw new ArgumentNullException(nameof(pipelineCoordinator));
        this.jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
        this.runs = runs ?? throw new ArgumentNullException(nameof(runs));
        this.availability = availability ?? throw new ArgumentNullException(nameof(availability));
        this.reconcileConsumer = reconcileConsumer ?? throw new ArgumentNullException(nameof(reconcileConsumer));
        this.reportStatus = reportStatus ?? throw new ArgumentNullException(nameof(reportStatus));
        this.pool = pool ?? throw new ArgumentNullException(nameof(pool));
        this.capacity = capacity ?? throw new ArgumentNullException(nameof(capacity));
        this.authority = authority ?? throw new ArgumentNullException(nameof(authority));
        if (controllerId is not { Length: >= 1 and <= 512 } ||
            controllerId.Any(static value => char.IsWhiteSpace(value) || char.IsControl(value)))
            throw new ArgumentException("The CI controller identity is invalid.", nameof(controllerId));
        this.controllerId = controllerId;
        this.timeProvider = timeProvider ?? TimeProvider.System;
        this.ownedSource = ownedSource;
    }

    internal async Task<bool> RunToCompletionAsync(
        ForgejoCiTriggerPlan trigger,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        while (true)
        {
            var receipt = await ProcessOnceAsync(trigger.Envelope.DedupeKey, cancellationToken);
            if (receipt.Disposition is RepositoryCiControllerDisposition.Succeeded or
                RepositoryCiControllerDisposition.Failed or
                RepositoryCiControllerDisposition.NotDispatchable)
            {
                await reportStatus(
                    trigger.Envelope.Revision,
                    receipt.Disposition switch
                    {
                        RepositoryCiControllerDisposition.Succeeded => ForgejoCommitStatusState.Success,
                        RepositoryCiControllerDisposition.Failed => ForgejoCommitStatusState.Failure,
                        _ => ForgejoCommitStatusState.Error,
                    },
                    cancellationToken);
                return true;
            }
            if (receipt.Disposition == RepositoryCiControllerDisposition.AuthorityLost)
                return false;
            if (receipt.Disposition != RepositoryCiControllerDisposition.Active)
                throw new InvalidDataException("The repository CI controller returned an unspecified state.");
            await Task.Delay(pool.PollInterval, cancellationToken);
        }
    }

    internal async Task<RepositoryCiControllerReceipt> ProcessOnceAsync(
        string dedupeKey,
        CancellationToken cancellationToken = default)
    {
        var lease = authority();
        if (!Ready(lease)) return Result(RepositoryCiControllerDisposition.AuthorityLost);
        bool StillValid() => SameAuthority(lease, authority());

        var pipeline = await pipelines.ReadAsync(dedupeKey, cancellationToken);
        if (pipeline is null)
        {
            var planned = await pipelineCoordinator.CoordinateAsync(
                dedupeKey,
                lease.Epoch,
                pool.Slots.Min(static slot => slot.Demand.Sequence),
                pool.Slots.Max(static slot => slot.Demand.Sequence),
                lease.Epoch,
                lease.KvRevision,
                StillValid,
                cancellationToken);
            if (planned.Disposition == RepositoryCiPipelineCoordinationDisposition.TriggerNotDispatchable)
                return Result(RepositoryCiControllerDisposition.NotDispatchable);
            if (planned.Disposition == RepositoryCiPipelineCoordinationDisposition.AuthorityLost)
                return Result(RepositoryCiControllerDisposition.AuthorityLost);
            if (!planned.IsPlanned)
                throw new InvalidDataException($"Repository CI planning failed closed: {planned.Disposition}.");
            pipeline = planned.Plan!;
        }

        availability.Clear();
        var tick = await runs.CoordinateAsync(
            pipeline,
            controllerId,
            lease.Epoch,
            lease.KvRevision,
            StillValid,
            cancellationToken);
        if (tick.Disposition == RepositoryCiPipelineRunCoordinationDisposition.AuthorityLost)
            return Result(RepositoryCiControllerDisposition.AuthorityLost, pipeline);
        EnsureSafe(tick.Disposition);
        if (tick.Disposition is RepositoryCiPipelineRunCoordinationDisposition.Succeeded or
            RepositoryCiPipelineRunCoordinationDisposition.Failed)
            return await DrainAsync(pipeline, tick.Disposition, StillValid, cancellationToken);
        var run = tick.Run ?? await jobs.ReadAsync(pipeline, cancellationToken);

        var assignments = Assign(run);
        foreach (var slot in assignments.Values.DistinctBy(static value => value.Demand.Runner))
        {
            if (!StillValid()) return Result(RepositoryCiControllerDisposition.AuthorityLost, pipeline);
            await reconcileConsumer(Zone(slot.Demand.Zone), slot.Demand.Runner, cancellationToken);
        }
        var active = run.Jobs.Where(static value => value.Phase is
                RepositoryCiJobPhase.DispatchPrepared or RepositoryCiJobPhase.Dispatched or
                RepositoryCiJobPhase.Running)
            .Select(static value => value.RunnerId)
            .Where(static value => value.Length != 0)
            .ToHashSet(StringComparer.Ordinal);
        var desired = assignments.Values.Select(static value => value.Demand)
            .DistinctBy(static value => $"{value.Runner}:{value.Sequence}")
            .ToArray();
        var observations = await ScaleAsync(desired, active, StillValid, cancellationToken);
        if (observations is null)
            return Result(RepositoryCiControllerDisposition.AuthorityLost, pipeline);
        var running = observations.Where(static value => value.State == OciCiRunnerNodeState.Running)
            .Select(static value => $"{value.Runner}:{value.Sequence}")
            .ToHashSet(StringComparer.Ordinal);
        availability.Update(assignments, running);

        if (availability.Count != 0)
        {
            tick = await runs.CoordinateAsync(
                pipeline,
                controllerId,
                lease.Epoch,
                lease.KvRevision,
                StillValid,
                cancellationToken);
            if (tick.Disposition == RepositoryCiPipelineRunCoordinationDisposition.AuthorityLost)
                return Result(RepositoryCiControllerDisposition.AuthorityLost, pipeline);
            EnsureSafe(tick.Disposition);
            if (tick.Disposition is RepositoryCiPipelineRunCoordinationDisposition.Succeeded or
                RepositoryCiPipelineRunCoordinationDisposition.Failed)
                return await DrainAsync(pipeline, tick.Disposition, StillValid, cancellationToken);
        }
        return StillValid()
            ? Result(RepositoryCiControllerDisposition.Active, pipeline)
            : Result(RepositoryCiControllerDisposition.AuthorityLost, pipeline);
    }

    private async Task<RepositoryCiControllerReceipt> DrainAsync(
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiPipelineRunCoordinationDisposition terminal,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        var observed = await ScaleAsync(
            [],
            new HashSet<string>(StringComparer.Ordinal),
            authorityStillValid,
            cancellationToken);
        if (observed is null)
            return Result(RepositoryCiControllerDisposition.AuthorityLost, pipeline);
        if (observed.Any(static value => value.State != OciCiRunnerNodeState.Terminated))
            return Result(RepositoryCiControllerDisposition.Active, pipeline);
        return Result(
            terminal == RepositoryCiPipelineRunCoordinationDisposition.Succeeded
                ? RepositoryCiControllerDisposition.Succeeded
                : RepositoryCiControllerDisposition.Failed,
            pipeline);
    }

    private Dictionary<string, OciCiRunnerPoolSlot> Assign(RepositoryCiPipelineRunSnapshot run)
    {
        var assignments = new Dictionary<string, OciCiRunnerPoolSlot>(StringComparer.Ordinal);
        var used = new HashSet<string>(StringComparer.Ordinal);
        foreach (var job in run.Jobs.Where(static value => value.RunnerId.Length != 0 &&
                     value.Phase is RepositoryCiJobPhase.DispatchPrepared or RepositoryCiJobPhase.Dispatched or
                     RepositoryCiJobPhase.Running))
        {
            var slot = Slot(job.RunnerId, job.RunnerSequence);
            assignments.Add(job.Job.Request.Job.Value, slot);
            used.Add(slot.Demand.Runner);
        }
        foreach (var job in run.Ready.OrderBy(static value => value.Request.Job.Value, StringComparer.Ordinal))
        {
            var slot = pool.Slots.Where(value =>
                    !used.Contains(value.Demand.Runner) &&
                    value.Demand.Zone == job.Request.AllowedZones.Single() &&
                    value.Demand.Sequence >= job.Request.MinimumRunnerSequence &&
                    value.Demand.Sequence <= job.Request.MaximumRunnerSequence &&
                    job.Request.RequiredCapabilities.All(value.Evidence(true).Capabilities.Contains))
                .OrderBy(static value => value.Demand.Runner, StringComparer.Ordinal)
                .FirstOrDefault();
            if (slot is null)
            {
                if (!pool.Slots.Any(value => value.Demand.Zone == job.Request.AllowedZones.Single()))
                    throw new InvalidDataException("The OCI CI runner pool cannot satisfy a pipeline trust zone.");
                continue;
            }
            assignments.Add(job.Request.Job.Value, slot);
            used.Add(slot.Demand.Runner);
        }
        return assignments;
    }

    private async Task<IReadOnlyList<OciCiRunnerNodeObservation>?> ScaleAsync(
        IReadOnlyList<OciCiRunnerDemand> desired,
        IReadOnlySet<string> active,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var observed = await capacity.ObserveAsync(pool.Template, cancellationToken);
        var current = observed.Select(value =>
        {
            if (active.Contains(value.Runner)) activity[value.Runner] = now;
            return value with
            {
                ActiveJob = active.Contains(value.Runner),
                LastActivity = activity.TryGetValue(value.Runner, out var last) && last > value.LastActivity
                    ? last
                    : value.LastActivity,
            };
        }).ToArray();
        var request = new OciCiRunnerCapacityRequest(
            now,
            pool.IdleTimeout,
            pool.Slots.Count,
            pool.Template,
            pool.Slots.Select(static slot => slot.Demand),
            desired,
            current);
        foreach (var action in OciCiRunnerCapacityEngine.Decide(request))
        {
            if (!authorityStillValid()) return null;
            _ = await capacity.ExecuteAsync(action, cancellationToken);
        }
        if (!authorityStillValid()) return null;
        foreach (var node in current.Where(static value => value.State == OciCiRunnerNodeState.Terminated))
            activity.Remove(node.Runner);
        return Array.AsReadOnly(current.Where(node => pool.Slots.Any(slot =>
            slot.Demand.Runner == node.Runner && slot.Demand.Sequence == node.Sequence &&
            OciCiRunnerCapacityEngine.Matches(node, slot.Demand, pool.Template))).ToArray());
    }

    private OciCiRunnerPoolSlot Slot(string runner, long sequence) =>
        pool.Slots.SingleOrDefault(value =>
            value.Demand.Runner == runner && value.Demand.Sequence == sequence)
        ?? throw new InvalidDataException("A CI job references a runner outside its configured OCI pool.");

    private static void EnsureSafe(RepositoryCiPipelineRunCoordinationDisposition disposition)
    {
        if (disposition is RepositoryCiPipelineRunCoordinationDisposition.Waiting or
            RepositoryCiPipelineRunCoordinationDisposition.Progressed or
            RepositoryCiPipelineRunCoordinationDisposition.LeaseHeld)
            return;
        if (disposition is RepositoryCiPipelineRunCoordinationDisposition.Succeeded or
            RepositoryCiPipelineRunCoordinationDisposition.Failed)
            return;
        throw new InvalidDataException($"Repository CI run coordination failed closed: {disposition}.");
    }

    private static bool Ready(RegionalAuthoritySnapshot value) =>
        value.Ready && value.IsLeader && value.Epoch > 0 && value.KvRevision > 0;

    internal static bool SameAuthority(RegionalAuthoritySnapshot expected, RegionalAuthoritySnapshot current) =>
        Ready(current) && current.Epoch == expected.Epoch && current.KvRevision >= expected.KvRevision;

    private static string Zone(TrustZone zone) => zone switch
    {
        TrustZone.UntrustedProduct => "untrusted-product",
        TrustZone.TrustedBuild => "trusted-build",
        _ => throw new ArgumentOutOfRangeException(nameof(zone)),
    };

    private static RepositoryCiControllerReceipt Result(
        RepositoryCiControllerDisposition disposition,
        RepositoryCiPipelinePlan? pipeline = null) => new(disposition, pipeline);

    public async ValueTask DisposeAsync()
    {
        capacity.Dispose();
        if (ownedSource is not null) await ownedSource.DisposeAsync();
    }
}

internal sealed class OciCiRunnerAvailability
{
    private IReadOnlyDictionary<string, RunnerEvidence> current =
        new Dictionary<string, RunnerEvidence>(StringComparer.Ordinal);

    internal int Count => current.Count;

    internal void Clear() => current = new Dictionary<string, RunnerEvidence>(StringComparer.Ordinal);

    internal void Update(
        IReadOnlyDictionary<string, OciCiRunnerPoolSlot> assignments,
        IReadOnlySet<string> running) => current = assignments
        .Where(value => running.Contains($"{value.Value.Demand.Runner}:{value.Value.Demand.Sequence}"))
        .ToDictionary(
            static value => value.Key,
            static value => value.Value.Evidence(true),
            StringComparer.Ordinal);

    internal Task<IReadOnlyList<RunnerEvidence>> ReadAsync(
        RepositoryCiPipelineJob job,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyList<RunnerEvidence>>(
            current.TryGetValue(job.Request.Job.Value, out var runner) ? [runner] : []);
    }
}
