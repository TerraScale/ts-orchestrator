using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiPipelineRunCoordinationDisposition
{
    Unspecified,
    Waiting,
    Progressed,
    Succeeded,
    Failed,
    AuthorityLost,
    LeaseHeld,
    IdentityConflict,
    Expired,
    Contention,
}

internal sealed record RepositoryCiPipelineRunCoordinationReceipt(
    RepositoryCiPipelineRunCoordinationDisposition Disposition,
    RepositoryCiPipelineRunSnapshot? Run,
    IReadOnlyList<RepositoryCiJobDispatchCoordinationReceipt> Dispatches,
    IReadOnlyList<RepositoryCiJobResultReconcileReceipt> Results,
    IReadOnlyList<RepositoryCiJobRetryCoordinationReceipt> Retries);

/// <summary>
/// Advances one durable pipeline tick: observe runner results, resume prepared commands, then
/// dispatch dependency-ready jobs. Retry authorization remains an explicit separate decision.
/// </summary>
internal sealed class RepositoryCiPipelineRunCoordinator(
    RepositoryCiJobJournal jobs,
    RepositoryCiJobDispatchCoordinator dispatch,
    RepositoryCiJobResultReconciler results,
    Func<RepositoryCiPipelineJob, CancellationToken, Task<IReadOnlyList<RunnerEvidence>>> readRunners,
    RepositoryCiJobRetryCoordinator? retries = null)
{
    private readonly RepositoryCiJobJournal jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
    private readonly RepositoryCiJobDispatchCoordinator dispatch =
        dispatch ?? throw new ArgumentNullException(nameof(dispatch));
    private readonly RepositoryCiJobResultReconciler results =
        results ?? throw new ArgumentNullException(nameof(results));
    private readonly Func<RepositoryCiPipelineJob, CancellationToken, Task<IReadOnlyList<RunnerEvidence>>>
        readRunners = readRunners ?? throw new ArgumentNullException(nameof(readRunners));
    private readonly RepositoryCiJobRetryCoordinator? retries = retries;

    internal async Task<RepositoryCiPipelineRunCoordinationReceipt> CoordinateAsync(
        RepositoryCiPipelinePlan pipeline,
        string controllerId,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (controllerId is not { Length: >= 1 and <= 512 } ||
            controllerId.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character)))
            throw new ArgumentException("The controller identity is invalid.", nameof(controllerId));
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        var dispatches = new List<RepositoryCiJobDispatchCoordinationReceipt>();
        var reconciled = new List<RepositoryCiJobResultReconcileReceipt>();
        var retried = new List<RepositoryCiJobRetryCoordinationReceipt>();

        var initialized = await jobs.InitializeAsync(
            pipeline,
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
        if (initialized is not (RepositoryCiJobJournalDisposition.Recorded or
                RepositoryCiJobJournalDisposition.Duplicate))
            return Receipt(Map(initialized), null, dispatches, reconciled, retried);

        var run = await jobs.ReadAsync(pipeline, cancellationToken);
        foreach (var job in run.Jobs.Where(static value => value.Phase is
                     RepositoryCiJobPhase.Dispatched or RepositoryCiJobPhase.Running))
        {
            var receipt = await results.ReconcileAsync(
                pipeline,
                job.Job.Request.Job,
                controllerId,
                authorityEpoch,
                authorityStillValid,
                cancellationToken);
            reconciled.Add(receipt);
            if (Terminal(receipt.Disposition) is { } terminal)
                return await FinishAsync(
                    terminal,
                    pipeline,
                    dispatches,
                    reconciled,
                    retried,
                    cancellationToken);
        }

        run = await jobs.ReadAsync(pipeline, cancellationToken);
        if (retries is not null)
        {
            var permanent = false;
            foreach (var job in run.Jobs.Where(static value => value.Phase is
                         RepositoryCiJobPhase.Failed or RepositoryCiJobPhase.RetryWaiting))
            {
                var receipt = await retries.CoordinateAsync(
                    pipeline,
                    job.Job.Request.Job,
                    controllerId,
                    authorityEpoch,
                    authorityStillValid,
                    cancellationToken);
                retried.Add(receipt);
                if (Terminal(receipt.Disposition) is { } terminal)
                    return await FinishAsync(
                        terminal,
                        pipeline,
                        dispatches,
                        reconciled,
                        retried,
                        cancellationToken);
                permanent |= receipt.Disposition is
                    RepositoryCiJobRetryCoordinationDisposition.NotRetryable or
                    RepositoryCiJobRetryCoordinationDisposition.AttemptsExhausted;
            }
            run = await jobs.ReadAsync(pipeline, cancellationToken);
            if (permanent)
                return Receipt(
                    RepositoryCiPipelineRunCoordinationDisposition.Failed,
                    run,
                    dispatches,
                    reconciled,
                    retried);
            if (run.State == RepositoryCiPipelineRunState.Failed)
                return Receipt(
                    RepositoryCiPipelineRunCoordinationDisposition.Waiting,
                    run,
                    dispatches,
                    reconciled,
                    retried);
        }
        if (run.State != RepositoryCiPipelineRunState.Active)
            return Receipt(State(run.State), run, dispatches, reconciled, retried);

        foreach (var job in run.Jobs.Where(static value =>
                     value.Phase == RepositoryCiJobPhase.DispatchPrepared))
        {
            var receipt = await dispatch.DispatchAsync(
                pipeline,
                job.Job.Request.Job,
                [],
                controllerId,
                authorityEpoch,
                authorityStillValid,
                cancellationToken);
            dispatches.Add(receipt);
            if (Terminal(receipt.Disposition) is { } terminal)
                return await FinishAsync(
                    terminal,
                    pipeline,
                    dispatches,
                    reconciled,
                    retried,
                    cancellationToken);
        }

        run = await jobs.ReadAsync(pipeline, cancellationToken);
        if (run.State != RepositoryCiPipelineRunState.Active)
            return Receipt(State(run.State), run, dispatches, reconciled, retried);
        foreach (var job in run.Ready)
        {
            var runners = await readRunners(job, cancellationToken)
                ?? throw new InvalidDataException("The CI runner reader returned no snapshot.");
            var receipt = await dispatch.DispatchAsync(
                pipeline,
                job.Request.Job,
                runners,
                controllerId,
                authorityEpoch,
                authorityStillValid,
                cancellationToken);
            dispatches.Add(receipt);
            if (Terminal(receipt.Disposition) is { } terminal)
                return await FinishAsync(
                    terminal,
                    pipeline,
                    dispatches,
                    reconciled,
                    retried,
                    cancellationToken);
        }

        run = await jobs.ReadAsync(pipeline, cancellationToken);
        var progressed = reconciled.Any(static value => value.Disposition is
                RepositoryCiJobResultReconcileDisposition.Running or
                RepositoryCiJobResultReconcileDisposition.Completed) ||
            dispatches.Any(static value =>
                value.Disposition == RepositoryCiJobDispatchCoordinationDisposition.Dispatched) ||
            retried.Any(static value => value.Disposition is
                RepositoryCiJobRetryCoordinationDisposition.Scheduled or
                RepositoryCiJobRetryCoordinationDisposition.Opened);
        return Receipt(
            run.State == RepositoryCiPipelineRunState.Active
                ? progressed
                    ? RepositoryCiPipelineRunCoordinationDisposition.Progressed
                    : RepositoryCiPipelineRunCoordinationDisposition.Waiting
                : State(run.State),
            run,
            dispatches,
            reconciled,
            retried);
    }

    private async Task<RepositoryCiPipelineRunCoordinationReceipt> FinishAsync(
        RepositoryCiPipelineRunCoordinationDisposition disposition,
        RepositoryCiPipelinePlan pipeline,
        List<RepositoryCiJobDispatchCoordinationReceipt> dispatches,
        List<RepositoryCiJobResultReconcileReceipt> results,
        List<RepositoryCiJobRetryCoordinationReceipt> retries,
        CancellationToken cancellationToken) => Receipt(
            disposition,
            await jobs.ReadAsync(pipeline, cancellationToken),
            dispatches,
            results,
            retries);

    private static RepositoryCiPipelineRunCoordinationDisposition? Terminal(
        RepositoryCiJobResultReconcileDisposition disposition) => disposition switch
    {
        RepositoryCiJobResultReconcileDisposition.AuthorityLost =>
            RepositoryCiPipelineRunCoordinationDisposition.AuthorityLost,
        RepositoryCiJobResultReconcileDisposition.LeaseHeld =>
            RepositoryCiPipelineRunCoordinationDisposition.LeaseHeld,
        RepositoryCiJobResultReconcileDisposition.IdentityConflict =>
            RepositoryCiPipelineRunCoordinationDisposition.IdentityConflict,
        RepositoryCiJobResultReconcileDisposition.Contention =>
            RepositoryCiPipelineRunCoordinationDisposition.Contention,
        _ => null,
    };

    private static RepositoryCiPipelineRunCoordinationDisposition? Terminal(
        RepositoryCiJobDispatchCoordinationDisposition disposition) => disposition switch
    {
        RepositoryCiJobDispatchCoordinationDisposition.AuthorityLost =>
            RepositoryCiPipelineRunCoordinationDisposition.AuthorityLost,
        RepositoryCiJobDispatchCoordinationDisposition.LeaseHeld =>
            RepositoryCiPipelineRunCoordinationDisposition.LeaseHeld,
        RepositoryCiJobDispatchCoordinationDisposition.IdentityConflict =>
            RepositoryCiPipelineRunCoordinationDisposition.IdentityConflict,
        RepositoryCiJobDispatchCoordinationDisposition.Expired =>
            RepositoryCiPipelineRunCoordinationDisposition.Expired,
        RepositoryCiJobDispatchCoordinationDisposition.Contention =>
            RepositoryCiPipelineRunCoordinationDisposition.Contention,
        _ => null,
    };

    private static RepositoryCiPipelineRunCoordinationDisposition? Terminal(
        RepositoryCiJobRetryCoordinationDisposition disposition) => disposition switch
    {
        RepositoryCiJobRetryCoordinationDisposition.AuthorityLost =>
            RepositoryCiPipelineRunCoordinationDisposition.AuthorityLost,
        RepositoryCiJobRetryCoordinationDisposition.LeaseHeld =>
            RepositoryCiPipelineRunCoordinationDisposition.LeaseHeld,
        RepositoryCiJobRetryCoordinationDisposition.IdentityConflict =>
            RepositoryCiPipelineRunCoordinationDisposition.IdentityConflict,
        RepositoryCiJobRetryCoordinationDisposition.Contention =>
            RepositoryCiPipelineRunCoordinationDisposition.Contention,
        _ => null,
    };

    private static RepositoryCiPipelineRunCoordinationDisposition Map(
        RepositoryCiJobJournalDisposition disposition) => disposition switch
    {
        RepositoryCiJobJournalDisposition.StaleAuthority =>
            RepositoryCiPipelineRunCoordinationDisposition.AuthorityLost,
        RepositoryCiJobJournalDisposition.IdentityConflict =>
            RepositoryCiPipelineRunCoordinationDisposition.IdentityConflict,
        RepositoryCiJobJournalDisposition.Contention =>
            RepositoryCiPipelineRunCoordinationDisposition.Contention,
        _ => RepositoryCiPipelineRunCoordinationDisposition.IdentityConflict,
    };

    private static RepositoryCiPipelineRunCoordinationDisposition State(
        RepositoryCiPipelineRunState state) => state switch
    {
        RepositoryCiPipelineRunState.Succeeded => RepositoryCiPipelineRunCoordinationDisposition.Succeeded,
        RepositoryCiPipelineRunState.Failed => RepositoryCiPipelineRunCoordinationDisposition.Failed,
        _ => RepositoryCiPipelineRunCoordinationDisposition.Waiting,
    };

    private static RepositoryCiPipelineRunCoordinationReceipt Receipt(
        RepositoryCiPipelineRunCoordinationDisposition disposition,
        RepositoryCiPipelineRunSnapshot? run,
        List<RepositoryCiJobDispatchCoordinationReceipt> dispatches,
        List<RepositoryCiJobResultReconcileReceipt> results,
        List<RepositoryCiJobRetryCoordinationReceipt> retries) => new(
            disposition,
            run,
            Array.AsReadOnly(dispatches.ToArray()),
            Array.AsReadOnly(results.ToArray()),
            Array.AsReadOnly(retries.ToArray()));
}
