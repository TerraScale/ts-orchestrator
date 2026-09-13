using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiJobDispatchCoordinationDisposition
{
    Unspecified,
    Dispatched,
    Duplicate,
    NotReady,
    SelectionHeld,
    IsolationDenied,
    AuthorityLost,
    LeaseHeld,
    IdentityConflict,
    Expired,
    Contention,
}

internal sealed record RepositoryCiJobDispatchCoordinationReceipt(
    RepositoryCiJobDispatchCoordinationDisposition Disposition,
    DeliveryErrorCode HoldReason,
    CiRunnerAdmissionReason IsolationReason,
    RepositoryCiJobSnapshot? Job,
    RepositoryCiJobDispatchReceipt? Dispatch);

/// <summary>
/// Selects one admitted runner, publishes the exact source archive, and durably dispatches one
/// ready CI job. A prepared job resumes without repeating source or isolation discovery.
/// </summary>
internal sealed class RepositoryCiJobDispatchCoordinator(
    RepositoryCiJobJournal jobs,
    RepositoryCiSourceBundlePublisher bundles,
    RepositoryCiJobDispatcher dispatcher,
    Func<ForgejoResolvedRevision, CancellationToken, Task<ForgejoSourceArchive>> readArchive,
    Func<RepositoryCiPipelineJob, RunnerEvidence, CancellationToken, Task<CiRunnerIsolationEvidence>>
        readIsolation)
{
    private const int MaximumIdentityLength = 512;
    private readonly RepositoryCiJobJournal jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
    private readonly RepositoryCiSourceBundlePublisher bundles =
        bundles ?? throw new ArgumentNullException(nameof(bundles));
    private readonly RepositoryCiJobDispatcher dispatcher =
        dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
    private readonly Func<ForgejoResolvedRevision, CancellationToken, Task<ForgejoSourceArchive>> readArchive =
        readArchive ?? throw new ArgumentNullException(nameof(readArchive));
    private readonly Func<RepositoryCiPipelineJob, RunnerEvidence, CancellationToken,
        Task<CiRunnerIsolationEvidence>> readIsolation =
        readIsolation ?? throw new ArgumentNullException(nameof(readIsolation));

    internal async Task<RepositoryCiJobDispatchCoordinationReceipt> DispatchAsync(
        RepositoryCiPipelinePlan pipeline,
        JobId jobId,
        IReadOnlyList<RunnerEvidence> runners,
        string controllerId,
        long authorityEpoch,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(jobId);
        ArgumentNullException.ThrowIfNull(runners);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (!Identity(controllerId))
            throw new ArgumentException("The controller identity is invalid.", nameof(controllerId));
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));

        var run = await jobs.ReadAsync(pipeline, cancellationToken);
        var current = run.Jobs.SingleOrDefault(value => value.Job.Request.Job == jobId)
            ?? throw new ArgumentException("The CI job is not part of the pipeline.", nameof(jobId));
        if (current.Phase == RepositoryCiJobPhase.DispatchPrepared)
            return await ResumeAsync(
                pipeline,
                jobId,
                controllerId,
                authorityEpoch,
                authorityStillValid,
                cancellationToken);
        if (current.Phase != RepositoryCiJobPhase.Pending ||
            !run.Ready.Any(value => value.Request.Job == jobId))
            return Result(RepositoryCiJobDispatchCoordinationDisposition.NotReady, current);
        if (!authorityStillValid())
            return Result(RepositoryCiJobDispatchCoordinationDisposition.AuthorityLost, current);

        var decision = DeliveryEngine.DecideJob(current.Job.Request, runners, MaximumIdentityLength);
        if (decision.Intents.Count != 1)
            throw new InvalidDataException("The CI runner decision did not return one bounded intent.");
        if (decision.Intents[0] is HoldDeliveryIntent hold)
            return new(
                RepositoryCiJobDispatchCoordinationDisposition.SelectionHeld,
                hold.Reason,
                CiRunnerAdmissionReason.Unspecified,
                current,
                null);
        if (decision.Intents[0] is not DispatchJobIntent selected ||
            selected.Job != jobId || selected.Request != current.Job.Request)
            throw new InvalidDataException("The CI runner decision changed the requested job identity.");

        var isolation = await readIsolation(current.Job, selected.SelectedRunnerEvidence, cancellationToken)
            ?? throw new InvalidDataException("The CI runner isolation reader returned no evidence.");
        var admission = CiRunnerIsolationPolicy.Evaluate(
            current.Job.Request,
            selected.SelectedRunnerEvidence,
            isolation);
        if (!admission.Accepted)
            return new(
                RepositoryCiJobDispatchCoordinationDisposition.IsolationDenied,
                DeliveryErrorCode.Unspecified,
                admission.Reason,
                current,
                null);
        if (!authorityStillValid())
            return Result(RepositoryCiJobDispatchCoordinationDisposition.AuthorityLost, current);

        var archive = await readArchive(current.Job.Source, cancellationToken)
            ?? throw new InvalidDataException("The CI source archive reader returned no archive.");
        if (!SameRevision(current.Job.Source, archive.Revision))
            return Result(RepositoryCiJobDispatchCoordinationDisposition.IdentityConflict, current);
        if (!authorityStillValid())
            return Result(RepositoryCiJobDispatchCoordinationDisposition.AuthorityLost, current);
        var bundle = await bundles.PublishAsync(archive, cancellationToken);
        if (!authorityStillValid())
            return Result(RepositoryCiJobDispatchCoordinationDisposition.AuthorityLost, current);

        var prepared = await jobs.PrepareDispatchAsync(
            pipeline,
            jobId,
            bundle,
            selected.SelectedRunnerEvidence,
            isolation,
            controllerId,
            authorityEpoch,
            current.Job.Request.Idempotency.Value,
            authorityStillValid,
            cancellationToken);
        if (prepared.Disposition is not (RepositoryCiJobJournalDisposition.Prepared or
                RepositoryCiJobJournalDisposition.Duplicate) || prepared.Job is null)
            return Result(Map(prepared.Disposition), prepared.Job ?? current);
        return await DispatchPreparedAsync(
            pipeline,
            prepared.Job,
            authorityStillValid,
            cancellationToken);
    }

    private async Task<RepositoryCiJobDispatchCoordinationReceipt> ResumeAsync(
        RepositoryCiPipelinePlan pipeline,
        JobId jobId,
        string controllerId,
        long authorityEpoch,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        var acquired = await jobs.AcquireAsync(
            pipeline,
            jobId,
            controllerId,
            authorityEpoch,
            authorityStillValid,
            cancellationToken);
        if (acquired.Disposition is not (RepositoryCiJobJournalDisposition.Resumed or
                RepositoryCiJobJournalDisposition.TakenOver) || acquired.Job is null)
            return Result(Map(acquired.Disposition), acquired.Job);
        return await DispatchPreparedAsync(
            pipeline,
            acquired.Job,
            authorityStillValid,
            cancellationToken);
    }

    private async Task<RepositoryCiJobDispatchCoordinationReceipt> DispatchPreparedAsync(
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiJobSnapshot prepared,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        var dispatched = await dispatcher.DispatchAsync(
            pipeline,
            prepared,
            authorityStillValid,
            cancellationToken);
        if (dispatched.Transition?.Disposition == RepositoryCiJobJournalDisposition.Advanced)
            return Result(
                RepositoryCiJobDispatchCoordinationDisposition.Dispatched,
                dispatched.Transition.Job,
                dispatched);
        if (dispatched.Transition?.Disposition == RepositoryCiJobJournalDisposition.Duplicate)
            return Result(
                RepositoryCiJobDispatchCoordinationDisposition.Duplicate,
                dispatched.Transition.Job,
                dispatched);
        if (dispatched.Publication.Disposition == RepositoryCiJobPublishDisposition.Expired)
            return Result(RepositoryCiJobDispatchCoordinationDisposition.Expired, prepared, dispatched);
        if (dispatched.Publication.Disposition is
            RepositoryCiJobPublishDisposition.AuthorityLostBeforePublish or
            RepositoryCiJobPublishDisposition.AuthorityLostAfterPublish)
            return Result(RepositoryCiJobDispatchCoordinationDisposition.AuthorityLost, prepared, dispatched);
        return Result(
            Map(dispatched.Transition?.Disposition ?? RepositoryCiJobJournalDisposition.Unspecified),
            dispatched.Transition?.Job ?? prepared,
            dispatched);
    }

    private static RepositoryCiJobDispatchCoordinationDisposition Map(
        RepositoryCiJobJournalDisposition disposition) => disposition switch
        {
            RepositoryCiJobJournalDisposition.StaleAuthority =>
                RepositoryCiJobDispatchCoordinationDisposition.AuthorityLost,
            RepositoryCiJobJournalDisposition.LeaseHeld or RepositoryCiJobJournalDisposition.StaleLease =>
                RepositoryCiJobDispatchCoordinationDisposition.LeaseHeld,
            RepositoryCiJobJournalDisposition.NotReady or RepositoryCiJobJournalDisposition.PipelineFailed or
            RepositoryCiJobJournalDisposition.PhaseConflict =>
                RepositoryCiJobDispatchCoordinationDisposition.NotReady,
            RepositoryCiJobJournalDisposition.RunnerDenied =>
                RepositoryCiJobDispatchCoordinationDisposition.IsolationDenied,
            RepositoryCiJobJournalDisposition.IdentityConflict =>
                RepositoryCiJobDispatchCoordinationDisposition.IdentityConflict,
            RepositoryCiJobJournalDisposition.Contention =>
                RepositoryCiJobDispatchCoordinationDisposition.Contention,
            _ => RepositoryCiJobDispatchCoordinationDisposition.IdentityConflict,
        };

    private static bool SameRevision(ForgejoResolvedRevision expected, ForgejoResolvedRevision actual) =>
        expected.Repository == actual.Repository && expected.Commit == actual.Commit &&
        expected.Tree == actual.Tree && expected.SignatureVerified == actual.SignatureVerified;

    private static bool Identity(string value) => value is { Length: >= 1 and <= MaximumIdentityLength } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));

    private static RepositoryCiJobDispatchCoordinationReceipt Result(
        RepositoryCiJobDispatchCoordinationDisposition disposition,
        RepositoryCiJobSnapshot? job,
        RepositoryCiJobDispatchReceipt? dispatch = null) => new(
            disposition,
            DeliveryErrorCode.Unspecified,
            CiRunnerAdmissionReason.Unspecified,
            job,
            dispatch);
}

