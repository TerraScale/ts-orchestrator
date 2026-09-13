using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiJobResultReconcileDisposition
{
    Unspecified,
    AwaitingExecution,
    Running,
    Completed,
    Duplicate,
    AuthorityLost,
    LeaseHeld,
    NotDispatchable,
    IdentityConflict,
    EvidenceConflict,
    Contention,
}

internal sealed record RepositoryCiJobResultReconcileReceipt(
    RepositoryCiJobResultReconcileDisposition Disposition,
    RepositoryCiJobSnapshot? Job,
    RepositoryCiJobExecutionSnapshot? Execution);

/// <summary>
/// Projects one exact runner-owned execution into the controller-owned job journal under the
/// current controller fence. Artifact interpretation remains a separate candidate gate.
/// </summary>
internal sealed class RepositoryCiJobResultReconciler(
    RepositoryCiJobJournal jobs,
    RepositoryCiJobExecutionJournal executions,
    IRepositoryCiJobResultEvidenceVerifier evidence)
{
    private readonly RepositoryCiJobJournal jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
    private readonly RepositoryCiJobExecutionJournal executions =
        executions ?? throw new ArgumentNullException(nameof(executions));
    private readonly IRepositoryCiJobResultEvidenceVerifier evidence =
        evidence ?? throw new ArgumentNullException(nameof(evidence));

    internal async Task<RepositoryCiJobResultReconcileReceipt> ReconcileAsync(
        RepositoryCiPipelinePlan pipeline,
        JobId jobId,
        string controllerId,
        long authorityEpoch,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(jobId);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        var acquired = await jobs.AcquireAsync(
            pipeline,
            jobId,
            controllerId,
            authorityEpoch,
            authorityStillValid,
            cancellationToken);
        if (acquired.Job is null)
            return Result(Map(acquired.Disposition), null, null);

        var job = acquired.Job;
        if (job.Phase is RepositoryCiJobPhase.Succeeded or RepositoryCiJobPhase.Failed)
        {
            var terminal = await executions.ReadAsync(
                job.RunnerId,
                pipeline.Digest,
                jobId.Value,
                cancellationToken);
            if (!ExactTerminal(job, terminal))
                return Result(RepositoryCiJobResultReconcileDisposition.IdentityConflict, job, terminal);
            if (terminal is null)
                throw new InvalidDataException("An exact terminal CI result has no execution evidence.");
            if (!await evidence.VerifyAsync(terminal, cancellationToken))
                return Result(RepositoryCiJobResultReconcileDisposition.EvidenceConflict, job, terminal);
            return Result(
                RepositoryCiJobResultReconcileDisposition.Duplicate,
                job,
                terminal);
        }
        if (job.Phase is not (RepositoryCiJobPhase.Dispatched or RepositoryCiJobPhase.Running))
            return Result(RepositoryCiJobResultReconcileDisposition.NotDispatchable, job, null);
        if (acquired.Disposition is not (RepositoryCiJobJournalDisposition.Resumed or
                RepositoryCiJobJournalDisposition.TakenOver))
            return Result(Map(acquired.Disposition), job, null);
        var execution = await executions.ReadAsync(
            job.RunnerId,
            pipeline.Digest,
            jobId.Value,
            cancellationToken);
        if (execution is null)
            return Result(
                job.Phase == RepositoryCiJobPhase.Dispatched
                    ? RepositoryCiJobResultReconcileDisposition.AwaitingExecution
                    : RepositoryCiJobResultReconcileDisposition.NotDispatchable,
                job,
                null);
        if (!Matches(job, execution))
            return Result(RepositoryCiJobResultReconcileDisposition.IdentityConflict, job, execution);
        if (execution.Phase == RepositoryCiJobExecutionPhase.Ready)
            return Result(
                job.Phase == RepositoryCiJobPhase.Dispatched
                    ? RepositoryCiJobResultReconcileDisposition.AwaitingExecution
                    : RepositoryCiJobResultReconcileDisposition.IdentityConflict,
                job,
                execution);
        if (execution.Phase is (RepositoryCiJobExecutionPhase.Succeeded or
                RepositoryCiJobExecutionPhase.Failed) &&
            !await evidence.VerifyAsync(execution, cancellationToken))
            return Result(RepositoryCiJobResultReconcileDisposition.EvidenceConflict, job, execution);

        if (job.Phase == RepositoryCiJobPhase.Dispatched)
        {
            var running = await jobs.AdvanceAsync(
                job,
                RepositoryCiJobPhase.Running,
                job.EvidenceDigest,
                0,
                RepositoryCiJobFailureKind.Unspecified,
                0,
                authorityStillValid,
                cancellationToken);
            if (running.Disposition is not (RepositoryCiJobJournalDisposition.Advanced or
                    RepositoryCiJobJournalDisposition.Duplicate) || running.Job is null)
                return Result(Map(running.Disposition), running.Job ?? job, execution);
            job = running.Job;
        }
        if (job.Phase != RepositoryCiJobPhase.Running)
            return Result(RepositoryCiJobResultReconcileDisposition.NotDispatchable, job, execution);
        if (execution.Phase == RepositoryCiJobExecutionPhase.Running)
            return Result(RepositoryCiJobResultReconcileDisposition.Running, job, execution);

        var succeeded = execution.Phase == RepositoryCiJobExecutionPhase.Succeeded;
        var completed = await jobs.AdvanceAsync(
            job,
            succeeded ? RepositoryCiJobPhase.Succeeded : RepositoryCiJobPhase.Failed,
            execution.EvidenceDigest,
            execution.RequiredTestSkips,
            execution.FailureKind,
            0,
            authorityStillValid,
            cancellationToken);
        return Result(
            completed.Disposition switch
            {
                RepositoryCiJobJournalDisposition.Advanced =>
                    RepositoryCiJobResultReconcileDisposition.Completed,
                RepositoryCiJobJournalDisposition.Duplicate =>
                    RepositoryCiJobResultReconcileDisposition.Duplicate,
                _ => Map(completed.Disposition),
            },
            completed.Job ?? job,
            execution);
    }

    private static bool Matches(
        RepositoryCiJobSnapshot job,
        RepositoryCiJobExecutionSnapshot execution)
    {
        var document = execution.Document;
        return document.Runner == job.RunnerId &&
            document.PipelineDigest == job.Document.PipelineDigest &&
            document.Job == job.Job.Request.Job.Value &&
            document.JobDigest == job.Document.JobDigest &&
            document.Generation == job.Job.Request.Generation &&
            document.Attempt == job.Attempt &&
            document.StreamSequence == job.DispatchStreamSequence &&
            (document.Phase == RepositoryCiJobExecutionPhase.Ready
                ? document.PayloadDigest == job.EvidenceDigest
                : document.LeaseId == job.OperationId);
    }

    private static bool ExactTerminal(
        RepositoryCiJobSnapshot job,
        RepositoryCiJobExecutionSnapshot? execution) => execution is not null &&
        Matches(job, execution) &&
        job.Phase == (execution.Phase == RepositoryCiJobExecutionPhase.Succeeded
            ? RepositoryCiJobPhase.Succeeded
            : execution.Phase == RepositoryCiJobExecutionPhase.Failed
                ? RepositoryCiJobPhase.Failed
                : RepositoryCiJobPhase.Unspecified) &&
        job.EvidenceDigest == execution.EvidenceDigest &&
        job.RequiredTestSkips == execution.RequiredTestSkips &&
        job.FailureKind == execution.FailureKind;

    private static RepositoryCiJobResultReconcileDisposition Map(
        RepositoryCiJobJournalDisposition disposition) => disposition switch
        {
            RepositoryCiJobJournalDisposition.StaleAuthority =>
                RepositoryCiJobResultReconcileDisposition.AuthorityLost,
            RepositoryCiJobJournalDisposition.LeaseHeld or RepositoryCiJobJournalDisposition.StaleLease =>
                RepositoryCiJobResultReconcileDisposition.LeaseHeld,
            RepositoryCiJobJournalDisposition.Contention =>
                RepositoryCiJobResultReconcileDisposition.Contention,
            RepositoryCiJobJournalDisposition.PhaseConflict =>
                RepositoryCiJobResultReconcileDisposition.NotDispatchable,
            _ => RepositoryCiJobResultReconcileDisposition.IdentityConflict,
        };

    private static RepositoryCiJobResultReconcileReceipt Result(
        RepositoryCiJobResultReconcileDisposition disposition,
        RepositoryCiJobSnapshot? job,
        RepositoryCiJobExecutionSnapshot? execution) => new(disposition, job, execution);
}

