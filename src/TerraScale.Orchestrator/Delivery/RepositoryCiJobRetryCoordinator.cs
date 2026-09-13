using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record RepositoryCiJobRetryAuthorization(
    string OperationId,
    string EvidenceDigest);

internal enum RepositoryCiJobRetryCoordinationDisposition
{
    Unspecified,
    Scheduled,
    Waiting,
    Opened,
    Duplicate,
    NotRetryable,
    AuthorizationMissing,
    AttemptsExhausted,
    AuthorityLost,
    LeaseHeld,
    IdentityConflict,
    Contention,
}

internal sealed record RepositoryCiJobRetryCoordinationReceipt(
    RepositoryCiJobRetryCoordinationDisposition Disposition,
    RepositoryCiJobSnapshot? Job,
    RepositoryCiJobRetryAuthorization? Authorization);

/// <summary>
/// Opens one bounded transient retry only from an injected evidence-backed authorization. The
/// journal owns delay, attempt, fencing, and idempotency enforcement.
/// </summary>
internal sealed class RepositoryCiJobRetryCoordinator(
    RepositoryCiJobJournal jobs,
    Func<RepositoryCiJobSnapshot, CancellationToken, Task<RepositoryCiJobRetryAuthorization?>> authorize)
{
    private readonly RepositoryCiJobJournal jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
    private readonly Func<RepositoryCiJobSnapshot, CancellationToken,
        Task<RepositoryCiJobRetryAuthorization?>> authorize =
        authorize ?? throw new ArgumentNullException(nameof(authorize));

    internal async Task<RepositoryCiJobRetryCoordinationReceipt> CoordinateAsync(
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
        if (!Identity(controllerId))
            throw new ArgumentException("The controller identity is invalid.", nameof(controllerId));
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        var current = (await jobs.ReadAsync(pipeline, cancellationToken)).Jobs
            .SingleOrDefault(value => value.Job.Request.Job == jobId)
            ?? throw new ArgumentException("The CI job is not part of the pipeline.", nameof(jobId));

        if (current.Phase is RepositoryCiJobPhase.RetryWaiting ||
            current.Phase == RepositoryCiJobPhase.Pending && current.Attempt > 1)
            return await OpenAsync(
                pipeline,
                jobId,
                controllerId,
                authorityEpoch,
                authorityStillValid,
                cancellationToken);
        if (current.Phase != RepositoryCiJobPhase.Failed ||
            !RepositoryCiJobJournal.Retryable(current.FailureKind) ||
            current.Job.Request.Kind != JobKind.ProductValidation)
            return Result(RepositoryCiJobRetryCoordinationDisposition.NotRetryable, current);
        if (current.Attempt >= current.Job.Request.MaximumAttempts)
            return Result(RepositoryCiJobRetryCoordinationDisposition.AttemptsExhausted, current);
        if (!authorityStillValid())
            return Result(RepositoryCiJobRetryCoordinationDisposition.AuthorityLost, current);

        var authorization = await authorize(current, cancellationToken);
        if (authorization is null)
            return Result(RepositoryCiJobRetryCoordinationDisposition.AuthorizationMissing, current);
        if (!Identity(authorization.OperationId) || !Digest(authorization.EvidenceDigest))
            throw new InvalidDataException("The CI retry authorizer returned invalid evidence.");
        if (!authorityStillValid())
            return Result(RepositoryCiJobRetryCoordinationDisposition.AuthorityLost, current, authorization);
        var scheduled = await jobs.ScheduleRetryAsync(
            pipeline,
            jobId,
            controllerId,
            authorityEpoch,
            authorization.OperationId,
            authorization.EvidenceDigest,
            authorityStillValid,
            cancellationToken);
        return Result(
            scheduled.Disposition switch
            {
                RepositoryCiJobJournalDisposition.RetryScheduled =>
                    RepositoryCiJobRetryCoordinationDisposition.Scheduled,
                RepositoryCiJobJournalDisposition.Duplicate =>
                    RepositoryCiJobRetryCoordinationDisposition.Duplicate,
                RepositoryCiJobJournalDisposition.RetryDenied =>
                    RepositoryCiJobRetryCoordinationDisposition.NotRetryable,
                RepositoryCiJobJournalDisposition.AttemptsExhausted =>
                    RepositoryCiJobRetryCoordinationDisposition.AttemptsExhausted,
                _ => Map(scheduled.Disposition),
            },
            scheduled.Job ?? current,
            authorization);
    }

    private async Task<RepositoryCiJobRetryCoordinationReceipt> OpenAsync(
        RepositoryCiPipelinePlan pipeline,
        JobId jobId,
        string controllerId,
        long authorityEpoch,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken)
    {
        var opened = await jobs.OpenRetryAsync(
            pipeline,
            jobId,
            controllerId,
            authorityEpoch,
            authorityStillValid,
            cancellationToken);
        return Result(
            opened.Disposition switch
            {
                RepositoryCiJobJournalDisposition.RetryOpened =>
                    RepositoryCiJobRetryCoordinationDisposition.Opened,
                RepositoryCiJobJournalDisposition.Duplicate =>
                    RepositoryCiJobRetryCoordinationDisposition.Duplicate,
                RepositoryCiJobJournalDisposition.NotReady =>
                    RepositoryCiJobRetryCoordinationDisposition.Waiting,
                _ => Map(opened.Disposition),
            },
            opened.Job);
    }

    private static RepositoryCiJobRetryCoordinationDisposition Map(
        RepositoryCiJobJournalDisposition disposition) => disposition switch
    {
        RepositoryCiJobJournalDisposition.StaleAuthority =>
            RepositoryCiJobRetryCoordinationDisposition.AuthorityLost,
        RepositoryCiJobJournalDisposition.LeaseHeld or RepositoryCiJobJournalDisposition.StaleLease =>
            RepositoryCiJobRetryCoordinationDisposition.LeaseHeld,
        RepositoryCiJobJournalDisposition.Contention =>
            RepositoryCiJobRetryCoordinationDisposition.Contention,
        _ => RepositoryCiJobRetryCoordinationDisposition.IdentityConflict,
    };

    private static bool Identity(string value) => value is { Length: >= 1 and <= 512 } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));

    private static bool Digest(string value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static RepositoryCiJobRetryCoordinationReceipt Result(
        RepositoryCiJobRetryCoordinationDisposition disposition,
        RepositoryCiJobSnapshot? job,
        RepositoryCiJobRetryAuthorization? authorization = null) => new(disposition, job, authorization);
}

