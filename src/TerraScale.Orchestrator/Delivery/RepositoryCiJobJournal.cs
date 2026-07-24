using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using Cysharp.Text;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiJobPhase
{
    Unspecified,
    Pending,
    DispatchPrepared,
    Dispatched,
    Running,
    Succeeded,
    Failed,
    RetryWaiting,
}

internal enum RepositoryCiJobFailureKind
{
    Unspecified,
    RunnerLost,
    InfrastructureTransient,
    WorkloadFailed,
    PolicyDenied,
}

internal enum RepositoryCiJobJournalDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    Prepared,
    Resumed,
    TakenOver,
    Advanced,
    RetryScheduled,
    RetryOpened,
    NotReady,
    RunnerDenied,
    RetryDenied,
    AttemptsExhausted,
    PipelineFailed,
    LeaseHeld,
    StaleAuthority,
    StaleLease,
    IdentityConflict,
    PhaseConflict,
    Contention,
}

internal enum RepositoryCiPipelineRunState
{
    Unspecified,
    Active,
    Succeeded,
    Failed,
}

internal sealed class RepositoryCiJobSnapshot
{
    internal RepositoryCiJobSnapshot(
        RepositoryCiPipelineJob job,
        RepositoryCiJobDocument document,
        ulong revision)
    {
        Job = job;
        Document = document;
        Revision = revision;
    }

    public RepositoryCiPipelineJob Job { get; }
    public RepositoryCiJobPhase Phase => Document.Phase;
    public string ControllerId => Document.ControllerId;
    public long AuthorityEpoch => Document.AuthorityEpoch;
    public long FencingToken => Document.FencingToken;
    public string RunnerId => Document.RunnerId;
    public long RunnerSequence => Document.RunnerSequence;
    public string OperationId => Document.OperationId;
    public string EvidenceDigest => Document.EvidenceDigest;
    public int RequiredTestSkips => Document.RequiredTestSkips;
    public int Attempt => Document.Attempt;
    public RepositoryCiJobFailureKind FailureKind => Document.FailureKind;
    public DateTimeOffset? RetryNotBefore => Document.RetryNotBeforeUnixMilliseconds == 0
        ? null
        : DateTimeOffset.FromUnixTimeMilliseconds(Document.RetryNotBeforeUnixMilliseconds);
    public DateTimeOffset? PreparedAt => Document.PreparedAtUnixMilliseconds == 0
        ? null
        : DateTimeOffset.FromUnixTimeMilliseconds(Document.PreparedAtUnixMilliseconds);
    public DateTimeOffset? ExpiresAt => Document.ExpiresAtUnixMilliseconds == 0
        ? null
        : DateTimeOffset.FromUnixTimeMilliseconds(Document.ExpiresAtUnixMilliseconds);
    public ulong DispatchStreamSequence => Document.DispatchStreamSequence;
    public bool LegacyDispatchWithoutAcknowledgement => Document.LegacyDispatchWithoutAcknowledgement;
    public string SourceBundleObject => Document.SourceBundleObject;
    public string SourceBundleSha256 => Document.SourceBundleSha256;
    public int SourceBundleBytes => Document.SourceBundleBytes;
    public bool LegacyDispatchWithoutSourceBundle => Document.LegacyDispatchWithoutSourceBundle;
    internal RepositoryCiJobDocument Document { get; }
    internal ulong Revision { get; }
}

internal sealed record RepositoryCiJobJournalReceipt(
    RepositoryCiJobJournalDisposition Disposition,
    RepositoryCiJobSnapshot? Job);

internal sealed record RepositoryCiPipelineRunSnapshot(
    RepositoryCiPipelineRunState State,
    IReadOnlyList<RepositoryCiJobSnapshot> Jobs,
    IReadOnlyList<RepositoryCiPipelineJob> Ready,
    IReadOnlyList<RepositoryCiJobResult> Results);

/// <summary>Persists one fenced execution record per immutable affected-pipeline job.</summary>
internal sealed class RepositoryCiJobJournal
{
    private const int MaximumRecordBytes = 16 * 1024;
    private const int MaximumConflictRetries = 8;
    private static readonly TimeSpan DispatchLifetime = TimeSpan.FromHours(2);
    private readonly IForgejoDeliveryLedger ledger;
    private readonly TimeProvider timeProvider;

    internal RepositoryCiJobJournal(IForgejoDeliveryLedger ledger, TimeProvider? timeProvider = null)
    {
        this.ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));
        this.timeProvider = timeProvider ?? TimeProvider.System;
    }

    internal async Task<RepositoryCiJobJournalDisposition> InitializeAsync(
        RepositoryCiPipelinePlan pipeline,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ValidatePlan(pipeline);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        var recorded = false;
        foreach (var job in pipeline.Jobs)
        {
            var proposed = RepositoryCiJobDocument.Pending(
                pipeline,
                job,
                JobDigest(pipeline, job),
                authorityEpoch,
                sequence);
            proposed.Validate();
            var key = Index(pipeline.Digest, job.Request.Job.Value);
            var completed = false;
            for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
            {
                var entry = await ledger.GetAsync(key, cancellationToken);
                if (entry is not null)
                {
                    var observed = Deserialize(entry.Value);
                    if (!observed.SameJob(proposed)) return RepositoryCiJobJournalDisposition.IdentityConflict;
                    completed = true;
                    break;
                }
                if (!authorityStillValid()) return RepositoryCiJobJournalDisposition.StaleAuthority;
                try
                {
                    await ledger.CreateAsync(key, Serialize(proposed), cancellationToken);
                    recorded = completed = true;
                    break;
                }
                catch (ForgejoDeliveryLedgerConflictException)
                {
                }
            }
            if (!completed) return RepositoryCiJobJournalDisposition.Contention;
        }
        return recorded ? RepositoryCiJobJournalDisposition.Recorded : RepositoryCiJobJournalDisposition.Duplicate;
    }

    internal async Task<RepositoryCiPipelineRunSnapshot> ReadAsync(
        RepositoryCiPipelinePlan pipeline,
        CancellationToken cancellationToken = default)
    {
        ValidatePlan(pipeline);
        var snapshots = new List<RepositoryCiJobSnapshot>(pipeline.Jobs.Count);
        foreach (var job in pipeline.Jobs)
        {
            var entry = await ledger.GetAsync(Index(pipeline.Digest, job.Request.Job.Value), cancellationToken)
                ?? throw new InvalidDataException("A CI pipeline job record is missing.");
            var document = Deserialize(entry.Value);
            if (document.PipelineDigest != pipeline.Digest ||
                document.JobDigest != JobDigest(pipeline, job) || document.Job != job.Request.Job.Value ||
                document.Attempt > job.Request.MaximumAttempts)
                throw new InvalidDataException("A CI pipeline job record changed immutable identity.");
            snapshots.Add(new(EffectiveJob(job, document.Attempt), document, entry.Revision));
        }

        var byId = snapshots.ToDictionary(static snapshot => snapshot.Job.Request.Job.Value, StringComparer.Ordinal);
        var state = snapshots.Any(static snapshot => snapshot.Phase == RepositoryCiJobPhase.Failed)
            ? RepositoryCiPipelineRunState.Failed
            : snapshots.All(static snapshot => snapshot.Phase == RepositoryCiJobPhase.Succeeded)
                ? RepositoryCiPipelineRunState.Succeeded
                : RepositoryCiPipelineRunState.Active;
        var ready = state == RepositoryCiPipelineRunState.Active
            ? snapshots.Where(snapshot => snapshot.Phase == RepositoryCiJobPhase.Pending &&
                    snapshot.Job.DependsOn.All(dependency =>
                        byId[dependency.Value].Phase == RepositoryCiJobPhase.Succeeded))
                .Select(static snapshot => snapshot.Job).ToArray()
            : [];
        var results = snapshots.Where(static snapshot => snapshot.Phase is
                RepositoryCiJobPhase.Succeeded or RepositoryCiJobPhase.Failed)
            .Select(static snapshot => new RepositoryCiJobResult(
                snapshot.Job.Request.Job,
                snapshot.Attempt,
                snapshot.Phase == RepositoryCiJobPhase.Succeeded,
                snapshot.RequiredTestSkips,
                snapshot.EvidenceDigest))
            .ToArray();
        return new(
            state,
            Array.AsReadOnly(snapshots.ToArray()),
            Array.AsReadOnly(ready),
            Array.AsReadOnly(results));
    }

    internal async Task<RepositoryCiJobJournalReceipt> PrepareDispatchAsync(
        RepositoryCiPipelinePlan pipeline,
        JobId jobId,
        RepositoryCiSourceBundle sourceBundle,
        RunnerEvidence runner,
        CiRunnerIsolationEvidence isolation,
        string controllerId,
        long authorityEpoch,
        string operationId,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ValidatePlan(pipeline);
        ArgumentNullException.ThrowIfNull(jobId);
        ArgumentNullException.ThrowIfNull(sourceBundle);
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(isolation);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        ValidateIdentity(controllerId, nameof(controllerId));
        ValidateIdentity(operationId, nameof(operationId));
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        var plannedBase = pipeline.Jobs.SingleOrDefault(job => job.Request.Job == jobId)
            ?? throw new ArgumentException("The CI job is not part of the pipeline.", nameof(jobId));
        ValidateSourceBundle(plannedBase, sourceBundle);
        var isolationDigest = IsolationDigest(isolation);

        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var run = await ReadAsync(pipeline, cancellationToken);
            if (run.State == RepositoryCiPipelineRunState.Failed)
                return new(RepositoryCiJobJournalDisposition.PipelineFailed, null);
            var current = run.Jobs.Single(job => job.Job.Request.Job == jobId);
            var planned = current.Job;
            if (current.Document.JobDigest != JobDigest(pipeline, plannedBase) ||
                current.Attempt > plannedBase.Request.MaximumAttempts)
                throw new InvalidDataException("The CI job changed immutable retry identity.");
            var admission = CiRunnerIsolationPolicy.Evaluate(planned.Request, runner, isolation);
            if (!admission.Accepted) return new(RepositoryCiJobJournalDisposition.RunnerDenied, current);
            if (current.Phase == RepositoryCiJobPhase.DispatchPrepared)
            {
                var exactLease = current.ControllerId == controllerId && current.AuthorityEpoch == authorityEpoch &&
                    current.RunnerId == runner.Runner.Value && current.RunnerSequence == runner.Sequence &&
                    current.OperationId == operationId && current.Document.IsolationDigest == isolationDigest;
                if (exactLease) return new(!SameSourceBundle(current.Document, sourceBundle)
                    ? RepositoryCiJobJournalDisposition.IdentityConflict
                    : authorityStillValid()
                        ? RepositoryCiJobJournalDisposition.Duplicate
                        : RepositoryCiJobJournalDisposition.StaleAuthority, current);
                return new(authorityEpoch < current.AuthorityEpoch
                    ? RepositoryCiJobJournalDisposition.StaleAuthority
                    : RepositoryCiJobJournalDisposition.LeaseHeld, current);
            }
            if (current.Phase != RepositoryCiJobPhase.Pending)
                return new(RepositoryCiJobJournalDisposition.PhaseConflict, current);
            if (authorityEpoch < current.AuthorityEpoch)
                return new(RepositoryCiJobJournalDisposition.StaleAuthority, current);
            if (!run.Ready.Any(job => job.Request.Job == jobId))
                return new(RepositoryCiJobJournalDisposition.NotReady, current);
            if (current.SourceBundleSha256.Length != 0 && !SameSourceBundle(current.Document, sourceBundle))
                return new(RepositoryCiJobJournalDisposition.IdentityConflict, current);
            if (!authorityStillValid())
                return new(RepositoryCiJobJournalDisposition.StaleAuthority, current);

            RepositoryCiJobDocument prepared;
            try
            {
                var preparedAt = timeProvider.GetUtcNow();
                prepared = current.Document with
                {
                    SchemaVersion = 5,
                    PreviousPhase = RepositoryCiJobPhase.Pending,
                    Phase = RepositoryCiJobPhase.DispatchPrepared,
                    PhaseSequence = 1,
                    ControllerId = controllerId,
                    AuthorityEpoch = authorityEpoch,
                    FencingToken = checked(current.FencingToken + 1),
                    RunnerId = runner.Runner.Value,
                    RunnerSequence = runner.Sequence,
                    IsolationDigest = isolationDigest,
                    OperationId = operationId,
                    EvidenceDigest = isolationDigest,
                    PreparedAtUnixMilliseconds = preparedAt.ToUnixTimeMilliseconds(),
                    ExpiresAtUnixMilliseconds = preparedAt.Add(DispatchLifetime).ToUnixTimeMilliseconds(),
                    SourceBundleObject = sourceBundle.ObjectName,
                    SourceBundleSha256 = sourceBundle.ContentSha256,
                    SourceBundleBytes = sourceBundle.ContentLength,
                    LegacyDispatchWithoutSourceBundle = false,
                };
            }
            catch (ArgumentOutOfRangeException exception)
            {
                throw new InvalidDataException("The CI job deadline exceeded the supported clock range.", exception);
            }
            catch (OverflowException exception)
            {
                throw new InvalidDataException("The CI job fencing token is exhausted.", exception);
            }
            prepared.Validate();
            try
            {
                var updated = await ledger.UpdateAsync(
                    Index(pipeline.Digest, jobId.Value),
                    Serialize(prepared),
                    current.Revision,
                    cancellationToken);
                return new(RepositoryCiJobJournalDisposition.Prepared, new(planned, prepared, updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }
        return new(RepositoryCiJobJournalDisposition.Contention, null);
    }

    internal async Task<RepositoryCiJobJournalReceipt> AcquireAsync(
        RepositoryCiPipelinePlan pipeline,
        JobId jobId,
        string controllerId,
        long authorityEpoch,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ValidatePlan(pipeline);
        ArgumentNullException.ThrowIfNull(jobId);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        ValidateIdentity(controllerId, nameof(controllerId));
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        var plannedBase = pipeline.Jobs.SingleOrDefault(job => job.Request.Job == jobId)
            ?? throw new ArgumentException("The CI job is not part of the pipeline.", nameof(jobId));
        var key = Index(pipeline.Digest, jobId.Value);
        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken)
                ?? throw new InvalidDataException("The CI job lease disappeared.");
            var document = Deserialize(entry.Value);
            if (document.JobDigest != JobDigest(pipeline, plannedBase) ||
                document.Attempt > plannedBase.Request.MaximumAttempts)
                throw new InvalidDataException("The CI job lease changed immutable identity.");
            var planned = EffectiveJob(plannedBase, document.Attempt);
            var snapshot = new RepositoryCiJobSnapshot(planned, document, entry.Revision);
            if (document.Phase is not (RepositoryCiJobPhase.DispatchPrepared or
                    RepositoryCiJobPhase.Dispatched or RepositoryCiJobPhase.Running))
                return new(RepositoryCiJobJournalDisposition.PhaseConflict, snapshot);
            if (authorityEpoch < document.AuthorityEpoch)
                return new(RepositoryCiJobJournalDisposition.StaleAuthority, snapshot);
            if (authorityEpoch == document.AuthorityEpoch)
                return new(controllerId == document.ControllerId
                    ? authorityStillValid()
                        ? RepositoryCiJobJournalDisposition.Resumed
                        : RepositoryCiJobJournalDisposition.StaleAuthority
                    : RepositoryCiJobJournalDisposition.LeaseHeld, snapshot);
            if (!authorityStillValid())
                return new(RepositoryCiJobJournalDisposition.StaleAuthority, snapshot);
            RepositoryCiJobDocument takeover;
            try
            {
                takeover = document with
                {
                    ControllerId = controllerId,
                    AuthorityEpoch = authorityEpoch,
                    FencingToken = checked(document.FencingToken + 1),
                };
            }
            catch (OverflowException exception)
            {
                throw new InvalidDataException("The CI job fencing token is exhausted.", exception);
            }
            takeover.Validate();
            try
            {
                var updated = await ledger.UpdateAsync(key, Serialize(takeover), entry.Revision, cancellationToken);
                return new(RepositoryCiJobJournalDisposition.TakenOver, new(planned, takeover, updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }
        return new(RepositoryCiJobJournalDisposition.Contention, null);
    }

    internal async Task<RepositoryCiJobJournalReceipt> AdvanceAsync(
        RepositoryCiJobSnapshot lease,
        RepositoryCiJobPhase nextPhase,
        string evidenceDigest,
        int requiredTestSkips,
        RepositoryCiJobFailureKind failureKind,
        ulong dispatchStreamSequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (!Digest(evidenceDigest)) throw new ArgumentException("CI job evidence digest is invalid.", nameof(evidenceDigest));
        if (requiredTestSkips is < 0 or > 1_000_000) throw new ArgumentOutOfRangeException(nameof(requiredTestSkips));
        if (nextPhase is not (RepositoryCiJobPhase.Dispatched or RepositoryCiJobPhase.Running or
                RepositoryCiJobPhase.Succeeded or RepositoryCiJobPhase.Failed))
            throw new ArgumentOutOfRangeException(nameof(nextPhase));
        if (nextPhase is not (RepositoryCiJobPhase.Succeeded or RepositoryCiJobPhase.Failed) && requiredTestSkips != 0)
            throw new ArgumentException("Only a terminal CI job result can report required test skips.", nameof(requiredTestSkips));
        if (nextPhase == RepositoryCiJobPhase.Failed && failureKind == RepositoryCiJobFailureKind.Unspecified ||
            nextPhase != RepositoryCiJobPhase.Failed && failureKind != RepositoryCiJobFailureKind.Unspecified ||
            !Enum.IsDefined(failureKind))
            throw new ArgumentException("The CI job failure classification does not match its phase.", nameof(failureKind));
        if (nextPhase == RepositoryCiJobPhase.Dispatched && dispatchStreamSequence == 0 ||
            nextPhase != RepositoryCiJobPhase.Dispatched && dispatchStreamSequence != 0)
            throw new ArgumentException("The CI job stream sequence does not match its phase.", nameof(dispatchStreamSequence));
        var key = Index(lease.Document.PipelineDigest, lease.Document.Job);
        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken)
                ?? throw new InvalidDataException("The CI job lease disappeared.");
            var current = Deserialize(entry.Value);
            var observed = new RepositoryCiJobSnapshot(lease.Job, current, entry.Revision);
            if (!current.SameLease(lease.Document))
                return new(RepositoryCiJobJournalDisposition.StaleLease, observed);
            if (current.Phase == nextPhase)
                return new(current.EvidenceDigest == evidenceDigest && current.RequiredTestSkips == requiredTestSkips &&
                    (nextPhase != RepositoryCiJobPhase.Dispatched ||
                        current.DispatchStreamSequence == dispatchStreamSequence)
                    ? authorityStillValid()
                        ? RepositoryCiJobJournalDisposition.Duplicate
                        : RepositoryCiJobJournalDisposition.StaleAuthority
                    : RepositoryCiJobJournalDisposition.PhaseConflict, observed);
            if (current.Phase != lease.Phase || !Allowed(current.Phase, nextPhase))
                return new(RepositoryCiJobJournalDisposition.PhaseConflict, observed);
            if (!authorityStillValid())
                return new(RepositoryCiJobJournalDisposition.StaleAuthority, observed);
            var advanced = current with
            {
                PreviousPhase = current.Phase,
                Phase = nextPhase,
                PhaseSequence = checked(current.PhaseSequence + 1),
                EvidenceDigest = evidenceDigest,
                RequiredTestSkips = requiredTestSkips,
                FailureKind = failureKind,
                DispatchStreamSequence = nextPhase == RepositoryCiJobPhase.Dispatched
                    ? dispatchStreamSequence
                    : current.DispatchStreamSequence,
                LegacyDispatchWithoutAcknowledgement = nextPhase == RepositoryCiJobPhase.Dispatched
                    ? false
                    : current.LegacyDispatchWithoutAcknowledgement,
            };
            advanced.Validate();
            try
            {
                var updated = await ledger.UpdateAsync(key, Serialize(advanced), entry.Revision, cancellationToken);
                return new(RepositoryCiJobJournalDisposition.Advanced, new(lease.Job, advanced, updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }
        return new(RepositoryCiJobJournalDisposition.Contention, null);
    }

    internal async Task<RepositoryCiJobJournalReceipt> ScheduleRetryAsync(
        RepositoryCiPipelinePlan pipeline,
        JobId jobId,
        string controllerId,
        long authorityEpoch,
        string operationId,
        string authorizationDigest,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ValidatePlan(pipeline);
        ArgumentNullException.ThrowIfNull(jobId);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        ValidateIdentity(controllerId, nameof(controllerId));
        ValidateIdentity(operationId, nameof(operationId));
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (!Digest(authorizationDigest))
            throw new ArgumentException("The CI retry authorization digest is invalid.", nameof(authorizationDigest));
        var plannedBase = pipeline.Jobs.SingleOrDefault(job => job.Request.Job == jobId)
            ?? throw new ArgumentException("The CI job is not part of the pipeline.", nameof(jobId));
        var key = Index(pipeline.Digest, jobId.Value);

        for (var conflict = 0; conflict < MaximumConflictRetries; conflict++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken)
                ?? throw new InvalidDataException("The failed CI job disappeared.");
            var current = Deserialize(entry.Value);
            if (current.JobDigest != JobDigest(pipeline, plannedBase) ||
                current.Attempt > plannedBase.Request.MaximumAttempts)
                throw new InvalidDataException("The failed CI job changed immutable identity.");
            var planned = EffectiveJob(plannedBase, current.Attempt);
            var snapshot = new RepositoryCiJobSnapshot(planned, current, entry.Revision);
            if (current.Phase == RepositoryCiJobPhase.RetryWaiting)
            {
                var exact = current.ControllerId == controllerId && current.AuthorityEpoch == authorityEpoch &&
                    current.OperationId == operationId && current.RetryAuthorizationDigest == authorizationDigest;
                return new(exact
                    ? authorityStillValid()
                        ? RepositoryCiJobJournalDisposition.Duplicate
                        : RepositoryCiJobJournalDisposition.StaleAuthority
                    : RepositoryCiJobJournalDisposition.PhaseConflict, snapshot);
            }
            if (current.Phase != RepositoryCiJobPhase.Failed)
                return new(RepositoryCiJobJournalDisposition.PhaseConflict, snapshot);
            if (plannedBase.Request.Kind != JobKind.ProductValidation || !Retryable(current.FailureKind))
                return new(RepositoryCiJobJournalDisposition.RetryDenied, snapshot);
            if (current.Attempt >= plannedBase.Request.MaximumAttempts)
                return new(RepositoryCiJobJournalDisposition.AttemptsExhausted, snapshot);
            if (authorityEpoch < current.AuthorityEpoch)
                return new(RepositoryCiJobJournalDisposition.StaleAuthority, snapshot);
            if (authorityEpoch == current.AuthorityEpoch && controllerId != current.ControllerId)
                return new(RepositoryCiJobJournalDisposition.LeaseHeld, snapshot);
            if (!authorityStillValid())
                return new(RepositoryCiJobJournalDisposition.StaleAuthority, snapshot);

            RepositoryCiJobDocument waiting;
            try
            {
                var retryNotBefore = timeProvider.GetUtcNow().Add(RetryDelay(current.Attempt));
                waiting = current with
                {
                    SchemaVersion = 5,
                    PreviousPhase = RepositoryCiJobPhase.Failed,
                    Phase = RepositoryCiJobPhase.RetryWaiting,
                    PhaseSequence = 5,
                    ControllerId = controllerId,
                    AuthorityEpoch = authorityEpoch,
                    FencingToken = checked(current.FencingToken + 1),
                    OperationId = operationId,
                    AttemptChainDigest = AttemptChainDigest(current, authorizationDigest),
                    RetryAuthorizationDigest = authorizationDigest,
                    RetryNotBeforeUnixMilliseconds = retryNotBefore.ToUnixTimeMilliseconds(),
                };
            }
            catch (ArgumentOutOfRangeException exception)
            {
                throw new InvalidDataException("The CI retry deadline exceeded the supported clock range.", exception);
            }
            catch (OverflowException exception)
            {
                throw new InvalidDataException("The CI job fencing token is exhausted.", exception);
            }
            waiting.Validate();
            try
            {
                var updated = await ledger.UpdateAsync(key, Serialize(waiting), entry.Revision, cancellationToken);
                return new(
                    RepositoryCiJobJournalDisposition.RetryScheduled,
                    new(planned, waiting, updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }
        return new(RepositoryCiJobJournalDisposition.Contention, null);
    }

    internal async Task<RepositoryCiJobJournalReceipt> OpenRetryAsync(
        RepositoryCiPipelinePlan pipeline,
        JobId jobId,
        string controllerId,
        long authorityEpoch,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ValidatePlan(pipeline);
        ArgumentNullException.ThrowIfNull(jobId);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        ValidateIdentity(controllerId, nameof(controllerId));
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        var plannedBase = pipeline.Jobs.SingleOrDefault(job => job.Request.Job == jobId)
            ?? throw new ArgumentException("The CI job is not part of the pipeline.", nameof(jobId));
        var key = Index(pipeline.Digest, jobId.Value);

        for (var conflict = 0; conflict < MaximumConflictRetries; conflict++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken)
                ?? throw new InvalidDataException("The retrying CI job disappeared.");
            var current = Deserialize(entry.Value);
            if (current.JobDigest != JobDigest(pipeline, plannedBase) ||
                current.Attempt > plannedBase.Request.MaximumAttempts)
                throw new InvalidDataException("The retrying CI job changed immutable identity.");
            var planned = EffectiveJob(plannedBase, current.Attempt);
            var snapshot = new RepositoryCiJobSnapshot(planned, current, entry.Revision);
            if (current.Phase == RepositoryCiJobPhase.Pending && current.Attempt > 1)
                return new(authorityEpoch < current.AuthorityEpoch || !authorityStillValid()
                    ? RepositoryCiJobJournalDisposition.StaleAuthority
                    : RepositoryCiJobJournalDisposition.Duplicate, snapshot);
            if (current.Phase != RepositoryCiJobPhase.RetryWaiting)
                return new(RepositoryCiJobJournalDisposition.PhaseConflict, snapshot);
            if (authorityEpoch < current.AuthorityEpoch)
                return new(RepositoryCiJobJournalDisposition.StaleAuthority, snapshot);
            if (authorityEpoch == current.AuthorityEpoch && controllerId != current.ControllerId)
                return new(RepositoryCiJobJournalDisposition.LeaseHeld, snapshot);
            if (!authorityStillValid())
                return new(RepositoryCiJobJournalDisposition.StaleAuthority, snapshot);
            if (timeProvider.GetUtcNow().ToUnixTimeMilliseconds() < current.RetryNotBeforeUnixMilliseconds)
                return new(RepositoryCiJobJournalDisposition.NotReady, snapshot);

            RepositoryCiJobDocument pending;
            try
            {
                pending = current with
                {
                    SchemaVersion = 5,
                    PreviousPhase = RepositoryCiJobPhase.RetryWaiting,
                    Phase = RepositoryCiJobPhase.Pending,
                    PhaseSequence = 0,
                    Attempt = checked(current.Attempt + 1),
                    ControllerId = string.Empty,
                    AuthorityEpoch = authorityEpoch,
                    FencingToken = authorityEpoch > current.AuthorityEpoch
                        ? checked(current.FencingToken + 1)
                        : current.FencingToken,
                    RunnerId = string.Empty,
                    RunnerSequence = 0,
                    IsolationDigest = string.Empty,
                    OperationId = string.Empty,
                    EvidenceDigest = string.Empty,
                    RequiredTestSkips = 0,
                    RetryNotBeforeUnixMilliseconds = 0,
                    FailureKind = RepositoryCiJobFailureKind.Unspecified,
                    PreparedAtUnixMilliseconds = 0,
                    ExpiresAtUnixMilliseconds = 0,
                    DispatchStreamSequence = 0,
                    LegacyDispatchWithoutAcknowledgement = false,
                };
            }
            catch (OverflowException exception)
            {
                throw new InvalidDataException("The CI retry identity is exhausted.", exception);
            }
            pending.Validate();
            try
            {
                var updated = await ledger.UpdateAsync(key, Serialize(pending), entry.Revision, cancellationToken);
                return new(
                    RepositoryCiJobJournalDisposition.RetryOpened,
                    new(EffectiveJob(plannedBase, pending.Attempt), pending, updated.Revision));
            }
            catch (ForgejoDeliveryLedgerConflictException)
            {
            }
        }
        return new(RepositoryCiJobJournalDisposition.Contention, null);
    }

    private static bool Allowed(RepositoryCiJobPhase current, RepositoryCiJobPhase next) => (current, next) switch
    {
        (RepositoryCiJobPhase.DispatchPrepared, RepositoryCiJobPhase.Dispatched) => true,
        (RepositoryCiJobPhase.Dispatched, RepositoryCiJobPhase.Running) => true,
        (RepositoryCiJobPhase.Running, RepositoryCiJobPhase.Succeeded or RepositoryCiJobPhase.Failed) => true,
        _ => false,
    };

    private static void ValidatePlan(RepositoryCiPipelinePlan pipeline)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        if (!Digest(pipeline.Digest) || !Digest(pipeline.ImpactDigest) ||
            pipeline.Pipeline?.Value != $"ci-{pipeline.Digest[..24]}" ||
            pipeline.Jobs is not { Count: > 0 and <= 16_384 } ||
            pipeline.Jobs.Any(job => job is null || job.Request?.Job?.Value is not { Length: > 0 } ||
                job.Request.Pipeline != pipeline.Pipeline || job.Request.Attempt != 1 ||
                job.Request.MaximumAttempts != 3 || job.Request.RetryAuthorized) ||
            pipeline.Jobs.Select(static job => job.Request.Job.Value).Distinct(StringComparer.Ordinal).Count() !=
            pipeline.Jobs.Count)
            throw new InvalidDataException("The CI pipeline cannot initialize durable job state.");
    }

    private static RepositoryCiPipelineJob EffectiveJob(RepositoryCiPipelineJob planned, int attempt)
    {
        if (attempt == planned.Request.Attempt) return planned;
        if (attempt <= planned.Request.Attempt || attempt > planned.Request.MaximumAttempts)
            throw new InvalidDataException("The CI job attempt is outside its immutable retry budget.");
        var request = planned.Request;
        return new(
            planned.Plan,
            planned.Source,
            new(
                request.Pipeline,
                request.Job,
                request.Kind,
                request.Tree,
                request.Generation,
                attempt,
                request.MaximumAttempts,
                new($"ci-{Hash($"{request.Idempotency.Value}\n{attempt}")}"),
                request.AllowedZones,
                request.RequiredCapabilities,
                request.MinimumRunnerSequence,
                request.MaximumRunnerSequence,
                retryAuthorized: true),
            planned.DependsOn,
            planned.MayPublishCandidateArtifact);
    }

    internal static bool Retryable(RepositoryCiJobFailureKind failure) => failure is
        RepositoryCiJobFailureKind.RunnerLost or RepositoryCiJobFailureKind.InfrastructureTransient;

    private static TimeSpan RetryDelay(int failedAttempt) => failedAttempt switch
    {
        1 => TimeSpan.FromSeconds(5),
        2 => TimeSpan.FromSeconds(30),
        _ => throw new InvalidDataException("The CI retry delay has no bounded policy."),
    };

    private static string AttemptChainDigest(
        RepositoryCiJobDocument failed,
        string authorizationDigest)
    {
        using var value = ZString.CreateStringBuilder();
        value.Append(failed.AttemptChainDigest);
        value.Append('\n');
        value.Append(failed.JobDigest);
        value.Append(':');
        value.Append(failed.Attempt);
        value.Append(':');
        value.Append(failed.EvidenceDigest);
        value.Append(':');
        value.Append(failed.FailureKind);
        value.Append('\n');
        value.Append(failed.ControllerId);
        value.Append(':');
        value.Append(failed.AuthorityEpoch);
        value.Append(':');
        value.Append(failed.FencingToken);
        value.Append(':');
        value.Append(failed.RunnerId);
        value.Append(':');
        value.Append(failed.OperationId);
        value.Append('\n');
        value.Append(authorizationDigest);
        return Hash(value.ToString());
    }

    internal static string JobDigest(RepositoryCiPipelinePlan pipeline, RepositoryCiPipelineJob job)
    {
        var request = job.Request;
        using var value = new ZStringWriter();
        value.Write(pipeline.Digest);
        value.Write('\n');
        value.Write(pipeline.ImpactDigest);
        value.Write('\n');
        value.Write(job.Plan.Id);
        value.Write(':');
        value.Write(job.Plan.Repository);
        value.Write(':');
        value.Write(job.Plan.Node.Id);
        value.Write(':');
        value.Write(job.Plan.Node.Kind);
        value.Write(':');
        value.Write(job.Plan.Node.ResourceWeight);
        value.Write(':');
        value.Write(string.Join(',', job.Plan.Node.Architectures));
        value.Write('\n');
        value.Write(job.Source.Repository);
        value.Write(':');
        value.Write(job.Source.Commit);
        value.Write(':');
        value.Write(job.Source.Tree);
        value.Write(':');
        value.Write(job.Source.SignatureVerified ? '1' : '0');
        value.Write('\n');
        value.Write(request.Pipeline.Value);
        value.Write(':');
        value.Write(request.Job.Value);
        value.Write(':');
        value.Write(request.Kind);
        value.Write(':');
        value.Write(request.Tree.Value);
        value.Write(':');
        value.Write(request.Generation);
        value.Write(':');
        value.Write(request.Attempt);
        value.Write(':');
        value.Write(request.MaximumAttempts);
        value.Write(':');
        value.Write(request.Idempotency.Value);
        value.Write(':');
        value.Write(request.MinimumRunnerSequence);
        value.Write(':');
        value.Write(request.MaximumRunnerSequence);
        value.Write(':');
        value.Write(request.RetryAuthorized ? '1' : '0');
        value.Write('\n');
        value.Write(string.Join(',', request.AllowedZones));
        value.Write('\n');
        value.Write(string.Join(',', request.RequiredCapabilities));
        value.Write('\n');
        value.Write(string.Join(',', job.DependsOn.Select(static dependency => dependency.Value)));
        value.Write('\n');
        value.Write(job.MayPublishCandidateArtifact ? '1' : '0');
        return Hash(value.ToString());
    }

    internal static string IsolationDigest(CiRunnerIsolationEvidence value)
    {
        var content = JsonSerializer.SerializeToUtf8Bytes(
            value,
            RepositoryCiJobJournalJsonContext.Default.CiRunnerIsolationEvidence);
        return Convert.ToHexStringLower(SHA256.HashData(content));
    }

    private static RepositoryCiJobDocument Deserialize(string value)
    {
        try
        {
            if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes) throw new JsonException();
            var document = JsonSerializer.Deserialize(
                value,
                RepositoryCiJobJournalJsonContext.Default.RepositoryCiJobDocument) ?? throw new JsonException();
            if (document.SchemaVersion == 1)
            {
                if (document.Attempt != 0 || document.AttemptChainDigest is not null ||
                    document.RetryAuthorizationDigest is not null || document.RetryNotBeforeUnixMilliseconds != 0 ||
                    document.FailureKind != RepositoryCiJobFailureKind.Unspecified ||
                    document.PreparedAtUnixMilliseconds != 0 || document.ExpiresAtUnixMilliseconds != 0 ||
                    document.DispatchStreamSequence != 0 || document.LegacyDispatchWithoutAcknowledgement)
                    throw new JsonException();
                document = document with
                {
                    SchemaVersion = 2,
                    Attempt = 1,
                    AttemptChainDigest = string.Empty,
                    RetryAuthorizationDigest = string.Empty,
                    FailureKind = document.Phase == RepositoryCiJobPhase.Failed
                        ? RepositoryCiJobFailureKind.WorkloadFailed
                        : RepositoryCiJobFailureKind.Unspecified,
                };
            }
            if (document.SchemaVersion == 2)
            {
                if (document.PreparedAtUnixMilliseconds != 0 || document.ExpiresAtUnixMilliseconds != 0)
                    throw new JsonException();
                var active = document.Phase != RepositoryCiJobPhase.Pending;
                document = document with
                {
                    SchemaVersion = 3,
                    PreparedAtUnixMilliseconds = active ? 1 : 0,
                    ExpiresAtUnixMilliseconds = active ? 2 : 0,
                };
            }
            if (document.SchemaVersion == 3)
            {
                if (document.DispatchStreamSequence != 0 || document.LegacyDispatchWithoutAcknowledgement)
                    throw new JsonException();
                var legacyDispatch = document.Phase is RepositoryCiJobPhase.Dispatched or
                    RepositoryCiJobPhase.Running or RepositoryCiJobPhase.Succeeded or
                    RepositoryCiJobPhase.Failed or RepositoryCiJobPhase.RetryWaiting;
                document = document with
                {
                    SchemaVersion = 4,
                    LegacyDispatchWithoutAcknowledgement = legacyDispatch,
                };
            }
            if (document.SchemaVersion == 4)
            {
                if (document.SourceBundleObject is not null || document.SourceBundleSha256 is not null ||
                    document.SourceBundleBytes != 0 || document.LegacyDispatchWithoutSourceBundle)
                    throw new JsonException();
                document = document with
                {
                    SchemaVersion = 5,
                    SourceBundleObject = string.Empty,
                    SourceBundleSha256 = string.Empty,
                    LegacyDispatchWithoutSourceBundle = document.Phase != RepositoryCiJobPhase.Pending,
                };
            }
            document.Validate();
            return document;
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("A CI job journal record is invalid.", exception);
        }
    }

    private static string Serialize(RepositoryCiJobDocument document)
    {
        var value = JsonSerializer.Serialize(document, RepositoryCiJobJournalJsonContext.Default.RepositoryCiJobDocument);
        if (Encoding.UTF8.GetByteCount(value) > MaximumRecordBytes)
            throw new InvalidDataException("The CI job journal record exceeded its bound.");
        return value;
    }

    private static string Index(string pipelineDigest, string job) =>
        $"ci-job.{pipelineDigest}.{Hash(job)[..32]}";

    private static string Hash(string value) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static void ValidateSourceBundle(
        RepositoryCiPipelineJob job,
        RepositoryCiSourceBundle bundle)
    {
        if (bundle.Revision.Repository != job.Source.Repository ||
            bundle.Revision.Commit != job.Source.Commit || bundle.Revision.Tree != job.Source.Tree ||
            bundle.Revision.SignatureVerified != job.Source.SignatureVerified ||
            !Digest(bundle.ContentSha256) ||
            bundle.ObjectName != RepositoryCiSourceBundlePublisher.ObjectName(bundle.ContentSha256) ||
            bundle.ContentLength is < 3 or > ForgejoSourceClient.MaximumArchiveBytes)
            throw new InvalidDataException("The CI source bundle does not match the immutable pipeline job.");
    }

    private static bool SameSourceBundle(
        RepositoryCiJobDocument document,
        RepositoryCiSourceBundle bundle) =>
        document.SourceBundleObject == bundle.ObjectName &&
        document.SourceBundleSha256 == bundle.ContentSha256 &&
        document.SourceBundleBytes == bundle.ContentLength &&
        !document.LegacyDispatchWithoutSourceBundle;

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static void ValidateIdentity(string? value, string parameter)
    {
        if (value is not { Length: >= 1 and <= 512 } || value.Any(static character =>
                char.IsWhiteSpace(character) || char.IsControl(character)))
            throw new ArgumentException("CI job operation identity is invalid.", parameter);
    }
}

internal sealed record RepositoryCiJobDocument(
    int SchemaVersion,
    string Pipeline,
    string PipelineDigest,
    string Job,
    string JobDigest,
    long CreatedAuthorityEpoch,
    long CreatedSequence,
    RepositoryCiJobPhase PreviousPhase,
    RepositoryCiJobPhase Phase,
    int PhaseSequence,
    string ControllerId,
    long AuthorityEpoch,
    long FencingToken,
    string RunnerId,
    long RunnerSequence,
    string IsolationDigest,
    string OperationId,
    string EvidenceDigest,
    int RequiredTestSkips,
    int Attempt,
    string AttemptChainDigest,
    string RetryAuthorizationDigest,
    long RetryNotBeforeUnixMilliseconds,
    RepositoryCiJobFailureKind FailureKind,
    long PreparedAtUnixMilliseconds,
    long ExpiresAtUnixMilliseconds,
    ulong DispatchStreamSequence,
    bool LegacyDispatchWithoutAcknowledgement,
    string SourceBundleObject,
    string SourceBundleSha256,
    int SourceBundleBytes,
    bool LegacyDispatchWithoutSourceBundle)
{
    private const long MaximumUnixMilliseconds = 253_402_300_799_999;

    internal static RepositoryCiJobDocument Pending(
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiPipelineJob job,
        string jobDigest,
        long authorityEpoch,
        long sequence) => new(
            5,
            pipeline.Pipeline.Value,
            pipeline.Digest,
            job.Request.Job.Value,
            jobDigest,
            authorityEpoch,
            sequence,
            RepositoryCiJobPhase.Unspecified,
            RepositoryCiJobPhase.Pending,
            0,
            string.Empty,
            0,
            0,
            string.Empty,
            0,
            string.Empty,
            string.Empty,
            string.Empty,
            0,
            1,
            string.Empty,
            string.Empty,
            0,
            RepositoryCiJobFailureKind.Unspecified,
            0,
            0,
            0,
            false,
            string.Empty,
            string.Empty,
            0,
            false);

    internal bool SameJob(RepositoryCiJobDocument other) =>
        Pipeline == other.Pipeline && PipelineDigest == other.PipelineDigest && Job == other.Job &&
        JobDigest == other.JobDigest;

    internal bool SameLease(RepositoryCiJobDocument other) => SameJob(other) &&
        Attempt == other.Attempt &&
        ControllerId == other.ControllerId && AuthorityEpoch == other.AuthorityEpoch &&
        FencingToken == other.FencingToken && RunnerId == other.RunnerId &&
        RunnerSequence == other.RunnerSequence && IsolationDigest == other.IsolationDigest &&
        OperationId == other.OperationId && SourceBundleObject == other.SourceBundleObject &&
        SourceBundleSha256 == other.SourceBundleSha256 && SourceBundleBytes == other.SourceBundleBytes &&
        LegacyDispatchWithoutSourceBundle == other.LegacyDispatchWithoutSourceBundle;

    internal void Validate()
    {
        var pending = Phase == RepositoryCiJobPhase.Pending;
        var retryWaiting = Phase == RepositoryCiJobPhase.RetryWaiting;
        var leased = Phase is RepositoryCiJobPhase.DispatchPrepared or RepositoryCiJobPhase.Dispatched or
            RepositoryCiJobPhase.Running or RepositoryCiJobPhase.Succeeded or RepositoryCiJobPhase.Failed;
        var active = leased || retryWaiting;
        var retryHistory = Attempt > 1 || retryWaiting;
        var noSourceBundle = SourceBundleObject is { Length: 0 } && SourceBundleSha256 is { Length: 0 } &&
            SourceBundleBytes == 0;
        var validSourceBundle = SourceBundleSha256 is { } bundleDigest && Identity(SourceBundleObject) &&
            Digest(bundleDigest) &&
            SourceBundleObject == RepositoryCiSourceBundlePublisher.ObjectName(bundleDigest) &&
            SourceBundleBytes is >= 3 and <= ForgejoSourceClient.MaximumArchiveBytes;
        if (SchemaVersion != 5 || !Identity(Pipeline) || !Digest(PipelineDigest) || !Identity(Job) ||
            !Digest(JobDigest) || CreatedAuthorityEpoch <= 0 || CreatedSequence <= 0 ||
            Attempt is < 1 or > 100 || AttemptChainDigest is null || RetryAuthorizationDigest is null ||
            !Enum.IsDefined(FailureKind) ||
            !Enum.IsDefined(PreviousPhase) || !Enum.IsDefined(Phase) || (!pending && !active) ||
            pending && (PreviousPhase != (Attempt == 1
                    ? RepositoryCiJobPhase.Unspecified
                    : RepositoryCiJobPhase.RetryWaiting) || PhaseSequence != 0 ||
                ControllerId.Length != 0 ||
                (Attempt == 1 ? AuthorityEpoch != 0 || FencingToken != 0 :
                    AuthorityEpoch <= 0 || FencingToken <= 0) || RunnerId.Length != 0 ||
                RunnerSequence != 0 || IsolationDigest.Length != 0 || OperationId.Length != 0 ||
                EvidenceDigest.Length != 0 || RequiredTestSkips != 0 ||
                FailureKind != RepositoryCiJobFailureKind.Unspecified ||
                PreparedAtUnixMilliseconds != 0 || ExpiresAtUnixMilliseconds != 0 ||
                DispatchStreamSequence != 0 || LegacyDispatchWithoutAcknowledgement ||
                (Attempt == 1
                    ? !noSourceBundle || LegacyDispatchWithoutSourceBundle
                    : !(validSourceBundle && !LegacyDispatchWithoutSourceBundle ||
                        noSourceBundle && LegacyDispatchWithoutSourceBundle))) ||
            leased && (!Identity(ControllerId) || AuthorityEpoch <= 0 || FencingToken <= 0 ||
                !Identity(RunnerId) || RunnerSequence <= 0 || !Digest(IsolationDigest) ||
                !Identity(OperationId) || !Digest(EvidenceDigest) || RequiredTestSkips is < 0 or > 1_000_000 ||
                !ValidPhaseEdge(PreviousPhase, Phase, PhaseSequence) || PreparedAtUnixMilliseconds <= 0 ||
                ExpiresAtUnixMilliseconds <= PreparedAtUnixMilliseconds) ||
            retryWaiting && (!Identity(ControllerId) || AuthorityEpoch <= 0 || FencingToken <= 0 ||
                !Identity(RunnerId) || RunnerSequence <= 0 || !Digest(IsolationDigest) ||
                !Identity(OperationId) || !Digest(EvidenceDigest) || RequiredTestSkips is < 0 or > 1_000_000 ||
                PreviousPhase != RepositoryCiJobPhase.Failed || PhaseSequence != 5 ||
                !RepositoryCiJobJournal.Retryable(FailureKind) || RetryNotBeforeUnixMilliseconds <= 0 ||
                RetryNotBeforeUnixMilliseconds > MaximumUnixMilliseconds ||
                PreparedAtUnixMilliseconds <= 0 || ExpiresAtUnixMilliseconds <= PreparedAtUnixMilliseconds) ||
            retryHistory && (!Digest(AttemptChainDigest) || !Digest(RetryAuthorizationDigest)) ||
            !retryHistory && (AttemptChainDigest.Length != 0 || RetryAuthorizationDigest.Length != 0) ||
            !retryWaiting && RetryNotBeforeUnixMilliseconds != 0 ||
            Phase == RepositoryCiJobPhase.Failed && FailureKind == RepositoryCiJobFailureKind.Unspecified ||
            Phase != RepositoryCiJobPhase.Failed && !retryWaiting &&
                FailureKind != RepositoryCiJobFailureKind.Unspecified ||
            PreparedAtUnixMilliseconds > MaximumUnixMilliseconds ||
            ExpiresAtUnixMilliseconds > MaximumUnixMilliseconds ||
            Phase == RepositoryCiJobPhase.DispatchPrepared &&
                (DispatchStreamSequence != 0 || LegacyDispatchWithoutAcknowledgement) ||
            Phase is (RepositoryCiJobPhase.Dispatched or RepositoryCiJobPhase.Running or
                    RepositoryCiJobPhase.Succeeded or RepositoryCiJobPhase.Failed or
                    RepositoryCiJobPhase.RetryWaiting) &&
                (DispatchStreamSequence == 0) != LegacyDispatchWithoutAcknowledgement ||
            Phase is not (RepositoryCiJobPhase.Succeeded or RepositoryCiJobPhase.Failed) && RequiredTestSkips != 0)
            throw new InvalidDataException("A CI job journal record is invalid.");
        if (active && !(validSourceBundle && !LegacyDispatchWithoutSourceBundle ||
                noSourceBundle && LegacyDispatchWithoutSourceBundle))
            throw new InvalidDataException("A CI job journal record has invalid source-bundle identity.");
    }

    private static bool ValidPhaseEdge(
        RepositoryCiJobPhase previous,
        RepositoryCiJobPhase phase,
        int sequence) => (previous, phase, sequence) switch
        {
            (RepositoryCiJobPhase.Pending, RepositoryCiJobPhase.DispatchPrepared, 1) => true,
            (RepositoryCiJobPhase.DispatchPrepared, RepositoryCiJobPhase.Dispatched, 2) => true,
            (RepositoryCiJobPhase.Dispatched, RepositoryCiJobPhase.Running, 3) => true,
            (RepositoryCiJobPhase.Running, RepositoryCiJobPhase.Succeeded or RepositoryCiJobPhase.Failed, 4) => true,
            _ => false,
        };

    private static bool Digest(string? value) => value is { Length: 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f') &&
        value.Any(static character => character != '0');

    private static bool Identity(string? value) => value is { Length: >= 1 and <= 512 } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));
}

[JsonSerializable(typeof(RepositoryCiJobDocument))]
[JsonSerializable(typeof(CiRunnerIsolationEvidence))]
internal sealed partial class RepositoryCiJobJournalJsonContext : JsonSerializerContext;
