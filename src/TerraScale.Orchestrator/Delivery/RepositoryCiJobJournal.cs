using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.ControlPlane.Delivery;

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
    NotReady,
    RunnerDenied,
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
internal sealed class RepositoryCiJobJournal(IForgejoDeliveryLedger ledger)
{
    private const int MaximumRecordBytes = 16 * 1024;
    private const int MaximumConflictRetries = 8;

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
                document.JobDigest != JobDigest(pipeline, job) || document.Job != job.Request.Job.Value)
                throw new InvalidDataException("A CI pipeline job record changed immutable identity.");
            snapshots.Add(new(job, document, entry.Revision));
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
                snapshot.Job.Request.Attempt,
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
        ArgumentNullException.ThrowIfNull(runner);
        ArgumentNullException.ThrowIfNull(isolation);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        ValidateIdentity(controllerId, nameof(controllerId));
        ValidateIdentity(operationId, nameof(operationId));
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        var planned = pipeline.Jobs.SingleOrDefault(job => job.Request.Job == jobId)
            ?? throw new ArgumentException("The CI job is not part of the pipeline.", nameof(jobId));
        var admission = CiRunnerIsolationPolicy.Evaluate(planned.Request, runner, isolation);
        if (!admission.Accepted) return new(RepositoryCiJobJournalDisposition.RunnerDenied, null);
        var isolationDigest = IsolationDigest(isolation);

        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var run = await ReadAsync(pipeline, cancellationToken);
            if (run.State == RepositoryCiPipelineRunState.Failed)
                return new(RepositoryCiJobJournalDisposition.PipelineFailed, null);
            var current = run.Jobs.Single(job => job.Job.Request.Job == jobId);
            if (current.Phase == RepositoryCiJobPhase.DispatchPrepared)
            {
                var exact = current.ControllerId == controllerId && current.AuthorityEpoch == authorityEpoch &&
                    current.RunnerId == runner.Runner.Value && current.RunnerSequence == runner.Sequence &&
                    current.OperationId == operationId && current.Document.IsolationDigest == isolationDigest;
                if (exact) return new(authorityStillValid()
                    ? RepositoryCiJobJournalDisposition.Duplicate
                    : RepositoryCiJobJournalDisposition.StaleAuthority, current);
                return new(authorityEpoch < current.AuthorityEpoch
                    ? RepositoryCiJobJournalDisposition.StaleAuthority
                    : RepositoryCiJobJournalDisposition.LeaseHeld, current);
            }
            if (current.Phase != RepositoryCiJobPhase.Pending)
                return new(RepositoryCiJobJournalDisposition.PhaseConflict, current);
            if (!run.Ready.Contains(planned))
                return new(RepositoryCiJobJournalDisposition.NotReady, current);
            if (!authorityStillValid())
                return new(RepositoryCiJobJournalDisposition.StaleAuthority, current);

            var prepared = current.Document with
            {
                PreviousPhase = RepositoryCiJobPhase.Pending,
                Phase = RepositoryCiJobPhase.DispatchPrepared,
                PhaseSequence = 1,
                ControllerId = controllerId,
                AuthorityEpoch = authorityEpoch,
                FencingToken = 1,
                RunnerId = runner.Runner.Value,
                RunnerSequence = runner.Sequence,
                IsolationDigest = isolationDigest,
                OperationId = operationId,
                EvidenceDigest = isolationDigest,
            };
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
        var planned = pipeline.Jobs.SingleOrDefault(job => job.Request.Job == jobId)
            ?? throw new ArgumentException("The CI job is not part of the pipeline.", nameof(jobId));
        var key = Index(pipeline.Digest, jobId.Value);
        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            var entry = await ledger.GetAsync(key, cancellationToken)
                ?? throw new InvalidDataException("The CI job lease disappeared.");
            var document = Deserialize(entry.Value);
            if (document.JobDigest != JobDigest(pipeline, planned))
                throw new InvalidDataException("The CI job lease changed immutable identity.");
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
                return new(current.EvidenceDigest == evidenceDigest && current.RequiredTestSkips == requiredTestSkips
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
                job.Request.Pipeline != pipeline.Pipeline) ||
            pipeline.Jobs.Select(static job => job.Request.Job.Value).Distinct(StringComparer.Ordinal).Count() !=
            pipeline.Jobs.Count)
            throw new InvalidDataException("The CI pipeline cannot initialize durable job state.");
    }

    private static string JobDigest(RepositoryCiPipelinePlan pipeline, RepositoryCiPipelineJob job)
    {
        var request = job.Request;
        var value = new StringBuilder(pipeline.Digest).Append('\n')
            .Append(pipeline.ImpactDigest).Append('\n')
            .Append(job.Plan.Id).Append(':').Append(job.Plan.Repository).Append(':')
            .Append(job.Plan.Node.Id).Append(':').Append(job.Plan.Node.Kind).Append(':')
            .Append(job.Plan.Node.ResourceWeight).Append('\n')
            .Append(job.Source.Repository).Append(':').Append(job.Source.Commit).Append(':')
            .Append(job.Source.Tree).Append(':').Append(job.Source.SignatureVerified ? '1' : '0').Append('\n')
            .Append(request.Pipeline.Value).Append(':').Append(request.Job.Value).Append(':')
            .Append(request.Kind).Append(':').Append(request.Tree.Value).Append(':')
            .Append(request.Generation).Append(':').Append(request.Attempt).Append(':')
            .Append(request.MaximumAttempts).Append(':').Append(request.Idempotency.Value).Append(':')
            .Append(request.MinimumRunnerSequence).Append(':').Append(request.MaximumRunnerSequence).Append(':')
            .Append(request.RetryAuthorized ? '1' : '0').Append('\n')
            .AppendJoin(',', request.AllowedZones).Append('\n')
            .AppendJoin(',', request.RequiredCapabilities).Append('\n')
            .AppendJoin(',', job.DependsOn.Select(static dependency => dependency.Value)).Append('\n')
            .Append(job.MayPublishCandidateArtifact ? '1' : '0');
        return Hash(value.ToString());
    }

    private static string IsolationDigest(CiRunnerIsolationEvidence value)
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
    int RequiredTestSkips)
{
    internal static RepositoryCiJobDocument Pending(
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiPipelineJob job,
        string jobDigest,
        long authorityEpoch,
        long sequence) => new(
            1,
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
            0);

    internal bool SameJob(RepositoryCiJobDocument other) =>
        Pipeline == other.Pipeline && PipelineDigest == other.PipelineDigest && Job == other.Job &&
        JobDigest == other.JobDigest;

    internal bool SameLease(RepositoryCiJobDocument other) => SameJob(other) &&
        ControllerId == other.ControllerId && AuthorityEpoch == other.AuthorityEpoch &&
        FencingToken == other.FencingToken && RunnerId == other.RunnerId &&
        RunnerSequence == other.RunnerSequence && IsolationDigest == other.IsolationDigest &&
        OperationId == other.OperationId;

    internal void Validate()
    {
        var pending = Phase == RepositoryCiJobPhase.Pending;
        var active = Phase is RepositoryCiJobPhase.DispatchPrepared or RepositoryCiJobPhase.Dispatched or
            RepositoryCiJobPhase.Running or RepositoryCiJobPhase.Succeeded or RepositoryCiJobPhase.Failed;
        if (SchemaVersion != 1 || !Identity(Pipeline) || !Digest(PipelineDigest) || !Identity(Job) ||
            !Digest(JobDigest) || CreatedAuthorityEpoch <= 0 || CreatedSequence <= 0 ||
            !Enum.IsDefined(PreviousPhase) || !Enum.IsDefined(Phase) || (!pending && !active) ||
            pending && (PreviousPhase != RepositoryCiJobPhase.Unspecified || PhaseSequence != 0 ||
                ControllerId.Length != 0 || AuthorityEpoch != 0 || FencingToken != 0 || RunnerId.Length != 0 ||
                RunnerSequence != 0 || IsolationDigest.Length != 0 || OperationId.Length != 0 ||
                EvidenceDigest.Length != 0 || RequiredTestSkips != 0) ||
            active && (!Identity(ControllerId) || AuthorityEpoch <= 0 || FencingToken <= 0 ||
                !Identity(RunnerId) || RunnerSequence <= 0 || !Digest(IsolationDigest) ||
                !Identity(OperationId) || !Digest(EvidenceDigest) || RequiredTestSkips is < 0 or > 1_000_000 ||
                !ValidPhaseEdge(PreviousPhase, Phase, PhaseSequence)) ||
            Phase is not (RepositoryCiJobPhase.Succeeded or RepositoryCiJobPhase.Failed) && RequiredTestSkips != 0)
            throw new InvalidDataException("A CI job journal record is invalid.");
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
