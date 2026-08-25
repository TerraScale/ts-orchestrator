namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiArtifactAttestationGateDisposition
{
    Unspecified,
    Attested,
    NotBuildPipeline,
    PipelineActive,
    PipelineFailed,
    AuthorityLost,
    /// <summary>
    /// The runner's native runtime proof for an exact subject has not been consumed yet (it
    /// arrives through a separate serial consumer). Retryable: never terminal, never throws.
    /// </summary>
    ProofNotYetConsumed,
    /// <summary>Permanent: the durable evidence exists but does not match the exact subject.</summary>
    EvidenceMismatch,
    /// <summary>
    /// Retryable: the durable delivery-evidence journal could not be reached while recording the
    /// published artifact's source binding. The Forgejo event must not be acknowledged until the
    /// record exists, because a production delivery of that digest would otherwise be denied.
    /// </summary>
    DeliveryEvidenceJournalUnavailable,
}

internal sealed record RepositoryCiArtifactAttestationGateReceipt(
    RepositoryCiArtifactAttestationGateDisposition Disposition)
{
    internal bool IsAttested => Disposition is
        RepositoryCiArtifactAttestationGateDisposition.Attested;
}

/// <summary>
/// Re-owns the acknowledge gate for successful trusted-build pipelines: every planned artifact
/// subject is derived from verified durable runner evidence and carries a recorded signature and
/// native-runtime proof before the originating Forgejo event may be acknowledged. Replaces the
/// retired candidate-recording coordinator; the candidate projection itself no longer exists.
/// </summary>
internal sealed class RepositoryCiArtifactAttestationGate(
    Func<RepositoryCiPipelinePlan, CancellationToken, Task<RepositoryCiPipelineRunSnapshot>> readRun,
    Func<RepositoryCiJobSnapshot, CancellationToken, Task<RepositoryCiJobExecutionSnapshot?>> readExecution,
    CiRunnerDurableEvidenceVerifier evidence,
    RepositoryCiArtifactAttestationJournal journal,
    IRepositoryCiArtifactAttestationSigner signer,
    IRepositoryCiArtifactSignatureVerifier artifactVerifier,
    IRepositoryCiArtifactSignatureVerifier runtimeVerifier,
    DirectDeliveryArtifactEvidenceJournal? deliveryEvidence = null)
{
    private readonly Func<RepositoryCiPipelinePlan, CancellationToken, Task<RepositoryCiPipelineRunSnapshot>> readRun =
        readRun ?? throw new ArgumentNullException(nameof(readRun));
    private readonly Func<RepositoryCiJobSnapshot, CancellationToken,
        Task<RepositoryCiJobExecutionSnapshot?>> readExecution = readExecution ??
            throw new ArgumentNullException(nameof(readExecution));
    private readonly CiRunnerDurableEvidenceVerifier evidence = evidence ??
        throw new ArgumentNullException(nameof(evidence));
    private readonly RepositoryCiArtifactAttestationJournal journal = journal ??
        throw new ArgumentNullException(nameof(journal));
    private readonly IRepositoryCiArtifactAttestationSigner signer = signer ??
        throw new ArgumentNullException(nameof(signer));
    private readonly IRepositoryCiArtifactSignatureVerifier artifactVerifier = artifactVerifier ??
        throw new ArgumentNullException(nameof(artifactVerifier));
    private readonly IRepositoryCiArtifactSignatureVerifier runtimeVerifier = runtimeVerifier ??
        throw new ArgumentNullException(nameof(runtimeVerifier));

    internal async Task<RepositoryCiArtifactAttestationGateReceipt> RecordAsync(
        RepositoryCiPipelinePlan pipeline,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        if (pipeline.Profile != RepositoryCiProfile.Build)
            return new(RepositoryCiArtifactAttestationGateDisposition.NotBuildPipeline);

        var run = await readRun(pipeline, cancellationToken) ??
            throw new InvalidDataException("The CI pipeline run reader returned no snapshot.");
        if (run.State == RepositoryCiPipelineRunState.Active)
            return new(RepositoryCiArtifactAttestationGateDisposition.PipelineActive);
        if (run.State == RepositoryCiPipelineRunState.Failed)
            return new(RepositoryCiArtifactAttestationGateDisposition.PipelineFailed);
        if (run.State != RepositoryCiPipelineRunState.Succeeded)
            throw new InvalidDataException("The CI pipeline run has an invalid state.");
        if (run.Jobs.Count != pipeline.Jobs.Count)
            throw new InvalidDataException("The build run is not a complete exact terminal result.");
        if (!authorityStillValid())
            return new(RepositoryCiArtifactAttestationGateDisposition.AuthorityLost);

        Dictionary<string, RepositoryCiJobSnapshot> byJob;
        try
        {
            byJob = run.Jobs.ToDictionary(
                static value => value.Job.Request.Job.Value,
                StringComparer.Ordinal);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException("The build run contains duplicate jobs.", exception);
        }

        var attestations = new RepositoryCiIssuingArtifactAttestationVerifier(
            journal,
            signer,
            new RepositoryCiSignedArtifactAttestationVerifier(
                journal.ReadArtifactAsync,
                journal.ReadRuntimeAsync,
                artifactVerifier,
                runtimeVerifier),
            authorityEpoch,
            sequence,
            authorityStillValid);
        foreach (var planned in pipeline.Jobs.Where(static value =>
                     value.Plan.Node.Kind == RepositoryCiNodeKind.Artifact))
        {
            if (!byJob.TryGetValue(planned.Request.Job.Value, out var job) || !ExactJob(pipeline, planned, job))
                throw new InvalidDataException("The artifact job is not an exact clean terminal result.");
            if (await readExecution(job, cancellationToken) is not { } execution ||
                !ExactExecution(pipeline, job, execution))
                throw new InvalidDataException("The artifact execution does not match its controller result.");
            var stored = await evidence.ReadVerifiedAsync(execution, cancellationToken) ??
                throw new InvalidDataException("The artifact execution evidence failed durable verification.");
            var artifacts = stored.Artifacts ?? [];
            if (artifacts.Length != planned.Plan.Node.Architectures.Count ||
                !artifacts.Select(static value => value.Architecture).ToHashSet()
                    .SetEquals(planned.Plan.Node.Architectures))
                throw new InvalidDataException("The durable artifact declarations do not cover the planned architectures.");

            foreach (var architecture in planned.Plan.Node.Architectures)
            {
                var declared = artifacts.Single(value => value.Architecture == architecture);
                var subject = new RepositoryCiArtifactSubject(
                    pipeline.Digest,
                    planned.Request.Job,
                    new(declared.Artifact),
                    architecture,
                    new(declared.Digest),
                    RepositoryCiArtifactAttestation.EntrypointsDigest(
                        architecture,
                        declared.Entrypoints));
                var verified = await attestations.VerifyAsync(subject, cancellationToken);
                if (verified is null)
                {
                    // A null proof is the not-yet-consumed runtime-proof race while the runner's
                    // serial consumer has not persisted the observation; anything else is a
                    // permanent mismatch. Retries converge once the proof lands.
                    if (architecture != RepositoryCiArchitecture.Any &&
                        await journal.ReadRuntimeAsync(subject, cancellationToken) is null)
                        return new(RepositoryCiArtifactAttestationGateDisposition.ProofNotYetConsumed);
                    return new(RepositoryCiArtifactAttestationGateDisposition.EvidenceMismatch);
                }
                var signingIdentity = verified.SigningIdentity;
                var signature = verified.Signature;
                if (signingIdentity is null || signature is null ||
                    !Identity(signingIdentity.Value) || !Identity(signature.Value) ||
                    architecture == RepositoryCiArchitecture.Any && verified.ObservedRuntimeDigest is not null ||
                    architecture != RepositoryCiArchitecture.Any && verified.ObservedRuntimeDigest != subject.Digest)
                    return new(RepositoryCiArtifactAttestationGateDisposition.EvidenceMismatch);
                // The artifact is now attested against verified durable runner evidence: record
                // its source binding for the direct-delivery provenance boundary so a production
                // delivery of this exact digest can verify instead of being denied. Without this
                // record the published artifact is unusable in production, so a journal that
                // cannot be reached fails the acknowledge as retryable rather than acknowledging
                // an unattestable publication.
                if (deliveryEvidence is not null)
                {
                    var disposition = await RecordDeliveryEvidenceAsync(
                        deliveryEvidence, planned, subject, declared, cancellationToken).ConfigureAwait(false);
                    if (disposition is not null)
                        return new(disposition.Value);
                }
            }
        }
        if (!authorityStillValid())
            return new(RepositoryCiArtifactAttestationGateDisposition.AuthorityLost);
        return new(RepositoryCiArtifactAttestationGateDisposition.Attested);
    }

    /// <summary>
    /// Records one attested artifact's delivery evidence. CI-declared artifacts bind: the exact
    /// content digest (runner-verified, re-prefixed into the delivery digest vocabulary), the
    /// attested subject digest as the manifest identity (the canonical attested declaration of
    /// pipeline, job, artifact, architecture, digest, and entrypoints), kind <c>package</c>
    /// (a repository CI artifact is a build output, not a deployed service image), and the
    /// source's Git tree object identity re-encoded as a sha256 digest. A conflicting durable
    /// claim for the same digest is a permanent mismatch; an unreachable journal is retryable.
    /// </summary>
    private async Task<RepositoryCiArtifactAttestationGateDisposition?> RecordDeliveryEvidenceAsync(
        DirectDeliveryArtifactEvidenceJournal deliveryEvidence,
        RepositoryCiPipelineJob planned,
        RepositoryCiArtifactSubject subject,
        CiRunnerStoredArtifactEvidence declared,
        CancellationToken cancellationToken)
    {
        try
        {
            var disposition = await deliveryEvidence.RecordAsync(
                new DirectDeliveryArtifactEvidence(
                    planned.Source.Repository,
                    planned.Source.Commit,
                    "sha256:" + Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
                        System.Text.Encoding.UTF8.GetBytes(planned.Source.Tree))),
                    "sha256:" + declared.Digest,
                    "sha256:" + RepositoryCiArtifactAttestation.SubjectDigest(subject),
                    "package"),
                // The evidence signer is the CI artifact signing identity: the same trust root
                // production delivery verifies against.
                signer,
                cancellationToken).ConfigureAwait(false);
            return disposition == DirectDeliveryArtifactEvidenceDisposition.IdentityConflict
                ? RepositoryCiArtifactAttestationGateDisposition.EvidenceMismatch
                : null;
        }
        catch (Exception exception) when (exception is not (OutOfMemoryException or StackOverflowException or
            AccessViolationException or OperationCanceledException or InvalidDataException or ArgumentException))
        {
            return RepositoryCiArtifactAttestationGateDisposition.DeliveryEvidenceJournalUnavailable;
        }
    }

    private static bool ExactJob(
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiPipelineJob planned,
        RepositoryCiJobSnapshot job) =>
        job.Job.Request.Job == planned.Request.Job &&
        job.Job.Plan.Id == planned.Plan.Id &&
        job.Phase == RepositoryCiJobPhase.Succeeded &&
        job.Attempt >= 1 && job.RequiredTestSkips == 0 &&
        job.FailureKind == RepositoryCiJobFailureKind.Unspecified &&
        job.Job.MayPublishArtifact &&
        job.Document.PipelineDigest == pipeline.Digest &&
        job.Document.JobDigest == RepositoryCiJobJournal.JobDigest(pipeline, planned) &&
        RepositoryCiJobExecutionDocument.IsDigest(job.EvidenceDigest);

    private static bool ExactExecution(
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiJobSnapshot job,
        RepositoryCiJobExecutionSnapshot? execution) => execution is not null &&
        execution.Phase == RepositoryCiJobExecutionPhase.Succeeded &&
        execution.Runner == job.RunnerId &&
        execution.PipelineDigest == pipeline.Digest &&
        execution.Job == job.Job.Request.Job.Value &&
        execution.Document.JobDigest == job.Document.JobDigest &&
        execution.Document.Generation == job.Job.Request.Generation &&
        execution.Attempt == job.Attempt &&
        execution.Document.StreamSequence == job.DispatchStreamSequence &&
        execution.LeaseId == job.OperationId &&
        execution.EvidenceDigest == job.EvidenceDigest &&
        execution.RequiredTestSkips == job.RequiredTestSkips &&
        execution.FailureKind == job.FailureKind;

    private static bool Identity(string? value) => value is { Length: >= 1 and <= 512 } &&
        !value.Any(static character => char.IsWhiteSpace(character) || char.IsControl(character));
}
