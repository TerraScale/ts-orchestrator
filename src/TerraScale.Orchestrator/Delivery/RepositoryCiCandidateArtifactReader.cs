using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record RepositoryCiArtifactSubject(
    string PipelineDigest,
    JobId Job,
    ArtifactId Artifact,
    RepositoryCiArchitecture Architecture,
    DigestId Digest,
    string EntrypointsDigest);

internal sealed record RepositoryCiVerifiedArtifactAttestation(
    SigningIdentityId SigningIdentity,
    SignatureId Signature,
    DigestId? ObservedRuntimeDigest);

/// <summary>
/// Owns registry/package signature verification and native execution evidence. A null result means
/// the exact artifact subject is not qualified; callers never infer either proof from build output.
/// </summary>
internal interface IRepositoryCiArtifactAttestationVerifier
{
    Task<RepositoryCiVerifiedArtifactAttestation?> VerifyAsync(
        RepositoryCiArtifactSubject subject,
        CancellationToken cancellationToken);
}

/// <summary>
/// Projects exact durable runner output into candidate input only after external signature and
/// native-runtime verification has qualified every declared artifact digest.
/// </summary>
internal sealed class RepositoryCiCandidateArtifactReader(
    Func<RepositoryCiJobSnapshot, CancellationToken, Task<RepositoryCiJobExecutionSnapshot?>> readExecution,
    CiRunnerDurableEvidenceVerifier evidence,
    IRepositoryCiArtifactAttestationVerifier attestations)
{
    private readonly Func<RepositoryCiJobSnapshot, CancellationToken,
        Task<RepositoryCiJobExecutionSnapshot?>> readExecution = readExecution ??
            throw new ArgumentNullException(nameof(readExecution));
    private readonly CiRunnerDurableEvidenceVerifier evidence = evidence ??
        throw new ArgumentNullException(nameof(evidence));
    private readonly IRepositoryCiArtifactAttestationVerifier attestations = attestations ??
        throw new ArgumentNullException(nameof(attestations));

    internal async Task<IReadOnlyList<RepositoryCiArtifactResult>> ReadAsync(
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiPipelineRunSnapshot run,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(run);
        if (pipeline.Profile != RepositoryCiProfile.Release ||
            run.State != RepositoryCiPipelineRunState.Succeeded ||
            run.Jobs.Count != pipeline.Jobs.Count)
            throw new InvalidDataException("Only a complete release run can expose candidate artifacts.");

        Dictionary<string, RepositoryCiJobSnapshot> byJob;
        try
        {
            byJob = run.Jobs.ToDictionary(
                static value => value.Job.Request.Job.Value,
                StringComparer.Ordinal);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException("The release run contains duplicate jobs.", exception);
        }

        var results = new List<RepositoryCiArtifactResult>();
        foreach (var planned in pipeline.Jobs.Where(static value =>
                     value.Plan.Node.Kind == RepositoryCiNodeKind.Artifact))
        {
            if (!byJob.TryGetValue(planned.Request.Job.Value, out var job) || !ExactJob(pipeline, planned, job))
                throw new InvalidDataException("The artifact job is not an exact clean terminal result.");
            var execution = await readExecution(job, cancellationToken);
            if (!ExactExecution(pipeline, job, execution))
                throw new InvalidDataException("The artifact execution does not match its controller result.");
            var stored = await evidence.ReadVerifiedAsync(execution!, cancellationToken) ??
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
                var verified = await attestations.VerifyAsync(subject, cancellationToken) ??
                    throw new InvalidDataException("A candidate artifact lacks verified signature or runtime evidence.");
                var signingIdentity = verified.SigningIdentity;
                var signature = verified.Signature;
                if (signingIdentity is null || signature is null ||
                    !Identity(signingIdentity.Value) || !Identity(signature.Value) ||
                    architecture == RepositoryCiArchitecture.Any && verified.ObservedRuntimeDigest is not null ||
                    architecture != RepositoryCiArchitecture.Any && verified.ObservedRuntimeDigest != subject.Digest)
                    throw new InvalidDataException("The verified artifact attestation does not match its exact subject.");
                results.Add(new(
                    planned.Plan.Repository,
                    planned.Plan.Promotion,
                    subject.Job,
                    subject.Artifact,
                    subject.Architecture,
                    subject.Digest,
                    Array.AsReadOnly(declared.Entrypoints.ToArray()),
                    signingIdentity,
                    signature,
                    true,
                    verified.ObservedRuntimeDigest));
            }
        }
        if (results.Count == 0)
            throw new InvalidDataException("The release run declared no candidate artifacts.");
        return Array.AsReadOnly(results.ToArray());
    }

    private static bool ExactJob(
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiPipelineJob planned,
        RepositoryCiJobSnapshot job) =>
        job.Job.Request.Job == planned.Request.Job &&
        job.Job.Plan.Id == planned.Plan.Id &&
        job.Phase == RepositoryCiJobPhase.Succeeded &&
        job.Attempt == 1 && job.RequiredTestSkips == 0 &&
        job.FailureKind == RepositoryCiJobFailureKind.Unspecified &&
        job.Job.MayPublishCandidateArtifact &&
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
