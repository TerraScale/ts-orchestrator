namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiCandidateCoordinationDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    NotReleasePipeline,
    PipelineActive,
    PipelineFailed,
    AuthorityLost,
    IdentityConflict,
}

internal sealed record RepositoryCiCandidateCoordinationReceipt(
    RepositoryCiCandidateCoordinationDisposition Disposition,
    RepositoryCiCandidate? Candidate)
{
    internal bool IsRecorded =>
        (Disposition is RepositoryCiCandidateCoordinationDisposition.Recorded or
            RepositoryCiCandidateCoordinationDisposition.Duplicate) &&
        Candidate is not null;
}

/// <summary>
/// Assembles one immutable candidate only after the durable release run has fully succeeded and an
/// injected reader supplies the exact signed artifact evidence for that pipeline.
/// </summary>
internal sealed class RepositoryCiCandidateCoordinator(
    RepositoryCiCandidateJournal candidates,
    Func<RepositoryCiPipelinePlan, CancellationToken, Task<RepositoryCiPipelineRunSnapshot>> readRun,
    Func<RepositoryCiPipelinePlan, CancellationToken, Task<IReadOnlyList<RepositoryCiArtifactResult>>>
        readArtifacts)
{
    internal async Task<RepositoryCiCandidateCoordinationReceipt> CoordinateAsync(
        RepositoryCiPipelinePlan pipeline,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(readRun);
        ArgumentNullException.ThrowIfNull(readArtifacts);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        if (pipeline.Profile != RepositoryCiProfile.Release)
            return Result(RepositoryCiCandidateCoordinationDisposition.NotReleasePipeline);

        var run = await readRun(pipeline, cancellationToken)
            ?? throw new InvalidDataException("The CI pipeline run reader returned no snapshot.");
        if (run.State == RepositoryCiPipelineRunState.Active)
            return Result(RepositoryCiCandidateCoordinationDisposition.PipelineActive);
        if (run.State == RepositoryCiPipelineRunState.Failed)
            return Result(RepositoryCiCandidateCoordinationDisposition.PipelineFailed);
        if (run.State != RepositoryCiPipelineRunState.Succeeded)
            throw new InvalidDataException("The CI pipeline run has an invalid state.");
        if (!authorityStillValid())
            return Result(RepositoryCiCandidateCoordinationDisposition.AuthorityLost);

        var artifacts = await readArtifacts(pipeline, cancellationToken)
            ?? throw new InvalidDataException("The CI artifact evidence reader returned no evidence.");
        if (!authorityStillValid())
            return Result(RepositoryCiCandidateCoordinationDisposition.AuthorityLost);
        var candidate = RepositoryCiCandidateAssembler.Assemble(pipeline, run.Results, artifacts);
        var recorded = await candidates.RecordCandidateAsync(
            candidate,
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
        return recorded.Disposition switch
        {
            RepositoryCiCandidateJournalDisposition.Recorded =>
                Result(RepositoryCiCandidateCoordinationDisposition.Recorded, candidate),
            RepositoryCiCandidateJournalDisposition.Duplicate =>
                Result(RepositoryCiCandidateCoordinationDisposition.Duplicate, candidate),
            RepositoryCiCandidateJournalDisposition.StaleAuthority =>
                Result(RepositoryCiCandidateCoordinationDisposition.AuthorityLost),
            RepositoryCiCandidateJournalDisposition.IdentityConflict =>
                Result(RepositoryCiCandidateCoordinationDisposition.IdentityConflict, candidate),
            _ => throw new InvalidDataException("The CI candidate journal returned an unspecified disposition."),
        };
    }

    private static RepositoryCiCandidateCoordinationReceipt Result(
        RepositoryCiCandidateCoordinationDisposition disposition,
        RepositoryCiCandidate? candidate = null) => new(disposition, candidate);
}
