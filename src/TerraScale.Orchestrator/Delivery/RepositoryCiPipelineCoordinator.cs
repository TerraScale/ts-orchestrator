namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiPipelineCoordinationDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    TriggerMissing,
    TriggerNotDispatchable,
    AuthorityLost,
    IdentityConflict,
}

internal sealed record RepositoryCiPipelineGraph(
    IReadOnlyList<ForgejoSourceFile> DescriptorFiles,
    IReadOnlyList<ForgejoResolvedRevision> Sources);

internal sealed record RepositoryCiPipelineCoordinationReceipt(
    RepositoryCiPipelineCoordinationDisposition Disposition,
    RepositoryCiPipelinePlan? Plan)
{
    internal bool IsPlanned =>
        (Disposition is RepositoryCiPipelineCoordinationDisposition.Recorded or
            RepositoryCiPipelineCoordinationDisposition.Duplicate) &&
        Plan is not null;
}

/// <summary>
/// Connects one durable Forgejo trigger decision to its exact affected pipeline. Cross-repository
/// source selection is injected so this coordinator cannot infer release inputs from moving refs.
/// </summary>
internal sealed class RepositoryCiPipelineCoordinator(
    ForgejoCiTriggerJournal triggers,
    RepositoryCiPipelineJournal pipelines,
    Func<ForgejoWebhookEnvelope, CancellationToken, Task<IReadOnlyList<string>>> readChangedPaths,
    Func<ForgejoCiTriggerPlan, IReadOnlyList<string>, CancellationToken,
        Task<RepositoryCiPipelineGraph>> resolveGraph)
{
    internal async Task<RepositoryCiPipelineCoordinationReceipt> CoordinateAsync(
        string dedupeKey,
        long generation,
        long minimumRunnerSequence,
        long maximumRunnerSequence,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        ArgumentNullException.ThrowIfNull(readChangedPaths);
        ArgumentNullException.ThrowIfNull(resolveGraph);
        if (generation <= 0 || minimumRunnerSequence <= 0 ||
            maximumRunnerSequence < minimumRunnerSequence)
            throw new ArgumentOutOfRangeException(nameof(generation));
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));
        var trigger = await triggers.ReadAsync(dedupeKey, cancellationToken);
        if (trigger is null)
            return Result(RepositoryCiPipelineCoordinationDisposition.TriggerMissing);
        if (trigger.Disposition != ForgejoCiTriggerDisposition.Dispatch)
            return Result(RepositoryCiPipelineCoordinationDisposition.TriggerNotDispatchable);

        var existing = await pipelines.ReadAsync(dedupeKey, cancellationToken);
        if (existing is not null)
            return Result(
                MatchesExecutionWindow(
                    existing,
                    generation,
                    minimumRunnerSequence,
                    maximumRunnerSequence)
                    ? RepositoryCiPipelineCoordinationDisposition.Duplicate
                    : RepositoryCiPipelineCoordinationDisposition.IdentityConflict,
                existing);
        if (!authorityStillValid())
            return Result(RepositoryCiPipelineCoordinationDisposition.AuthorityLost);

        var paths = await readChangedPaths(trigger.Envelope, cancellationToken);
        if (!authorityStillValid())
            return Result(RepositoryCiPipelineCoordinationDisposition.AuthorityLost);
        var graph = await resolveGraph(trigger, paths, cancellationToken)
            ?? throw new InvalidDataException("The CI source graph resolver returned no graph.");
        if (graph.DescriptorFiles is null || graph.Sources is null)
            throw new InvalidDataException("The CI source graph is incomplete.");
        if (!authorityStillValid())
            return Result(RepositoryCiPipelineCoordinationDisposition.AuthorityLost);

        var recorded = await pipelines.PlanAndRecordAsync(
            trigger,
            graph.DescriptorFiles,
            [new RepositoryCiChange(trigger.Envelope.Repository, paths)],
            graph.Sources,
            generation,
            minimumRunnerSequence,
            maximumRunnerSequence,
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
        return recorded.Disposition switch
        {
            RepositoryCiPipelineJournalDisposition.Recorded =>
                Result(RepositoryCiPipelineCoordinationDisposition.Recorded, recorded.Plan),
            RepositoryCiPipelineJournalDisposition.Duplicate =>
                Result(RepositoryCiPipelineCoordinationDisposition.Duplicate, recorded.Plan),
            RepositoryCiPipelineJournalDisposition.StaleAuthority =>
                Result(RepositoryCiPipelineCoordinationDisposition.AuthorityLost),
            RepositoryCiPipelineJournalDisposition.IdentityConflict =>
                Result(RepositoryCiPipelineCoordinationDisposition.IdentityConflict, recorded.Plan),
            _ => throw new InvalidDataException("The CI pipeline journal returned an unspecified disposition."),
        };
    }

    private static RepositoryCiPipelineCoordinationReceipt Result(
        RepositoryCiPipelineCoordinationDisposition disposition,
        RepositoryCiPipelinePlan? plan = null) => new(disposition, plan);

    private static bool MatchesExecutionWindow(
        RepositoryCiPipelinePlan plan,
        long generation,
        long minimumRunnerSequence,
        long maximumRunnerSequence) => plan.Jobs.Count > 0 && plan.Jobs.All(job =>
        job.Request.Generation == generation &&
        job.Request.MinimumRunnerSequence == minimumRunnerSequence &&
        job.Request.MaximumRunnerSequence == maximumRunnerSequence);
}
