namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsGlobalHandoffCoordinationDisposition
{
    Unspecified,
    Completed,
    AlreadyComplete,
    SourceMissing,
    SourceNotRecoverable,
    SourceChanged,
    AuthorityLost,
    PreparationRejected,
    DispatchRejected,
}

internal sealed record NativeGitOpsGlobalHandoffCoordinationReceipt(
    NativeGitOpsGlobalHandoffCoordinationDisposition Disposition,
    NativeGitOpsSignedHandoffJournalDisposition PreparationDisposition,
    NativeGitOpsGlobalHandoffDispatchReceipt? Dispatch,
    ulong SourceJournalRevision)
{
    internal bool IsComplete =>
        (Disposition is NativeGitOpsGlobalHandoffCoordinationDisposition.Completed or
            NativeGitOpsGlobalHandoffCoordinationDisposition.AlreadyComplete) &&
        Dispatch is { IsComplete: true };
}

/// <summary>
/// Rehydrates one durable source/base diff, persists its exact signed handoff, and resumes global
/// publication from per-cell storage acknowledgements. It contains no clock, KMS, or receive loop.
/// </summary>
internal sealed class NativeGitOpsGlobalHandoffCoordinator(
    NativeGitOpsSourceJournal sources,
    NativeGitOpsSignedHandoffJournal signedHandoffs,
    NativeGitOpsGlobalHandoffDispatcher dispatcher)
{
    internal async Task<NativeGitOpsGlobalHandoffCoordinationReceipt> CoordinateAsync(
        string repository,
        string branch,
        long authorityEpoch,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        INativeGitOpsCellSpecSigner signer,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default,
        string? expectedCommit = null)
    {
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (issuedAt == default || expiresAt <= issuedAt)
            throw new ArgumentException("The coordinated native GitOps handoff window is invalid.");
        var accepted = await sources.ReadAsync(repository, branch, cancellationToken);
        if (accepted is null)
            return Result(NativeGitOpsGlobalHandoffCoordinationDisposition.SourceMissing);
        if (expectedCommit is not null &&
            !StringComparer.OrdinalIgnoreCase.Equals(accepted.Revision.Commit, expectedCommit))
            return Result(
                NativeGitOpsGlobalHandoffCoordinationDisposition.SourceChanged,
                sourceJournalRevision: accepted.JournalRevision);
        if (accepted.Diff is null)
            return Result(
                NativeGitOpsGlobalHandoffCoordinationDisposition.SourceNotRecoverable,
                sourceJournalRevision: accepted.JournalRevision);
        if (accepted.AuthorityEpoch > authorityEpoch || !authorityStillValid())
            return Result(
                NativeGitOpsGlobalHandoffCoordinationDisposition.AuthorityLost,
                sourceJournalRevision: accepted.JournalRevision);

        var source = new NativeGitOpsSourcePlan(
            accepted.Revision,
            accepted.SourceFile,
            accepted.Plan,
            accepted.Diff);
        var prepared = await signedHandoffs.PrepareAsync(
            branch,
            source,
            accepted.JournalRevision,
            authorityEpoch,
            issuedAt,
            expiresAt,
            signer,
            authorityStillValid,
            cancellationToken);
        if (prepared.Disposition == NativeGitOpsSignedHandoffJournalDisposition.StaleAuthority)
            return Result(
                NativeGitOpsGlobalHandoffCoordinationDisposition.AuthorityLost,
                prepared.Disposition,
                sourceJournalRevision: accepted.JournalRevision);
        if (prepared.Disposition is not (
                NativeGitOpsSignedHandoffJournalDisposition.Recorded or
                NativeGitOpsSignedHandoffJournalDisposition.Duplicate) ||
            prepared.Handoff is null)
            return Result(
                NativeGitOpsGlobalHandoffCoordinationDisposition.PreparationRejected,
                prepared.Disposition,
                sourceJournalRevision: accepted.JournalRevision);

        var dispatched = await dispatcher.DispatchAsync(
            prepared.Handoff,
            authorityStillValid,
            cancellationToken);
        var disposition = dispatched.Disposition switch
        {
            NativeGitOpsGlobalHandoffDispatchDisposition.Completed =>
                NativeGitOpsGlobalHandoffCoordinationDisposition.Completed,
            NativeGitOpsGlobalHandoffDispatchDisposition.AlreadyComplete =>
                NativeGitOpsGlobalHandoffCoordinationDisposition.AlreadyComplete,
            NativeGitOpsGlobalHandoffDispatchDisposition.AuthorityLostBeforePublish or
            NativeGitOpsGlobalHandoffDispatchDisposition.AuthorityLostAfterPublish or
            NativeGitOpsGlobalHandoffDispatchDisposition.AuthorityLostBeforeJournal =>
                NativeGitOpsGlobalHandoffCoordinationDisposition.AuthorityLost,
            _ => NativeGitOpsGlobalHandoffCoordinationDisposition.DispatchRejected,
        };
        return Result(disposition, prepared.Disposition, dispatched, accepted.JournalRevision);
    }

    private static NativeGitOpsGlobalHandoffCoordinationReceipt Result(
        NativeGitOpsGlobalHandoffCoordinationDisposition disposition,
        NativeGitOpsSignedHandoffJournalDisposition preparationDisposition =
            NativeGitOpsSignedHandoffJournalDisposition.Unspecified,
        NativeGitOpsGlobalHandoffDispatchReceipt? dispatch = null,
        ulong sourceJournalRevision = 0) => new(
            disposition,
            preparationDisposition,
            dispatch,
            sourceJournalRevision);
}
