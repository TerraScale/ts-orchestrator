namespace TerraScale.Orchestrator.Delivery;

internal enum NativeGitOpsGlobalHandoffDispatchDisposition
{
    Unspecified,
    Completed,
    AlreadyComplete,
    AuthorityLostBeforePublish,
    AuthorityLostAfterPublish,
    AuthorityLostBeforeJournal,
    JournalRejected,
    Contention,
}

internal sealed record NativeGitOpsGlobalHandoffDispatchReceipt(
    NativeGitOpsGlobalHandoffDispatchDisposition Disposition,
    NativeGitOpsGlobalHandoffPublishJournalDisposition JournalDisposition,
    NativeGitOpsGlobalHandoffPublishSnapshot? Snapshot,
    int PublishedCells)
{
    internal bool IsComplete => Disposition is
        NativeGitOpsGlobalHandoffDispatchDisposition.Completed or
        NativeGitOpsGlobalHandoffDispatchDisposition.AlreadyComplete &&
        Snapshot is { IsComplete: true };
}

/// <summary>
/// Resumes one prepared global handoff from its durable per-cell storage acknowledgements. A crash
/// between NATS storage and CAS replay publishes the same persisted bytes and message ID, then
/// converges on the acknowledgement journal before attempting the next cell.
/// </summary>
internal sealed class NativeGitOpsGlobalHandoffDispatcher(
    NativeGitOpsGlobalHandoffPublishJournal journal,
    NativeGitOpsGlobalHandoffPublisher publisher)
{
    internal async Task<NativeGitOpsGlobalHandoffDispatchReceipt> DispatchAsync(
        NativeGitOpsPreparedHandoff handoff,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handoff);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        NativeGitOpsGlobalHandoffPublisher.Validate(handoff);
        var current = await journal.ReadAsync(handoff.Repository, handoff.Branch, cancellationToken);
        var exact = false;
        if (current is not null)
        {
            var rejected = NativeGitOpsGlobalHandoffPublishJournal.Compare(current, handoff);
            if (rejected is not null)
                return Result(
                    NativeGitOpsGlobalHandoffDispatchDisposition.JournalRejected,
                    rejected.Value,
                    current,
                    0);
            exact = NativeGitOpsGlobalHandoffPublishJournal.SamePreparedHandoff(current, handoff);
            if (exact && current.IsComplete)
                return Result(
                    NativeGitOpsGlobalHandoffDispatchDisposition.AlreadyComplete,
                    NativeGitOpsGlobalHandoffPublishJournalDisposition.Duplicate,
                    current,
                    0);
        }

        var published = 0;
        foreach (var cell in handoff.Cells)
        {
            if (exact && current!.Cells.Any(acknowledgement =>
                    acknowledgement.Cell == cell.Cell && acknowledgement.WireSha256 == cell.WireSha256))
                continue;
            var attempt = await publisher.PublishCellAsync(
                handoff,
                cell,
                authorityStillValid,
                cancellationToken);
            if (attempt.Disposition == NativeGitOpsGlobalHandoffPublishDisposition.AuthorityLostBeforePublish)
                return Result(
                    NativeGitOpsGlobalHandoffDispatchDisposition.AuthorityLostBeforePublish,
                    NativeGitOpsGlobalHandoffPublishJournalDisposition.StaleAuthority,
                    current,
                    published);
            if (attempt.Disposition == NativeGitOpsGlobalHandoffPublishDisposition.AuthorityLostAfterPublish)
                return Result(
                    NativeGitOpsGlobalHandoffDispatchDisposition.AuthorityLostAfterPublish,
                    NativeGitOpsGlobalHandoffPublishJournalDisposition.StaleAuthority,
                    current,
                    checked(published + 1));
            var publication = attempt.Cell
                ?? throw new InvalidDataException("A completed global CellSpec publish has no acknowledgement.");
            published++;
            var recorded = await journal.RecordAsync(
                handoff,
                publication,
                authorityStillValid,
                cancellationToken);
            if (recorded.Disposition == NativeGitOpsGlobalHandoffPublishJournalDisposition.StaleAuthority)
                return Result(
                    NativeGitOpsGlobalHandoffDispatchDisposition.AuthorityLostBeforeJournal,
                    recorded.Disposition,
                    recorded.Snapshot,
                    published);
            if (recorded.Disposition == NativeGitOpsGlobalHandoffPublishJournalDisposition.ConcurrentUpdate)
            {
                current = await journal.ReadAsync(handoff.Repository, handoff.Branch, cancellationToken);
                exact = current is not null &&
                    NativeGitOpsGlobalHandoffPublishJournal.SamePreparedHandoff(current, handoff);
                if (exact && current!.Cells.Any(acknowledgement =>
                        acknowledgement.Cell == cell.Cell &&
                        acknowledgement.WireSha256 == cell.WireSha256 &&
                        acknowledgement.StreamSequence == publication.StreamSequence))
                    continue;
                return Result(
                    NativeGitOpsGlobalHandoffDispatchDisposition.Contention,
                    recorded.Disposition,
                    current,
                    published);
            }
            if (recorded.Disposition is not (
                    NativeGitOpsGlobalHandoffPublishJournalDisposition.Recorded or
                    NativeGitOpsGlobalHandoffPublishJournalDisposition.Duplicate))
                return Result(
                    NativeGitOpsGlobalHandoffDispatchDisposition.JournalRejected,
                    recorded.Disposition,
                    recorded.Snapshot,
                    published);
            current = recorded.Snapshot;
            exact = current is not null &&
                NativeGitOpsGlobalHandoffPublishJournal.SamePreparedHandoff(current, handoff);
        }

        if (current is not { IsComplete: true } || !exact)
            throw new InvalidDataException("The global handoff dispatch ended without complete durable evidence.");
        return Result(
            NativeGitOpsGlobalHandoffDispatchDisposition.Completed,
            NativeGitOpsGlobalHandoffPublishJournalDisposition.Recorded,
            current,
            published);
    }

    private static NativeGitOpsGlobalHandoffDispatchReceipt Result(
        NativeGitOpsGlobalHandoffDispatchDisposition disposition,
        NativeGitOpsGlobalHandoffPublishJournalDisposition journalDisposition,
        NativeGitOpsGlobalHandoffPublishSnapshot? snapshot,
        int publishedCells) => new(disposition, journalDisposition, snapshot, publishedCells);
}
