namespace TerraScale.Orchestrator.Delivery;

internal sealed record RepositoryCiCandidateRetentionSummary(
    int Scanned,
    int NotExpired,
    int Retained,
    int Deleted,
    int AlreadyDeleted,
    int Deferred,
    bool AuthorityLost);

/// <summary>Streams lifecycle keys and removes only expired, unqualified candidates.</summary>
internal sealed class RepositoryCiCandidateRetentionCoordinator
{
    private const string LifecyclePrefix = "ci-candidate-lifecycle.";
    private const string LifecycleFilter = LifecyclePrefix + ">";
    private readonly RepositoryCiCandidateJournal candidates;
    private readonly IForgejoDeliveryRetentionLedger ledger;
    private readonly int maximumDeletions;

    internal RepositoryCiCandidateRetentionCoordinator(
        RepositoryCiCandidateJournal candidates,
        IForgejoDeliveryRetentionLedger ledger,
        int maximumDeletions = 64)
    {
        ArgumentNullException.ThrowIfNull(candidates);
        ArgumentNullException.ThrowIfNull(ledger);
        if (maximumDeletions is < 1 or > 256)
            throw new ArgumentOutOfRangeException(nameof(maximumDeletions));
        this.candidates = candidates;
        this.ledger = ledger;
        this.maximumDeletions = maximumDeletions;
    }

    internal async Task<RepositoryCiCandidateRetentionSummary> RunOnceAsync(
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));

        var scanned = 0;
        var notExpired = 0;
        var retained = 0;
        var deleted = 0;
        var alreadyDeleted = 0;
        var deferred = 0;
        var authorityLost = false;
        if (!authorityStillValid())
            return new(scanned, notExpired, retained, deleted, alreadyDeleted, deferred, true);

        await foreach (var key in ledger.ListKeysAsync(LifecycleFilter, cancellationToken))
        {
            scanned++;
            if (!key.StartsWith(LifecyclePrefix, StringComparison.Ordinal))
                throw new InvalidDataException("Candidate lifecycle discovery returned an invalid key.");
            var candidateDigest = key[LifecyclePrefix.Length..];
            RepositoryCiCandidateRetentionReceipt receipt;
            try
            {
                receipt = await candidates.DeleteExpiredAsync(
                    candidateDigest,
                    authorityEpoch,
                    sequence,
                    authorityStillValid,
                    cancellationToken);
            }
            catch (ArgumentException exception)
            {
                throw new InvalidDataException("Candidate lifecycle discovery returned an invalid digest.", exception);
            }

            switch (receipt.Disposition)
            {
                case RepositoryCiCandidateRetentionDisposition.NotExpired:
                    notExpired++;
                    break;
                case RepositoryCiCandidateRetentionDisposition.Retained:
                    retained++;
                    break;
                case RepositoryCiCandidateRetentionDisposition.Deleted:
                    deleted++;
                    if (deleted >= maximumDeletions)
                        return new(scanned, notExpired, retained, deleted, alreadyDeleted, deferred, false);
                    break;
                case RepositoryCiCandidateRetentionDisposition.AlreadyDeleted:
                    alreadyDeleted++;
                    break;
                case RepositoryCiCandidateRetentionDisposition.StaleAuthority:
                    authorityLost = true;
                    return new(scanned, notExpired, retained, deleted, alreadyDeleted, deferred, authorityLost);
                case RepositoryCiCandidateRetentionDisposition.NotFound:
                case RepositoryCiCandidateRetentionDisposition.IdentityConflict:
                case RepositoryCiCandidateRetentionDisposition.ConcurrentUpdate:
                    deferred++;
                    break;
                default:
                    throw new InvalidDataException("Candidate retention returned an invalid disposition.");
            }
        }

        return new(scanned, notExpired, retained, deleted, alreadyDeleted, deferred, authorityLost);
    }
}
