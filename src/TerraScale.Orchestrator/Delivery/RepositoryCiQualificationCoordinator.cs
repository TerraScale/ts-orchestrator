using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery;

internal enum RepositoryCiQualificationCoordinationDisposition
{
    Unspecified,
    Recorded,
    Duplicate,
    TriggerMissing,
    TriggerNotQualification,
    CandidateMissing,
    AuthorityLost,
    IdentityConflict,
}

internal sealed record RepositoryCiQualificationCoordinationReceipt(
    RepositoryCiQualificationCoordinationDisposition Disposition,
    RepositoryCiQualifiedCandidate? Qualified)
{
    internal bool IsQualified =>
        (Disposition is RepositoryCiQualificationCoordinationDisposition.Recorded or
            RepositoryCiQualificationCoordinationDisposition.Duplicate) &&
        Qualified is not null;
}

/// <summary>
/// Resolves one durable protected-main trigger against exact signed branch observations and the
/// immutable candidate indexed by their tree set, then records the qualification under authority.
/// </summary>
internal sealed class RepositoryCiQualificationCoordinator(
    ForgejoCiTriggerJournal triggers,
    RepositoryCiCandidateJournal candidates,
    Func<ForgejoCiTriggerPlan, CancellationToken, Task<IReadOnlyList<ForgejoBranchObservation>>>
        readCurrentMainSources)
{
    internal async Task<RepositoryCiQualificationCoordinationReceipt> CoordinateAsync(
        string dedupeKey,
        long authorityEpoch,
        long sequence,
        Func<bool> authorityStillValid,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(readCurrentMainSources);
        ArgumentNullException.ThrowIfNull(authorityStillValid);
        if (authorityEpoch <= 0) throw new ArgumentOutOfRangeException(nameof(authorityEpoch));
        if (sequence <= 0) throw new ArgumentOutOfRangeException(nameof(sequence));

        var trigger = await triggers.ReadAsync(dedupeKey, cancellationToken);
        if (trigger is null)
            return Result(RepositoryCiQualificationCoordinationDisposition.TriggerMissing);
        if (trigger.Disposition != ForgejoCiTriggerDisposition.Dispatch ||
            trigger.Reason != ForgejoCiTriggerReason.QualifiedPromotion ||
            trigger.JobKind != JobKind.Promotion || !trigger.RequiresQualifiedCandidate)
            return Result(RepositoryCiQualificationCoordinationDisposition.TriggerNotQualification);
        if (!authorityStillValid())
            return Result(RepositoryCiQualificationCoordinationDisposition.AuthorityLost);

        var observed = await readCurrentMainSources(trigger, cancellationToken)
            ?? throw new InvalidDataException("The protected-main source reader returned no observations.");
        var sources = observed.Take(65).ToArray();
        if (!authorityStillValid())
            return Result(RepositoryCiQualificationCoordinationDisposition.AuthorityLost);
        var candidate = await candidates.FindCandidateAsync(sources, cancellationToken);
        if (!authorityStillValid())
            return Result(RepositoryCiQualificationCoordinationDisposition.AuthorityLost);
        if (candidate is null)
            return Result(RepositoryCiQualificationCoordinationDisposition.CandidateMissing);

        var qualified = RepositoryCiCandidateResolver.Resolve(trigger, candidate, sources);
        var recorded = await candidates.RecordQualifiedAsync(
            qualified,
            authorityEpoch,
            sequence,
            authorityStillValid,
            cancellationToken);
        return recorded.Disposition switch
        {
            RepositoryCiCandidateJournalDisposition.Recorded =>
                Result(RepositoryCiQualificationCoordinationDisposition.Recorded, qualified),
            RepositoryCiCandidateJournalDisposition.Duplicate =>
                Result(RepositoryCiQualificationCoordinationDisposition.Duplicate, qualified),
            RepositoryCiCandidateJournalDisposition.StaleAuthority =>
                Result(RepositoryCiQualificationCoordinationDisposition.AuthorityLost),
            RepositoryCiCandidateJournalDisposition.IdentityConflict =>
                Result(RepositoryCiQualificationCoordinationDisposition.IdentityConflict, qualified),
            _ => throw new InvalidDataException("The CI candidate journal returned an unspecified disposition."),
        };
    }

    private static RepositoryCiQualificationCoordinationReceipt Result(
        RepositoryCiQualificationCoordinationDisposition disposition,
        RepositoryCiQualifiedCandidate? qualified = null) => new(disposition, qualified);
}
