using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

/// <summary>
/// Keeps a protected-main delivery pending until its exact immutable candidate can be qualified.
/// </summary>
internal sealed class RepositoryCiQualificationController(
    Func<string, long, long, Func<bool>, CancellationToken,
        Task<RepositoryCiQualificationCoordinationReceipt>> coordinate,
    Func<RegionalAuthoritySnapshot> authority,
    Func<string, ForgejoCommitStatusState, CancellationToken, Task> reportStatus)
{
    internal async Task<bool> RunToCompletionAsync(
        ForgejoCiTriggerPlan trigger,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(trigger);
        if (trigger.Disposition != ForgejoCiTriggerDisposition.Dispatch ||
            trigger.Reason != ForgejoCiTriggerReason.QualifiedPromotion ||
            !trigger.RequiresQualifiedCandidate)
            throw new ArgumentException("Only a protected-main qualification trigger can be processed.",
                nameof(trigger));

        var lease = authority();
        if (!Ready(lease)) return false;
        bool StillValid() => RepositoryCiController.SameAuthority(lease, authority());
        var receipt = await coordinate(
            trigger.Envelope.DedupeKey,
            lease.Epoch,
            lease.KvRevision,
            StillValid,
            cancellationToken);
        if (receipt.Disposition is RepositoryCiQualificationCoordinationDisposition.Recorded or
            RepositoryCiQualificationCoordinationDisposition.Duplicate)
        {
            if (!receipt.IsQualified)
                throw new InvalidDataException("A successful CI qualification returned no candidate.");
            await reportStatus(
                trigger.Envelope.Revision,
                ForgejoCommitStatusState.Success,
                cancellationToken);
            return true;
        }
        if (receipt.Disposition is RepositoryCiQualificationCoordinationDisposition.CandidateMissing or
            RepositoryCiQualificationCoordinationDisposition.AuthorityLost)
            return false;
        throw new InvalidDataException($"Repository CI qualification failed closed: {receipt.Disposition}.");
    }

    private static bool Ready(RegionalAuthoritySnapshot value) =>
        value.Ready && value.IsLeader && value.Epoch > 0 && value.KvRevision > 0;
}
