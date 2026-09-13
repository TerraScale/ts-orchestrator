using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Delivery;

internal sealed record NativeGitOpsSourceReconcileResult(
    NativeGitOpsSourceJournalDisposition Disposition,
    NativeGitOpsSourcePlan? SourcePlan);

/// <summary>Compiles and records one exact Forgejo revision only while regional authority remains exact.</summary>
internal sealed class NativeGitOpsSourceReconciler
{
    private const int MaximumConflictRetries = 8;
    private readonly ForgejoSourceClient source;
    private readonly NativeGitOpsSourceJournal journal;
    private readonly Func<RegionalAuthoritySnapshot> authority;

    internal NativeGitOpsSourceReconciler(
        ForgejoSourceClient source,
        NativeGitOpsSourceJournal journal,
        Func<RegionalAuthoritySnapshot> authority)
    {
        this.source = source;
        this.journal = journal;
        this.authority = authority;
    }

    internal async Task<NativeGitOpsSourceReconcileResult> ReconcileAsync(
        ForgejoBranchObservation observation,
        long authorityEpoch,
        long pollSequence,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(observation);
        if (!observation.Protected)
            throw new InvalidDataException("Native GitOps reconciliation requires a protected branch.");
        if (!HasAuthority(authorityEpoch))
            return new(NativeGitOpsSourceJournalDisposition.StaleAuthority, null);

        NativeGitOpsSourcePlan loaded;
        try
        {
            loaded = await NativeGitOpsSourceLoader.LoadAsync(
                source,
                observation.Revision,
                cancellationToken: cancellationToken);
        }
        catch (ForgejoSourceNotFoundException)
        {
            return new(NativeGitOpsSourceJournalDisposition.NotConfigured, null);
        }
        for (var attempt = 0; attempt < MaximumConflictRetries; attempt++)
        {
            if (!HasAuthority(authorityEpoch))
                return new(NativeGitOpsSourceJournalDisposition.StaleAuthority, null);
            var accepted = await journal.ReadAsync(
                observation.Revision.Repository,
                observation.Branch,
                cancellationToken);
            if (accepted is not null && authorityEpoch < accepted.AuthorityEpoch)
                return new(NativeGitOpsSourceJournalDisposition.StaleAuthority, null);

            var plan = loaded with
            {
                Diff = NativeGitOpsDiff.Compare(accepted?.Plan, loaded.Proposed)
            };
            if (!HasAuthority(authorityEpoch))
                return new(NativeGitOpsSourceJournalDisposition.StaleAuthority, null);
            var receipt = await journal.RecordAsync(
                observation.Branch,
                plan,
                authorityEpoch,
                pollSequence,
                accepted,
                () => HasAuthority(authorityEpoch),
                cancellationToken);
            if (receipt.Disposition != NativeGitOpsSourceJournalDisposition.ConcurrentUpdate)
                return new(receipt.Disposition, plan);
        }

        throw new InvalidOperationException("Native GitOps reconciliation could not resolve a concurrent writer.");
    }

    private bool HasAuthority(long expectedEpoch)
    {
        var snapshot = authority();
        return expectedEpoch > 0 && snapshot.Ready && snapshot.IsLeader && snapshot.Epoch == expectedEpoch;
    }
}

