namespace TerraScale.Orchestrator.ControlPlane.Storage;

public sealed class StorageDeletionEvidence
{
    public StorageDeletionEvidence(
        StorageEvidenceScope scope, StorageProof leadershipTransferred, StorageProof topologyRemoved,
        StorageProof quorumAndReplicationHealthy, StorageProof noDatabaseReference,
        StorageProof applicationBackupVerified, StorageProof retentionSatisfied,
        StorageProof ownerFenceVerified, StorageProof quarantined,
        StorageProof disposablePolicyVerified, StorageProof postDeleteAuditReady,
        StorageProof deletionRequested, StorageProof providerAbsent, StorageProof postDeleteAuditPassed)
    {
        Scope = scope; LeadershipTransferred = leadershipTransferred; TopologyRemoved = topologyRemoved;
        QuorumAndReplicationHealthy = quorumAndReplicationHealthy; NoDatabaseReference = noDatabaseReference;
        ApplicationBackupVerified = applicationBackupVerified; RetentionSatisfied = retentionSatisfied;
        OwnerFenceVerified = ownerFenceVerified; Quarantined = quarantined;
        DisposablePolicyVerified = disposablePolicyVerified; PostDeleteAuditReady = postDeleteAuditReady;
        DeletionRequested = deletionRequested; ProviderAbsent = providerAbsent; PostDeleteAuditPassed = postDeleteAuditPassed;
    }
    public StorageEvidenceScope Scope { get; }
    public StorageProof LeadershipTransferred { get; }
    public StorageProof TopologyRemoved { get; }
    public StorageProof QuorumAndReplicationHealthy { get; }
    public StorageProof NoDatabaseReference { get; }
    public StorageProof ApplicationBackupVerified { get; }
    public StorageProof RetentionSatisfied { get; }
    public StorageProof OwnerFenceVerified { get; }
    public StorageProof Quarantined { get; }
    public StorageProof DisposablePolicyVerified { get; }
    public StorageProof PostDeleteAuditReady { get; }
    public StorageProof DeletionRequested { get; }
    public StorageProof ProviderAbsent { get; }
    public StorageProof PostDeleteAuditPassed { get; }

    internal IEnumerable<StorageProof> CommonPreconditions()
    {
        yield return LeadershipTransferred; yield return TopologyRemoved; yield return QuorumAndReplicationHealthy;
        yield return NoDatabaseReference; yield return ApplicationBackupVerified; yield return RetentionSatisfied;
        yield return OwnerFenceVerified; yield return PostDeleteAuditReady;
    }

    internal IEnumerable<StorageProof> AllProofs()
    {
        foreach (var proof in CommonPreconditions()) yield return proof;
        yield return Quarantined; yield return DisposablePolicyVerified; yield return DeletionRequested;
        yield return ProviderAbsent; yield return PostDeleteAuditPassed;
    }
}

public static class StorageDeletionPlanner
{
    public static StorageDecision Plan(StorageVolumeRecord? volume, StorageAuthorityContext? context, StorageDeletionEvidence? evidence)
    {
        var validation = StorageAuthority.Validate(volume, context);
        if (validation != StorageDecisionCode.Completed) return StorageDecision.Hold(validation, volume?.Trace());
        if (volume is not { } authorizedVolume)
            return StorageDecision.Hold(StorageDecisionCode.InvalidInput);
        var trace = authorizedVolume.Trace();
        if (evidence is null) return StorageDecision.Hold(StorageDecisionCode.InvalidInput, trace);
        if (authorizedVolume.Retention == StorageRetention.Permanent) return StorageDecision.Hold(StorageDecisionCode.PermanentRetention, trace);
        if (evidence.Scope is not { } evidenceScope || !evidenceScope.IsWellFormed || evidenceScope != authorizedVolume.EvidenceScope)
            return StorageDecision.Hold(StorageDecisionCode.WrongEvidenceScope, trace);
        if (evidence.AllProofs().Any(static proof => !Enum.IsDefined(proof)))
            return StorageDecision.Hold(StorageDecisionCode.InvalidInput, trace);
        if (evidence.AllProofs().Any(static proof => proof == StorageProof.Contradicted))
            return StorageDecision.Hold(StorageDecisionCode.StepContradicted, trace);
        if (evidence.CommonPreconditions().Any(static proof => proof != StorageProof.Proven))
            return StorageDecision.Hold(StorageDecisionCode.DeletionProofMissing, trace);
        if (authorizedVolume.Retention == StorageRetention.ElasticQuarantine && evidence.Quarantined != StorageProof.Proven)
            return StorageDecision.Hold(StorageDecisionCode.QuarantineProofMissing, trace);
        if (authorizedVolume.Retention == StorageRetention.ExplicitDisposable && evidence.DisposablePolicyVerified != StorageProof.Proven)
            return StorageDecision.Hold(StorageDecisionCode.DisposableProofMissing, trace);
        if (evidence.DeletionRequested != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Delete, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep, trace);
        if (evidence.ProviderAbsent != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Observe, StorageIntentTarget.ProviderVolume, StorageDecisionCode.ProviderConvergencePending, trace);
        if (evidence.PostDeleteAuditPassed != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Observe, StorageIntentTarget.PostDeleteAudit, StorageDecisionCode.PostDeleteAuditRequired, trace);
        return StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.PostDeleteAudit, StorageDecisionCode.Completed, trace);
    }
}
