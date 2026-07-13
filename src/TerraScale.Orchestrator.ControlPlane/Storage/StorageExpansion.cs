namespace TerraScale.Orchestrator.ControlPlane.Storage;

public sealed class StorageExpansionEvidence
{
    public StorageExpansionEvidence(
        StorageEvidenceScope scope, StorageProof intentPersisted, StorageProof prechecksPassed, StorageProof recoveryPointVerified,
        StorageProof providerRequestRecorded, StorageProof providerSizeVerified, StorageProof guestRescanned,
        StorageProof layoutExtended, StorageProof filesystemGrown, StorageProof sizesVerified,
        StorageProof applicationHealthVerified, StorageProof metricsAndCostUpdated,
        StorageConflictClass conflicts)
    {
        Scope=scope; IntentPersisted=intentPersisted; PrechecksPassed=prechecksPassed; RecoveryPointVerified=recoveryPointVerified;
        ProviderRequestRecorded=providerRequestRecorded; ProviderSizeVerified=providerSizeVerified; GuestRescanned=guestRescanned;
        LayoutExtended=layoutExtended; FilesystemGrown=filesystemGrown; SizesVerified=sizesVerified;
        ApplicationHealthVerified=applicationHealthVerified; MetricsAndCostUpdated=metricsAndCostUpdated; Conflicts=conflicts;
    }
    public StorageEvidenceScope Scope { get; }
    public StorageProof IntentPersisted { get; }
    public StorageProof PrechecksPassed { get; }
    public StorageProof RecoveryPointVerified { get; }
    public StorageProof ProviderRequestRecorded { get; }
    public StorageProof ProviderSizeVerified { get; }
    public StorageProof GuestRescanned { get; }
    public StorageProof LayoutExtended { get; }
    public StorageProof FilesystemGrown { get; }
    public StorageProof SizesVerified { get; }
    public StorageProof ApplicationHealthVerified { get; }
    public StorageProof MetricsAndCostUpdated { get; }
    public StorageConflictClass Conflicts { get; }

    internal IEnumerable<StorageProof> OrderedProofs()
    {
        yield return IntentPersisted; yield return PrechecksPassed; yield return RecoveryPointVerified;
        yield return ProviderRequestRecorded; yield return ProviderSizeVerified; yield return GuestRescanned;
        yield return LayoutExtended; yield return FilesystemGrown; yield return SizesVerified;
        yield return ApplicationHealthVerified; yield return MetricsAndCostUpdated;
    }
}

public static class StorageExpansionPlanner
{
    public static StorageDecision Plan(StorageVolumeRecord? volume, StorageAuthorityContext? context, StorageExpansionEvidence? evidence)
    {
        var validation=StorageAuthority.Validate(volume,context);
        if (validation != StorageDecisionCode.Completed) return StorageDecision.Hold(validation, volume?.Trace(evidence?.Conflicts ?? StorageConflictClass.None));
        var trace=volume!.Trace(evidence?.Conflicts ?? StorageConflictClass.None);
        if (evidence is null) return StorageDecision.Hold(StorageDecisionCode.InvalidInput, trace);
        if (evidence.Scope is null || !evidence.Scope.IsWellFormed || evidence.Scope != volume.EvidenceScope)
            return StorageDecision.Hold(StorageDecisionCode.WrongEvidenceScope,trace);
        if (evidence.Conflicts != StorageConflictClass.None) return StorageDecision.Hold(StorageDecisionCode.ConflictingOperation, trace);
        if (evidence.OrderedProofs().Any(static proof => proof == StorageProof.Contradicted))
            return StorageDecision.Hold(StorageDecisionCode.StepContradicted, trace);
        var gap=false;
        foreach (var proof in evidence.OrderedProofs())
        {
            if (!Enum.IsDefined(proof)) return StorageDecision.Hold(StorageDecisionCode.InvalidInput, trace);
            if (proof != StorageProof.Proven) gap=true;
            else if (gap) return StorageDecision.Hold(StorageDecisionCode.ConflictingObservation, trace);
        }
        if (volume.RequestedBytes.Value < volume.FilesystemBytes.Value) return StorageDecision.Hold(StorageDecisionCode.ShrinkForbidden, trace);
        if (volume.RequestedBytes.Value == volume.FilesystemBytes.Value
            && evidence.IntentPersisted != StorageProof.Proven)
            return StorageDecision.Hold(StorageDecisionCode.NoGrowthRequested, trace);
        try
        {
            if (checked(volume.UsedBytes.Value + volume.FreeBytes.Value) != volume.FilesystemBytes.Value)
                return StorageDecision.Hold(StorageDecisionCode.SizeDisagreement, trace);
        }
        catch (OverflowException)
        {
            return StorageDecision.Hold(StorageDecisionCode.ArithmeticOverflow, trace);
        }

        if (evidence.IntentPersisted != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Observe, StorageIntentTarget.None, StorageDecisionCode.NextStep, trace);
        if (evidence.PrechecksPassed != StorageProof.Proven || evidence.RecoveryPointVerified != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.NextStep, trace);
        if (evidence.ProviderRequestRecorded != StorageProof.Proven)
            return volume.ProviderBytes.Value >= volume.RequestedBytes.Value
                ? StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep, trace)
                : StorageDecision.Emit(StorageAction.Extend, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep, trace);
        if (evidence.ProviderSizeVerified != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Observe, StorageIntentTarget.ProviderVolume, StorageDecisionCode.ProviderConvergencePending, trace);
        if (volume.ProviderBytes.Value < volume.RequestedBytes.Value)
            return StorageDecision.Emit(StorageAction.Observe, StorageIntentTarget.ProviderVolume, StorageDecisionCode.ProviderConvergencePending, trace);
        if (evidence.GuestRescanned != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Rescan, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep, trace);
        if (volume.BlockBytes.Value < volume.RequestedBytes.Value)
            return StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.SizeDisagreement, trace);
        if (evidence.LayoutExtended != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Extend, StorageIntentTarget.StorageLayout, StorageDecisionCode.NextStep, trace);
        if (evidence.FilesystemGrown != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Grow, StorageIntentTarget.Filesystem, StorageDecisionCode.NextStep, trace);
        if (volume.FilesystemBytes.Value < volume.RequestedBytes.Value)
            return StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.Filesystem, StorageDecisionCode.SizeDisagreement, trace);
        if (evidence.SizesVerified != StorageProof.Proven
            || volume.ProviderBytes.Value < volume.RequestedBytes.Value
            || volume.BlockBytes.Value < volume.RequestedBytes.Value
            || volume.FilesystemBytes.Value < volume.RequestedBytes.Value)
            return StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.Filesystem, StorageDecisionCode.SizeDisagreement, trace);
        if (evidence.ApplicationHealthVerified != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.NextStep, trace);
        if (evidence.MetricsAndCostUpdated != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Observe, StorageIntentTarget.MetricsAndCost, StorageDecisionCode.NextStep, trace);
        return StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.Completed, trace);
    }
}
