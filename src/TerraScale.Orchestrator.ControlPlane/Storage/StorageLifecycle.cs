using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Storage;

public enum StorageCreateCheckpoint
{
    Unknown = 0, ClaimAccepted, CapacityAndBudgetChecked, VolumeCreated, AttachmentCreated,
    DeviceIdentityVerified, Classified, FormattedIfNew, Mounted, OwnershipAndPerformanceVerified, Ready,
}

public sealed record StorageFormatEvidence(StorageEvidenceScope Scope, StorageProof ProviderIdentityProof,
    StorageDeviceClassification Classification, StorageProof BlankProof, StorageProof FilesystemIdentityProof);

public static class StorageCreatePlanner
{
    public static StorageDecision Plan(StorageVolumeRecord? volume, StorageAuthorityContext? context,
        StorageCreateCheckpoint checkpoint, StorageFormatEvidence? evidence)
    {
        var validation = StorageAuthority.Validate(volume, context);
        if (validation != StorageDecisionCode.Completed) return StorageDecision.Hold(validation, volume?.Trace());
        if (evidence is null || evidence.Scope is null || !evidence.Scope.IsWellFormed || evidence.Scope != volume!.EvidenceScope)
            return StorageDecision.Hold(StorageDecisionCode.WrongEvidenceScope, volume?.Trace());
        var trace = volume!.Trace();
        return checkpoint switch
        {
            StorageCreateCheckpoint.ClaimAccepted => StorageDecision.Emit(StorageAction.Observe, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep, trace),
            StorageCreateCheckpoint.CapacityAndBudgetChecked => StorageDecision.Emit(StorageAction.Create, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep, trace),
            StorageCreateCheckpoint.VolumeCreated => StorageDecision.Emit(StorageAction.Attach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep, trace),
            StorageCreateCheckpoint.AttachmentCreated => StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep, trace),
            StorageCreateCheckpoint.DeviceIdentityVerified => StorageDecision.Emit(StorageAction.Classify, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep, trace),
            StorageCreateCheckpoint.Classified => StorageFormatPlanner.Plan(volume, context, evidence),
            StorageCreateCheckpoint.FormattedIfNew => StorageDecision.Emit(StorageAction.Mount, StorageIntentTarget.Filesystem, StorageDecisionCode.NextStep, trace),
            StorageCreateCheckpoint.Mounted => StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.NextStep, trace),
            StorageCreateCheckpoint.OwnershipAndPerformanceVerified or StorageCreateCheckpoint.Ready => StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.Completed, trace),
            _ => StorageDecision.Hold(StorageDecisionCode.InvalidInput, trace),
        };
    }
}

public static class StorageFormatPlanner
{
    public static StorageDecision Plan(StorageVolumeRecord? volume, StorageAuthorityContext? context, StorageFormatEvidence? evidence)
    {
        var validation = StorageAuthority.Validate(volume, context);
        if (validation != StorageDecisionCode.Completed) return StorageDecision.Hold(validation, volume?.Trace());
        if (evidence is null || evidence.Scope is null || !evidence.Scope.IsWellFormed || evidence.Scope != volume!.EvidenceScope)
            return StorageDecision.Hold(StorageDecisionCode.WrongEvidenceScope, volume?.Trace());
        var trace = volume!.Trace();
        if (evidence.ProviderIdentityProof != StorageProof.Proven) return StorageDecision.Hold(StorageDecisionCode.WrongProviderVolume, trace);
        if (evidence.Classification == StorageDeviceClassification.Recognized)
            return evidence.FilesystemIdentityProof == StorageProof.Proven
                ? StorageDecision.Emit(StorageAction.Mount, StorageIntentTarget.Filesystem, StorageDecisionCode.RecognizedVolumeNeverFormats, trace)
                : StorageDecision.Hold(StorageDecisionCode.WrongOwner, trace);
        if (evidence.Classification == StorageDeviceClassification.Unknown)
            return StorageDecision.Emit(StorageAction.Classify, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep, trace);
        if (evidence.Classification != StorageDeviceClassification.Blank || evidence.BlankProof != StorageProof.Proven)
            return StorageDecision.Hold(StorageDecisionCode.BlankProofRequired, trace);
        return StorageDecision.Emit(StorageAction.Format, StorageIntentTarget.Filesystem, StorageDecisionCode.NextStep, trace);
    }
}

public sealed class StorageWriterObservation
{
    public StorageWriterObservation(StorageNodeId node, StorageAttachmentId attachment, StorageWriterEpoch epoch)
    { Node=node; Attachment=attachment; Epoch=epoch; }
    public StorageNodeId Node { get; }
    public StorageAttachmentId Attachment { get; }
    public StorageWriterEpoch Epoch { get; }
}

public sealed class StorageReattachEvidence
{
    private readonly StorageWriterObservation[] _writers;
    private readonly ReadOnlyCollection<StorageWriterObservation> _view;
    public StorageReattachEvidence(StorageEvidenceScope scope, IEnumerable<StorageWriterObservation?>? writers, StorageProof processStopped,
        StorageProof leaseRevoked, StorageProof providerDetached, StorageProof healthVerified,
        StorageProof writerInventoryComplete, StorageWriterEpoch proposedEpoch, int maximumWriterObservations)
    {
        Scope=scope; ProcessStopped=processStopped; LeaseRevoked=leaseRevoked; ProviderDetached=providerDetached;
        HealthVerified=healthVerified; ProposedEpoch=proposedEpoch;
        WriterInventoryComplete=writerInventoryComplete;
        var collected = new List<StorageWriterObservation>();
        if (writers is not null)
        {
            foreach (var writer in writers)
            {
                if (writer is null || collected.Count >= maximumWriterObservations) { IsWellFormed=false; _writers=[]; _view=Array.AsReadOnly(_writers); return; }
                collected.Add(writer);
            }
        }
        _writers=[.. collected]; _view=Array.AsReadOnly(_writers);
        IsWellFormed=scope is not null && scope.IsWellFormed && maximumWriterObservations > 0 && proposedEpoch.IsValid && writerInventoryComplete == StorageProof.Proven
            && _writers.All(static writer => writer.Node is not null && writer.Attachment is not null && writer.Epoch.IsValid)
            && _writers.Select(static writer => writer.Attachment).Distinct().Count() == _writers.Length;
    }
    public IReadOnlyList<StorageWriterObservation> Writers => _view;
    public StorageEvidenceScope Scope { get; }
    public StorageProof ProcessStopped { get; }
    public StorageProof LeaseRevoked { get; }
    public StorageProof ProviderDetached { get; }
    public StorageProof HealthVerified { get; }
    public StorageProof WriterInventoryComplete { get; }
    public StorageWriterEpoch ProposedEpoch { get; }
    public bool IsWellFormed { get; }
}

public static class StorageAttachmentPlanner
{
    public static StorageDecision Plan(StorageVolumeRecord? volume, StorageAuthorityContext? context,
        StorageNodeId? targetNode, StorageReattachEvidence? evidence)
    {
        var validation = StorageAuthority.Validate(volume, context);
        if (validation != StorageDecisionCode.Completed) return StorageDecision.Hold(validation, volume?.Trace());
        var trace=volume!.Trace();
        if (targetNode is null || evidence is null || !evidence.IsWellFormed) return StorageDecision.Hold(StorageDecisionCode.InvalidInput, trace);
        if (evidence.Scope != volume.EvidenceScope) return StorageDecision.Hold(StorageDecisionCode.WrongEvidenceScope,trace);
        if (evidence.Writers.Count > 1) return StorageDecision.Hold(StorageDecisionCode.DualWriter, trace);
        if (evidence.Writers.Count == 0)
        {
            if (evidence.ProviderDetached != StorageProof.Proven) return StorageDecision.Emit(StorageAction.Detach,StorageIntentTarget.ProviderAttachment,StorageDecisionCode.NextStep,trace);
            if (evidence.ProposedEpoch.Value <= volume.WriterEpoch.Value) return StorageDecision.Hold(StorageDecisionCode.NewWriterEpochRequired,trace);
            return StorageDecision.Emit(StorageAction.Attach,StorageIntentTarget.ProviderAttachment,StorageDecisionCode.NextStep,
                volume.Trace(authorizedEpoch:evidence.ProposedEpoch));
        }
        var current=evidence.Writers[0];
        if (current.Attachment != volume.Attachment) return StorageDecision.Hold(StorageDecisionCode.WrongOwner, trace);
        if (current.Epoch != volume.WriterEpoch) return StorageDecision.Hold(StorageDecisionCode.StaleWriterEpoch, trace);
        if (current.Node == targetNode)
            return evidence.HealthVerified == StorageProof.Proven
                ? StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.Completed, trace)
                : StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.HealthVerificationRequired, trace);
        if (evidence.ProcessStopped != StorageProof.Proven || evidence.LeaseRevoked != StorageProof.Proven)
            return StorageDecision.Hold(StorageDecisionCode.ReattachProofMissing, trace);
        if (evidence.ProviderDetached != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Detach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep, trace);
        if (evidence.ProposedEpoch.Value <= current.Epoch.Value || evidence.ProposedEpoch.Value <= volume.WriterEpoch.Value)
            return StorageDecision.Hold(StorageDecisionCode.NewWriterEpochRequired, trace);
        return StorageDecision.Emit(StorageAction.Attach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep,
            volume.Trace(authorizedEpoch: evidence.ProposedEpoch));
    }
}
