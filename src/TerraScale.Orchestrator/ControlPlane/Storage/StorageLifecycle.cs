using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Storage;

/// <summary>Technical caller-input snapshot limits; these are not storage topology or writer policy caps.</summary>
public static class StorageTechnicalInputLimits
{
    public const int MaximumWriterObservationCount = 4_096;
}

internal static class StorageInputSnapshot
{
    internal static bool TryCopyWriters(IEnumerable<StorageWriterObservation?>? source, int businessMaximum,
        out StorageWriterObservation[] snapshot)
    {
        snapshot = [];
        if (source is null) return businessMaximum > 0;
        if (businessMaximum <= 0) return false;
        var maximum = Math.Min(businessMaximum, StorageTechnicalInputLimits.MaximumWriterObservationCount);
        var values = new List<StorageWriterObservation>(Math.Min(maximum, 256));
        try
        {
            using var iterator = source.GetEnumerator();
            while (iterator.MoveNext())
            {
                if (values.Count == maximum) return false;
                var current = iterator.Current;
                if (current is null) return false;
                values.Add(current);
            }
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            return false;
        }
        snapshot = values.ToArray();
        return true;
    }
}

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
        if (volume is not { } authorizedVolume)
            return StorageDecision.Hold(StorageDecisionCode.InvalidInput);
        if (evidence is null || evidence.Scope is not { } evidenceScope || !evidenceScope.IsWellFormed || evidenceScope != authorizedVolume.EvidenceScope)
            return StorageDecision.Hold(StorageDecisionCode.WrongEvidenceScope, authorizedVolume.Trace());
        var trace = authorizedVolume.Trace();
        return checkpoint switch
        {
            StorageCreateCheckpoint.ClaimAccepted => StorageDecision.Emit(StorageAction.Observe, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep, trace),
            StorageCreateCheckpoint.CapacityAndBudgetChecked => StorageDecision.Emit(StorageAction.Create, StorageIntentTarget.ProviderVolume, StorageDecisionCode.NextStep, trace),
            StorageCreateCheckpoint.VolumeCreated => StorageDecision.Emit(StorageAction.Attach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep, trace),
            StorageCreateCheckpoint.AttachmentCreated => StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep, trace),
            StorageCreateCheckpoint.DeviceIdentityVerified => StorageDecision.Emit(StorageAction.Classify, StorageIntentTarget.DeviceIdentity, StorageDecisionCode.NextStep, trace),
            StorageCreateCheckpoint.Classified => StorageFormatPlanner.Plan(authorizedVolume, context, evidence),
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
        if (volume is not { } authorizedVolume)
            return StorageDecision.Hold(StorageDecisionCode.InvalidInput);
        if (evidence is null || evidence.Scope is not { } evidenceScope || !evidenceScope.IsWellFormed || evidenceScope != authorizedVolume.EvidenceScope)
            return StorageDecision.Hold(StorageDecisionCode.WrongEvidenceScope, authorizedVolume.Trace());
        var trace = authorizedVolume.Trace();
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
    { Node = node; Attachment = attachment; Epoch = epoch; }
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
        Scope = scope; ProcessStopped = processStopped; LeaseRevoked = leaseRevoked; ProviderDetached = providerDetached;
        HealthVerified = healthVerified; ProposedEpoch = proposedEpoch;
        WriterInventoryComplete = writerInventoryComplete;
        var captured = StorageInputSnapshot.TryCopyWriters(writers, maximumWriterObservations, out _writers);
        _view = Array.AsReadOnly(_writers);
        IsWellFormed = scope is not null && scope.IsWellFormed && maximumWriterObservations > 0 && proposedEpoch.IsValid && writerInventoryComplete == StorageProof.Proven
            && captured
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
    internal IEnumerable<StorageProof> Proofs()
    {
        yield return ProcessStopped; yield return LeaseRevoked; yield return ProviderDetached;
        yield return HealthVerified; yield return WriterInventoryComplete;
    }
}

public static class StorageAttachmentPlanner
{
    public static StorageDecision Plan(StorageVolumeRecord? volume, StorageAuthorityContext? context,
        StorageNodeId? targetNode, StorageReattachEvidence? evidence)
    {
        var validation = StorageAuthority.Validate(volume, context);
        if (validation != StorageDecisionCode.Completed) return StorageDecision.Hold(validation, volume?.Trace());
        if (volume is not { } authorizedVolume)
            return StorageDecision.Hold(StorageDecisionCode.InvalidInput);
        var trace = authorizedVolume.Trace();
        if (targetNode is not { } authorizedTarget || evidence is null || evidence.Scope is not { } evidenceScope || !evidenceScope.IsWellFormed)
            return StorageDecision.Hold(StorageDecisionCode.InvalidInput, trace);
        if (evidenceScope != authorizedVolume.EvidenceScope) return StorageDecision.Hold(StorageDecisionCode.WrongEvidenceScope, trace);
        if (evidence.Proofs().Any(static proof => !Enum.IsDefined(proof)))
            return StorageDecision.Hold(StorageDecisionCode.InvalidInput, trace);
        if (evidence.Proofs().Any(static proof => proof == StorageProof.Contradicted))
            return StorageDecision.Hold(StorageDecisionCode.StepContradicted, trace);
        if (!evidence.IsWellFormed) return StorageDecision.Hold(StorageDecisionCode.InvalidInput, trace);
        if (evidence.Writers.Count > 1) return StorageDecision.Hold(StorageDecisionCode.DualWriter, trace);
        if (evidence.Writers.Count == 0)
        {
            if (evidence.ProviderDetached != StorageProof.Proven) return StorageDecision.Emit(StorageAction.Detach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep, trace);
            if (evidence.ProposedEpoch.Value <= authorizedVolume.WriterEpoch.Value) return StorageDecision.Hold(StorageDecisionCode.NewWriterEpochRequired, trace);
            return StorageDecision.Emit(StorageAction.Attach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep,
                authorizedVolume.Trace(authorizedEpoch: evidence.ProposedEpoch, authorizedNode: authorizedTarget));
        }
        var current = evidence.Writers[0];
        if (current.Attachment != authorizedVolume.Attachment) return StorageDecision.Hold(StorageDecisionCode.WrongOwner, trace);
        if (current.Epoch != authorizedVolume.WriterEpoch) return StorageDecision.Hold(StorageDecisionCode.StaleWriterEpoch, trace);
        if (current.Node == authorizedTarget)
            return evidence.HealthVerified == StorageProof.Proven
                ? StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.Completed, trace)
                : StorageDecision.Emit(StorageAction.Verify, StorageIntentTarget.Application, StorageDecisionCode.HealthVerificationRequired, trace);
        if (evidence.ProcessStopped != StorageProof.Proven || evidence.LeaseRevoked != StorageProof.Proven)
            return StorageDecision.Hold(StorageDecisionCode.ReattachProofMissing, trace);
        if (evidence.ProviderDetached != StorageProof.Proven)
            return StorageDecision.Emit(StorageAction.Detach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep, trace);
        if (evidence.ProposedEpoch.Value <= current.Epoch.Value || evidence.ProposedEpoch.Value <= authorizedVolume.WriterEpoch.Value)
            return StorageDecision.Hold(StorageDecisionCode.NewWriterEpochRequired, trace);
        return StorageDecision.Emit(StorageAction.Attach, StorageIntentTarget.ProviderAttachment, StorageDecisionCode.NextStep,
            authorizedVolume.Trace(authorizedEpoch: evidence.ProposedEpoch, authorizedNode: authorizedTarget));
    }
}

