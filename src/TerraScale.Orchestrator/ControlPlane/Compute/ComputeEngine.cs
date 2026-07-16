using System.Collections.ObjectModel;
using System.Globalization;

namespace TerraScale.Orchestrator.ControlPlane.Compute;

public static class ComputeEngine
{
    private const ComputeRequirementCode Requirement = ComputeRequirementCode.ReqO011;
    private static readonly StringComparer Ordinal = StringComparer.Ordinal;

    public static ComputeDecision DecideScaleOut(ScaleOutRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var decision = DecideScaleOutCore(request);
        return decision.Errors.Count == 0
            ? Decision(decision.Intents, decision.Errors, decision.Trace, request)
            : decision;
    }

    private static ComputeDecision DecideScaleOutCore(ScaleOutRequest request)
    {
        var operation = request.Binding?.Operation;
        if (!ValidBinding(request.Binding, request.MaximumIdentityLength) || !Defined(request.State) ||
            request.EvaluationSequence <= 0 || !ValidDemand(request.Demand, request.Binding!, request.MaximumIdentityLength) ||
            !ValidPlan(request.Plan, request.Binding!, request.MaximumIdentityLength))
            return Held(ComputeErrorCode.InvalidInput, operation);
        var binding = request.Binding!;
        if (request.Demand.ObservationSequence > request.EvaluationSequence)
            return Held(ComputeErrorCode.EvidenceStale, operation);
        var demandFresh = request.Demand.FreshThroughSequence >= request.EvaluationSequence;
        var boundedSafety = request.Demand.ExplicitDemand && request.Demand.SafetyBounded &&
            request.Demand.Trigger is ComputeTrigger.FailedHostReplacement or ComputeTrigger.SafetyRecovery;
        if (!demandFresh && !boundedSafety)
            return Held(ComputeErrorCode.EvidenceStale, operation);
        if (!request.Demand.ExplicitDemand || (!request.Demand.Sustained && !boundedSafety))
            return Held(ComputeErrorCode.MissingProof, operation);
        if (request.Plan.DesiredNodes != request.Demand.RequiredNodes)
            return Held(ComputeErrorCode.EvidenceMismatch, operation);
        if (request.State == ScaleOutState.DemandObserved)
        {
            if (request.PersistedPlan is not null || request.Authorization is not null ||
                request.CreateEvidence is not null || request.Progress is not null)
                return Held(ComputeErrorCode.EvidenceMismatch, operation);
        }
        else if (!ValidPersistedPlan(request.PersistedPlan, request.Plan, request.MaximumIdentityLength))
            return Held(ComputeErrorCode.MissingProof, operation);
        if (request.State == ScaleOutState.PlanPersisted &&
            (request.Authorization is not null || request.CreateEvidence is not null || request.Progress is not null))
            return Held(ComputeErrorCode.EvidenceMismatch, operation);
        if (request.State >= ScaleOutState.Authorized)
        {
            var authorizationError = ValidateAuthorization(request.Authorization, binding, request.MaximumIdentityLength);
            if (authorizationError != ComputeErrorCode.Unspecified) return Held(authorizationError, operation);
            if (request.Authorization!.AuthorizedNodes != request.Plan.DesiredNodes ||
                request.Authorization.Resources != request.Plan.Resources)
                return Held(ComputeErrorCode.EvidenceMismatch, operation);
        }
        if (request.State == ScaleOutState.Authorized && request.Progress is not null)
            return Held(ComputeErrorCode.EvidenceMismatch, operation);
        if (request.State == ScaleOutState.RequestRecorded &&
            request.CreateEvidence?.Status == ProviderCreateStatus.OutcomeUnknown && request.Progress is not null)
            return Held(ComputeErrorCode.EvidenceMismatch, operation);
        if (request.State >= ScaleOutState.InstanceCreated)
        {
            if (!ValidCreate(request.CreateEvidence, binding, request.MaximumIdentityLength) ||
                request.CreateEvidence!.Status != ProviderCreateStatus.Created || request.CreateEvidence.Resource is null ||
                !ValidProgress(request.Progress, binding, request.MaximumIdentityLength) ||
                request.Progress!.Resource != request.CreateEvidence.Resource || request.Progress.Node is null)
                return Held(ComputeErrorCode.MissingProof, operation);
        }

        switch (request.State)
        {
            case ScaleOutState.DemandObserved:
                return One(new PersistScalePlanIntent(binding, request.Plan.Resources, request.Plan.DesiredNodes,
                    request.Plan.PlanIdentity), ComputeTraceCode.PlanRequired);
            case ScaleOutState.PlanPersisted:
                return One(new AuthorizeCapacityIntent(binding, request.PersistedPlan!), ComputeTraceCode.AuthorizationReady);
            case ScaleOutState.Authorized:
                if (!ValidCreate(request.CreateEvidence, binding, request.MaximumIdentityLength) ||
                    request.CreateEvidence!.Status != ProviderCreateStatus.ProvenAbsent)
                    return Held(ComputeErrorCode.MissingProof, operation);
                return One(new RequestCreateIntent(binding, request.CreateEvidence.CreateKey, request.PersistedPlan!,
                    request.Authorization!, request.CreateEvidence), ComputeTraceCode.CreateReady);
            case ScaleOutState.RequestRecorded:
                if (!ValidCreate(request.CreateEvidence, binding, request.MaximumIdentityLength))
                    return Held(ComputeErrorCode.MissingProof, operation);
                if (request.CreateEvidence!.Status == ProviderCreateStatus.OutcomeUnknown)
                    return One(new ObserveCreateIntent(binding, request.CreateEvidence.CreateKey), ComputeTraceCode.ObservationRequired);
                if (request.CreateEvidence.Status != ProviderCreateStatus.Created || request.CreateEvidence.Resource is null)
                    return Held(ComputeErrorCode.MissingProof, operation);
                return DecideCreated(request, request.CreateEvidence.Resource);
            case ScaleOutState.InstanceCreated:
                return DecideCreated(request, request.CreateEvidence!.Resource!);
            case ScaleOutState.Enrolled:
                if (!ValidProgress(request.Progress, binding, request.MaximumIdentityLength) ||
                    !ValidOutPrefix(ScaleOutState.Enrolled, request.Progress!) || request.Progress!.Resource is null ||
                    request.Progress.Node is null)
                    return Held(ComputeErrorCode.MissingProof, operation);
                return One(new ReadyNodeIntent(binding, request.Progress.Resource!, request.Progress.Node!,
                    request.Progress.BootstrapProof!, request.Progress.DiskProof!, request.Authorization!.PlacementProof),
                    ComputeTraceCode.ReadinessReady);
            case ScaleOutState.Ready:
                if (!ValidProgress(request.Progress, binding, request.MaximumIdentityLength) ||
                    !ValidOutPrefix(ScaleOutState.Ready, request.Progress!))
                    return Held(ComputeErrorCode.PlacementDenied, operation);
                return Completed();
            case ScaleOutState.Completed:
                if (!ValidProgress(request.Progress, binding, request.MaximumIdentityLength) ||
                    !ValidOutPrefix(ScaleOutState.Completed, request.Progress!))
                    return Held(ComputeErrorCode.MissingProof, operation);
                return Completed();
            default:
                return Held(ComputeErrorCode.InvalidInput, operation);
        }
    }

    public static ComputeDecision DecideScaleIn(ScaleInRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var operation = request.Binding?.Compute?.Operation;
        if (!ValidScaleInBinding(request.Binding, request.MaximumIdentityLength) || !Defined(request.State) ||
            request.EvaluationSequence <= 0 || !ValidScaleInAuthorization(request.Authorization, request.Binding!,
                request.MaximumIdentityLength) || !ValidScaleInProgress(request.Progress, request.Binding!,
                request.MaximumIdentityLength))
            return Held(ComputeErrorCode.InvalidInput, operation);
        var binding = request.Binding!;
        var authorization = request.Authorization;
        if (authorization.ObservationSequence > request.EvaluationSequence ||
            authorization.FreshThroughSequence < request.EvaluationSequence)
            return Held(ComputeErrorCode.EvidenceStale, operation);
        if (authorization.ConflictingOperation) return Held(ComputeErrorCode.ConflictingOperation, operation);
        if (!authorization.SustainedLowUse || !authorization.CooldownPassed || !authorization.LifetimePassed)
            return Held(ComputeErrorCode.MissingProof, operation);
        if (!authorization.CostBenefitPassed) return Held(ComputeErrorCode.CostDenied, operation);
        if (authorization.ReplacementCapacity <= 0 || authorization.AvailabilityHeadroom <= 0 ||
            !authorization.RegionalControlHealthy || !authorization.NatsHealthy)
            return Held(ComputeErrorCode.AvailabilityDenied, operation);
        var critical = binding.Role is ComputeNodeRole.SeedController or ComputeNodeRole.ControlNats or
            ComputeNodeRole.ProductNats or ComputeNodeRole.TerraBase;
        if (authorization.CurrentCount <= authorization.MinimumCount || authorization.CurrentCount <= 1 ||
            (critical && (authorization.MinimumCount < 3 || authorization.CurrentCount - 1 < 3)))
            return Held(ComputeErrorCode.FloorDenied, operation);
        var stateful = binding.Role is ComputeNodeRole.ElasticStateful or ComputeNodeRole.ControlNats or
            ComputeNodeRole.ProductNats or ComputeNodeRole.TerraBase;
        if (authorization.StatefulDisposition == StatefulDisposition.Vetoed ||
            (stateful && (authorization.StatefulDisposition != StatefulDisposition.Approved || !authorization.StatefulApproved)))
            return Held(ComputeErrorCode.StatefulVeto, operation);

        var progress = request.Progress!;
        if ((stateful && (progress.VolumeDisposition != VolumeDisposition.RetainedStateful || progress.StatefulOwner is null)) ||
            (!stateful && (progress.VolumeDisposition != VolumeDisposition.DetachedEphemeral || progress.StatefulOwner is not null)))
            return Held(ComputeErrorCode.StatefulVeto, operation);
        if (request.State == ScaleInState.Terminated && (!progress.ExactInstanceTerminated || !progress.BootVolumeAbsent))
            return Held(ComputeErrorCode.UnsafeTermination, operation);
        if (request.State == ScaleInState.Audited && !progress.OrphanAuditPassed)
            return Held(ComputeErrorCode.OrphanDenied, operation);
        if (!ValidScaleInPrefix(request.State, progress)) return Held(ComputeErrorCode.MissingProof, operation);
        switch (request.State)
        {
            case ScaleInState.CandidateSelected:
                return One(new CordonNodeIntent(binding), ComputeTraceCode.CordonReady);
            case ScaleInState.Cordoned:
                return One(new DrainNodeIntent(binding, progress.CordonProof!), ComputeTraceCode.DrainReady);
            case ScaleInState.Drained:
                return One(new DeregisterNodeIntent(binding, authorization.StatefulProof), ComputeTraceCode.DeregistrationReady);
            case ScaleInState.Deregistered:
                if (!Defined(progress.VolumeDisposition) ||
                    (progress.VolumeDisposition == VolumeDisposition.RetainedStateful && progress.StatefulOwner is null) ||
                    (progress.VolumeDisposition == VolumeDisposition.DetachedEphemeral && progress.StatefulOwner is not null))
                    return Held(ComputeErrorCode.StatefulVeto, operation);
                return One(new DetachVolumeIntent(binding, progress.VolumeDisposition, progress.StatefulOwner),
                    ComputeTraceCode.VolumeReady);
            case ScaleInState.StorageHandled:
                return One(new RevokeNodeIntent(binding, progress.VolumeProof!), ComputeTraceCode.RevocationReady);
            case ScaleInState.Revoked:
                return One(new TerminateNodeIntent(binding, progress.RevocationProof!, authorization, progress),
                    ComputeTraceCode.TerminationReady);
            case ScaleInState.Terminated:
                return One(new AuditOrphansIntent(binding, progress.TerminationProof!, progress.BootAbsenceProof!),
                    ComputeTraceCode.AuditReady);
            case ScaleInState.Audited:
                return Completed();
            case ScaleInState.Completed:
                return Completed();
            default:
                return Held(ComputeErrorCode.InvalidInput, operation);
        }
    }

    public static ComputeDecision DecideSurvival(SurvivalRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var operation = request.ReplacementTarget?.Operation;
        if (!ValidBundle(request.Required, request.MaximumIdentityLength) || request.Evidence is null ||
            !ValidBundle(request.Evidence.Observed, request.MaximumIdentityLength) ||
            !Valid(request.Evidence.BundleSignature?.Value, request.MaximumIdentityLength) ||
            !Valid(request.Evidence.EncryptionProof?.Value, request.MaximumIdentityLength) ||
            request.CurrentAcceptedGeneration <= 0 || request.EvaluationPosition <= 0 ||
            !ValidAuthority(request.Authority, request.MaximumIdentityLength))
            return Held(ComputeErrorCode.InvalidInput, operation);
        if (!EquivalentBundle(request.Required, request.Evidence.Observed))
            return Held(ComputeErrorCode.EvidenceMismatch, operation);
        if (request.Required.Generation < request.CurrentAcceptedGeneration)
            return Held(ComputeErrorCode.EvidenceStale, operation);
        if (request.Required.Generation > request.CurrentAcceptedGeneration)
            return Held(ComputeErrorCode.EvidenceMismatch, operation);
        var evidence = request.Evidence;
        if (!evidence.SignatureValid || !evidence.MetadataEncrypted || !evidence.ArtifactsLocal || !evidence.SecretsLocal ||
            !evidence.ProviderReady || !evidence.TrustReady || !evidence.NatsReady || !evidence.DnsReady || !evidence.BackupReady)
            return Held(ComputeErrorCode.BundleIncomplete, operation);
        if (request.Required.FreshThroughPosition < request.EvaluationPosition ||
            request.Required.ExpiresAfterPosition < request.EvaluationPosition)
            return Held(ComputeErrorCode.BundleExpired, operation);
        if (request.Authority.Cell != request.Required.Cell || request.Authority.AuthorityEpoch != request.Required.AuthorityEpoch ||
            request.Authority.JournalPosition != request.Required.JournalPosition || !request.Authority.QuorumAuthoritative)
            return Held(ComputeErrorCode.AuthorityDenied, operation);
        if (!request.DisconnectedReplacementRequested && request.ReplacementTarget is not null)
            return Held(ComputeErrorCode.EvidenceMismatch, operation);
        if (request.DisconnectedReplacementRequested)
        {
            if (request.ReplacementTarget is null)
                return Held(ComputeErrorCode.MissingProof, operation);
            if (!ValidReplacementTarget(request.ReplacementTarget, request.Required, request.MaximumIdentityLength))
                return Held(ComputeErrorCode.InvalidInput, operation);
            return One(new AuthorizeSurvivalIntent(request.Required, request.Authority, request.ReplacementTarget!),
                ComputeTraceCode.AuthorizationReady);
        }
        return One(new ReadySurvivalIntent(request.Required), ComputeTraceCode.ReadinessReady);
    }

    private static ComputeDecision DecideCreated(ScaleOutRequest request, ProviderResourceId resource)
    {
        if (!ValidProgress(request.Progress, request.Binding, request.MaximumIdentityLength) ||
            !ValidOutPrefix(ScaleOutState.InstanceCreated, request.Progress!) ||
            request.Progress!.Resource != resource || request.Progress.Node is null)
            return Held(ComputeErrorCode.MissingProof, request.Binding.Operation);
        return One(new EnrollNodeIntent(request.Binding, resource, request.Progress.Node, request.Progress.IdentityProof!),
            ComputeTraceCode.EnrollmentReady);
    }

    private static ComputeErrorCode ValidateAuthorization(CapacityAuthorization? value, ComputeBinding binding, int max)
    {
        if (value is null || value.Binding != binding || value.Resources is null || value.AuthorizedNodes <= 0 ||
            value.Resources.Ocpus == 0 || value.Resources.MemoryMib == 0 || value.Resources.StorageGib == 0 ||
            value.Resources.EstimatedHourlyCostMicros == 0 || !Valid(value.BudgetProof?.Value, max) ||
            !Valid(value.QuotaProof?.Value, max) || !Valid(value.CapacityProof?.Value, max) ||
            !Valid(value.CostProof?.Value, max) || !Valid(value.PlacementProof?.Value, max))
            return ComputeErrorCode.MissingProof;
        if (!value.BudgetAllowed) return ComputeErrorCode.BudgetDenied;
        if (!value.QuotaAllowed) return ComputeErrorCode.QuotaDenied;
        if (!value.CapacityAvailable) return ComputeErrorCode.CapacityDenied;
        if (!value.CostAllowed) return ComputeErrorCode.CostDenied;
        if (!value.PlacementAllowed) return ComputeErrorCode.PlacementDenied;
        return ComputeErrorCode.Unspecified;
    }

    private static bool ValidPlan(ScaleOutPlan value, ComputeBinding binding, int max) => value is not null &&
        value.Binding == binding && value.Resources is not null && value.DesiredNodes > 0 && value.Resources.Ocpus > 0 &&
        value.Resources.MemoryMib > 0 && value.Resources.StorageGib > 0 &&
        value.Resources.EstimatedHourlyCostMicros > 0 && Valid(value.PlanIdentity?.Value, max);
    private static bool ValidPersistedPlan(PersistedScaleOutPlan? value, ScaleOutPlan proposal, int max) =>
        value is not null && value.Plan == proposal && Valid(value.PersistenceProof?.Value, max);

    private static bool ValidBinding(ComputeBinding? value, int max) => value is not null && max > 0 &&
        Valid(value.Cell?.Value, max) && Valid(value.NodeClass?.Value, max) && Valid(value.Template?.Value, max) &&
        Valid(value.Shape?.Value, max) && Valid(value.Domain?.Value, max) && Valid(value.Artifact?.Value, max) &&
        Valid(value.ArtifactDigest?.Value, max) && Valid(value.Demand?.Value, max) && Valid(value.Operation?.Value, max) &&
        Valid(value.ProviderFingerprint?.Value, max) && value.Generation > 0 && value.ControllerEpoch > 0;
    private static bool ValidDemand(DemandEvidence value, ComputeBinding binding, int max) => value is not null &&
        value.Binding == binding && Defined(value.Trigger) && value.ObservationSequence > 0 && value.FreshThroughSequence > 0 &&
        value.FreshThroughSequence >= value.ObservationSequence && value.RequiredNodes > 0 && Valid(value.Binding.Demand?.Value, max);
    private static bool ValidCreate(ProviderCreateEvidence? value, ComputeBinding binding, int max) => value is not null &&
        value.Binding == binding && Defined(value.Status) && Valid(value.CreateKey?.Value, max) &&
        Valid(value.ObservationProof?.Value, max) &&
        (value.Resource is null || Valid(value.Resource.Value, max)) &&
        (value.WorkRequest is null || Valid(value.WorkRequest.Value, max)) &&
        value.Status switch
        {
            ProviderCreateStatus.ProvenAbsent => value.Resource is null && value.WorkRequest is null,
            ProviderCreateStatus.OutcomeUnknown => value.Resource is null,
            ProviderCreateStatus.Created => value.Resource is not null && value.WorkRequest is not null,
            _ => false,
        };
    private static bool ValidProgress(ScaleOutProgress? value, ComputeBinding binding, int max) => value is not null &&
        value.Binding == binding && (value.Resource is null || Valid(value.Resource.Value, max)) &&
        (value.Node is null || Valid(value.Node.Value, max)) && ValidOptional(value.IdentityProof, max) &&
        ValidOptional(value.EnrollmentProof, max) && ValidOptional(value.BootstrapProof, max) &&
        ValidOptional(value.DiskProof, max) && ValidOptional(value.PlacementProof, max) && ValidOptional(value.HealthProof, max);
    private static bool ValidScaleInBinding(ScaleInBinding? value, int max) => value is not null &&
        ValidBinding(value.Compute, max) && Valid(value.Node?.Value, max) && Valid(value.Resource?.Value, max) &&
        Valid(value.LoadBalancerRegistration?.Value, max) && Valid(value.Volume?.Value, max) && Defined(value.Role);
    private static bool ValidScaleInAuthorization(ScaleInAuthorization value, ScaleInBinding binding, int max) => value is not null &&
        value.Binding == binding && Valid(value.LowUseObservation?.Value, max) && value.ObservationSequence > 0 &&
        value.FreshThroughSequence > 0 && value.CurrentCount > 0 && value.MinimumCount >= 0 &&
        value.ReplacementCapacity >= 0 && value.AvailabilityHeadroom >= 0 &&
        Valid(value.LowUseProof?.Value, max) && Valid(value.CooldownProof?.Value, max) &&
        Valid(value.LifetimeProof?.Value, max) && Valid(value.CostBenefitProof?.Value, max) &&
        Valid(value.ControlHealthProof?.Value, max) && Valid(value.NatsHealthProof?.Value, max) &&
        Valid(value.AvailabilityProof?.Value, max) && Defined(value.StatefulDisposition) &&
        Valid(value.StatefulProof?.Value, max);
    private static bool ValidScaleInProgress(ScaleInProgress value, ScaleInBinding binding, int max) => value is not null &&
        value.Binding == binding && ValidOptional(value.CordonProof, max) && ValidOptional(value.DrainProof, max) &&
        ValidOptional(value.DeregistrationProof, max) && ValidOptional(value.VolumeProof, max) &&
        ValidOptional(value.RevocationProof, max) && ValidOptional(value.TerminationProof, max) &&
        ValidOptional(value.BootAbsenceProof, max) && ValidOptional(value.OrphanAuditProof, max) &&
        Defined(value.VolumeDisposition) && (value.StatefulOwner is null || Valid(value.StatefulOwner.Value, max)) &&
        (value.VolumeDisposition == VolumeDisposition.RetainedStateful ? value.StatefulOwner is not null : value.StatefulOwner is null);
    private static bool ValidBundle(RegionalSurvivalBundle value, int max) => value is not null && max > 0 &&
        Valid(value.Bundle?.Value, max) && Valid(value.Cell?.Value, max) && value.Generation > 0 &&
        Valid(value.ProviderFingerprint?.Value, max) && Valid(value.AcceptedArtifact?.Value, max) &&
        Valid(value.AcceptedDigest?.Value, max) && Valid(value.AcceptedSignature?.Value, max) &&
        Valid(value.RollbackArtifact?.Value, max) && Valid(value.RollbackDigest?.Value, max) &&
        Valid(value.RollbackSignature?.Value, max) && value.AcceptedArtifact != value.RollbackArtifact &&
        value.AcceptedDigest != value.RollbackDigest && value.EncryptedSecretVersions.Count > 0 && value.Templates.Count > 0 &&
        value.EncryptedSecretVersions.All(item => Valid(item?.Value, max)) &&
        value.Templates.All(item => item is not null && Valid(item.NodeClass?.Value, max) &&
            Valid(item.Template?.Value, max) && Valid(item.Shape?.Value, max) && Valid(item.Domain?.Value, max)) &&
        value.EncryptedSecretVersions.Distinct().Count() == value.EncryptedSecretVersions.Count &&
        value.Templates.Select(static item => item.Template).Distinct().Count() == value.Templates.Count && Valid(value.Trust?.Value, max) &&
        Valid(value.Nats?.Value, max) && Valid(value.Dns?.Value, max) && Valid(value.Backup?.Value, max) &&
        value.AuthorityEpoch > 0 && value.JournalPosition > 0 && value.SnapshotPosition > 0 &&
        value.FreshThroughPosition > 0 && value.ExpiresAfterPosition > 0 &&
        value.SnapshotPosition <= value.JournalPosition && value.JournalPosition <= value.FreshThroughPosition &&
        value.FreshThroughPosition <= value.ExpiresAfterPosition;
    private static bool ValidAuthority(RegionalAuthorityProof value, int max) => value is not null &&
        Valid(value.Cell?.Value, max) && value.AuthorityEpoch > 0 && value.JournalPosition > 0 && Valid(value.Proof?.Value, max);
    private static bool ValidReplacementTarget(SurvivalReplacementTarget? value, RegionalSurvivalBundle bundle, int max) =>
        value is not null && Valid(value.Cell?.Value, max) && Valid(value.NodeClass?.Value, max) &&
        Valid(value.Template?.Value, max) && Valid(value.Shape?.Value, max) && Valid(value.Domain?.Value, max) &&
        Valid(value.Artifact?.Value, max) && Valid(value.ArtifactDigest?.Value, max) && Valid(value.Operation?.Value, max) &&
        Valid(value.ProviderFingerprint?.Value, max) && Valid(value.CreateKey?.Value, max) && value.BundleGeneration > 0 &&
        value.ControllerEpoch > 0 && value.Cell == bundle.Cell && value.ProviderFingerprint == bundle.ProviderFingerprint &&
        value.BundleGeneration == bundle.Generation && value.ControllerEpoch == bundle.AuthorityEpoch &&
        value.Artifact == bundle.AcceptedArtifact && value.ArtifactDigest == bundle.AcceptedDigest &&
        bundle.Templates.Any(template => template.NodeClass == value.NodeClass && template.Template == value.Template &&
            template.Shape == value.Shape && template.Domain == value.Domain);
    private static bool ValidOutPrefix(ScaleOutState state, ScaleOutProgress value) => state switch
    {
        ScaleOutState.InstanceCreated => value.IdentityAttested && value.IdentityProof is not null &&
            !value.Enrolled && value.EnrollmentProof is null && !value.BootstrapPassed && value.BootstrapProof is null &&
            !value.DiskPassed && value.DiskProof is null && !value.PlacementComplete && value.PlacementProof is null &&
            !value.ServiceHealthy && value.HealthProof is null,
        ScaleOutState.Enrolled => value.IdentityAttested && value.Enrolled && value.BootstrapPassed &&
            value.DiskPassed && value.IdentityProof is not null && value.EnrollmentProof is not null &&
            value.BootstrapProof is not null && value.DiskProof is not null && !value.PlacementComplete &&
            value.PlacementProof is null && !value.ServiceHealthy && value.HealthProof is null,
        ScaleOutState.Ready or ScaleOutState.Completed => value.IdentityAttested && value.Enrolled &&
            value.BootstrapPassed && value.DiskPassed && value.PlacementComplete && value.ServiceHealthy &&
            value.IdentityProof is not null && value.EnrollmentProof is not null && value.BootstrapProof is not null &&
            value.DiskProof is not null && value.PlacementProof is not null && value.HealthProof is not null,
        _ => false,
    };
    private static bool ValidScaleInPrefix(ScaleInState state, ScaleInProgress value) => state switch
    {
        ScaleInState.CandidateSelected => !value.Cordoned && value.CordonProof is null && !value.Drained &&
            value.DrainProof is null && !value.Deregistered && value.DeregistrationProof is null &&
            !value.VolumeHandled && value.VolumeProof is null && !value.Revoked && value.RevocationProof is null &&
            !value.ExactInstanceTerminated && value.TerminationProof is null && !value.BootVolumeAbsent &&
            value.BootAbsenceProof is null && !value.OrphanAuditPassed && value.OrphanAuditProof is null,
        ScaleInState.Cordoned => value.Cordoned && !value.Drained && !value.Deregistered && !value.VolumeHandled &&
            !value.Revoked && !value.ExactInstanceTerminated && !value.BootVolumeAbsent && !value.OrphanAuditPassed &&
            value.CordonProof is not null && value.DrainProof is null && value.DeregistrationProof is null &&
            value.VolumeProof is null && value.RevocationProof is null && value.TerminationProof is null &&
            value.BootAbsenceProof is null && value.OrphanAuditProof is null,
        ScaleInState.Drained => value.Cordoned && value.Drained && !value.Deregistered && !value.VolumeHandled &&
            !value.Revoked && !value.ExactInstanceTerminated && !value.BootVolumeAbsent && !value.OrphanAuditPassed &&
            value.CordonProof is not null && value.DrainProof is not null && value.DeregistrationProof is null &&
            value.VolumeProof is null && value.RevocationProof is null && value.TerminationProof is null &&
            value.BootAbsenceProof is null && value.OrphanAuditProof is null,
        ScaleInState.Deregistered => value.Cordoned && value.Drained && value.Deregistered && !value.VolumeHandled &&
            !value.Revoked && !value.ExactInstanceTerminated && !value.BootVolumeAbsent && !value.OrphanAuditPassed &&
            value.CordonProof is not null && value.DrainProof is not null && value.DeregistrationProof is not null &&
            value.VolumeProof is null && value.RevocationProof is null && value.TerminationProof is null &&
            value.BootAbsenceProof is null && value.OrphanAuditProof is null,
        ScaleInState.StorageHandled => value.Cordoned && value.Drained && value.Deregistered && value.VolumeHandled &&
            !value.Revoked && !value.ExactInstanceTerminated && !value.BootVolumeAbsent && !value.OrphanAuditPassed &&
            value.CordonProof is not null && value.DrainProof is not null && value.DeregistrationProof is not null &&
            value.VolumeProof is not null && value.RevocationProof is null && value.TerminationProof is null &&
            value.BootAbsenceProof is null && value.OrphanAuditProof is null,
        ScaleInState.Revoked => value.Cordoned && value.Drained && value.Deregistered && value.VolumeHandled &&
            value.Revoked && !value.ExactInstanceTerminated && !value.BootVolumeAbsent && !value.OrphanAuditPassed &&
            value.CordonProof is not null && value.DrainProof is not null && value.DeregistrationProof is not null &&
            value.VolumeProof is not null && value.RevocationProof is not null && value.TerminationProof is null &&
            value.BootAbsenceProof is null && value.OrphanAuditProof is null,
        ScaleInState.Terminated => value.Cordoned && value.Drained && value.Deregistered && value.VolumeHandled &&
            value.Revoked && value.ExactInstanceTerminated && value.BootVolumeAbsent && !value.OrphanAuditPassed &&
            value.CordonProof is not null && value.DrainProof is not null && value.DeregistrationProof is not null &&
            value.VolumeProof is not null && value.RevocationProof is not null && value.TerminationProof is not null &&
            value.BootAbsenceProof is not null && value.OrphanAuditProof is null,
        ScaleInState.Audited or ScaleInState.Completed => value.Cordoned && value.Drained && value.Deregistered &&
            value.VolumeHandled && value.Revoked && value.ExactInstanceTerminated && value.BootVolumeAbsent &&
            value.OrphanAuditPassed && value.CordonProof is not null && value.DrainProof is not null &&
            value.DeregistrationProof is not null && value.VolumeProof is not null && value.RevocationProof is not null &&
            value.TerminationProof is not null && value.BootAbsenceProof is not null && value.OrphanAuditProof is not null,
        _ => false,
    };
    private static bool EquivalentBundle(RegionalSurvivalBundle left, RegionalSurvivalBundle right) =>
        left.Bundle == right.Bundle && left.Cell == right.Cell && left.Generation == right.Generation &&
        left.ProviderFingerprint == right.ProviderFingerprint && left.AcceptedArtifact == right.AcceptedArtifact &&
        left.AcceptedDigest == right.AcceptedDigest && left.AcceptedSignature == right.AcceptedSignature &&
        left.RollbackArtifact == right.RollbackArtifact && left.RollbackDigest == right.RollbackDigest &&
        left.RollbackSignature == right.RollbackSignature && left.Trust == right.Trust && left.Nats == right.Nats &&
        left.Dns == right.Dns && left.Backup == right.Backup && left.AuthorityEpoch == right.AuthorityEpoch &&
        left.JournalPosition == right.JournalPosition && left.SnapshotPosition == right.SnapshotPosition &&
        left.FreshThroughPosition == right.FreshThroughPosition && left.ExpiresAfterPosition == right.ExpiresAfterPosition &&
        left.EncryptedSecretVersions.OrderBy(static item => item.Value, Ordinal).SequenceEqual(
            right.EncryptedSecretVersions.OrderBy(static item => item.Value, Ordinal)) &&
        left.Templates.OrderBy(static item => item.Template.Value, Ordinal).SequenceEqual(
            right.Templates.OrderBy(static item => item.Template.Value, Ordinal));

    private static bool Valid(string? value, int max)
    {
        if (string.IsNullOrEmpty(value) || value.Length > max) return false;
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (char.IsWhiteSpace(character) || char.IsControl(character)) return false;
            if (!char.IsSurrogate(character)) continue;
            if (!char.IsHighSurrogate(character) || index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1])) return false;
            index++;
        }
        return true;
    }
    private static bool ValidOptional(ComputeProofId? value, int max) => value is null || Valid(value.Value, max);
    private static bool Defined<T>(T value) where T : struct, Enum => Enum.IsDefined(value) && Convert.ToInt64(value, CultureInfo.InvariantCulture) != 0;
    private static ComputeDecision One(ComputeIntent intent, ComputeTraceCode code) => Decision([intent], [], [new(1, code, intent.Action)]);
    private static ComputeDecision Completed() => Decision([], [], [new(1, ComputeTraceCode.Completed, ComputeAction.Ready)]);
    private static ComputeDecision Held(ComputeErrorCode code, ComputeOperationId? operation)
    {
        var error = new ComputeError(code, Requirement, operation);
        var hold = new HoldComputeIntent(code, operation);
        return Decision([hold], [error], [new(1, ComputeTraceCode.Held, hold.Action)]);
    }
    private static ComputeDecision Decision(IEnumerable<ComputeIntent> intents, IEnumerable<ComputeError> errors,
        IEnumerable<ComputeTrace> trace, ScaleOutRequest? acceptedScaleOutRequest = null) => new(
        new ReadOnlyCollection<ComputeIntent>(intents.ToArray()),
        new ReadOnlyCollection<ComputeError>(errors.ToArray()), new ReadOnlyCollection<ComputeTrace>(trace.ToArray()),
        acceptedScaleOutRequest);
}
