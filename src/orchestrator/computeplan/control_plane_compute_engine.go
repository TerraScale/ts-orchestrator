package computeplan

import "sort"

var ComputeEngine computeEngine

type computeEngine struct{}

const computeEngineRequirement = ComputeRequirementCodeReqO011

func (computeEngine) DecideScaleOut(request *ScaleOutRequest) (*ComputeDecision, error) {
	if request == nil {
		return nil, argumentNil("request")
	}
	decision := computeDecideScaleOutCore(request)
	if len(decision.Errors) == 0 {
		return computeDecision(decision.Intents, decision.Errors, decision.Trace, request), nil
	}
	return decision, nil
}

func computeDecideScaleOutCore(request *ScaleOutRequest) *ComputeDecision {
	operation := request.Binding.Operation
	if !computeValidBinding(request.Binding, request.MaximumIdentityLength) ||
		!computeDefined(computeScaleOutDefined(request.State)) || request.EvaluationSequence <= 0 ||
		!computeValidDemand(request.Demand, request.Binding, request.MaximumIdentityLength) ||
		!computeValidPlan(request.Plan, request.Binding, request.MaximumIdentityLength) {
		return computeHeld(ComputeErrorCodeInvalidInput, operation)
	}
	if request.Demand.ObservationSequence > request.EvaluationSequence {
		return computeHeld(ComputeErrorCodeEvidenceStale, operation)
	}
	demandFresh := request.Demand.FreshThroughSequence >= request.EvaluationSequence
	boundedSafety := request.Demand.ExplicitDemand && request.Demand.SafetyBounded &&
		(request.Demand.Trigger == ComputeTriggerFailedHostReplacement ||
			request.Demand.Trigger == ComputeTriggerSafetyRecovery)
	if !demandFresh && !boundedSafety {
		return computeHeld(ComputeErrorCodeEvidenceStale, operation)
	}
	if !request.Demand.ExplicitDemand || (!request.Demand.Sustained && !boundedSafety) {
		return computeHeld(ComputeErrorCodeMissingProof, operation)
	}
	if request.Plan.DesiredNodes != request.Demand.RequiredNodes {
		return computeHeld(ComputeErrorCodeEvidenceMismatch, operation)
	}
	if request.State == ScaleOutStateDemandObserved {
		if request.PersistedPlan != nil || request.Authorization != nil ||
			request.CreateEvidence != nil || request.Progress != nil {
			return computeHeld(ComputeErrorCodeEvidenceMismatch, operation)
		}
	} else if !computeValidPersistedPlan(request.PersistedPlan, request.Plan, request.MaximumIdentityLength) {
		return computeHeld(ComputeErrorCodeMissingProof, operation)
	}
	if request.State == ScaleOutStatePlanPersisted &&
		(request.Authorization != nil || request.CreateEvidence != nil || request.Progress != nil) {
		return computeHeld(ComputeErrorCodeEvidenceMismatch, operation)
	}
	if request.State >= ScaleOutStateAuthorized {
		if request.Authorization == nil {
			return computeHeld(ComputeErrorCodeMissingProof, operation)
		}
		authorizationError := computeValidateAuthorization(*request.Authorization, request.Binding,
			request.MaximumIdentityLength)
		if authorizationError != ComputeErrorCodeUnspecified {
			return computeHeld(authorizationError, operation)
		}
		if request.Authorization.AuthorizedNodes != request.Plan.DesiredNodes ||
			request.Authorization.Resources != request.Plan.Resources {
			return computeHeld(ComputeErrorCodeEvidenceMismatch, operation)
		}
	}
	if request.State == ScaleOutStateAuthorized && request.Progress != nil {
		return computeHeld(ComputeErrorCodeEvidenceMismatch, operation)
	}
	if request.State == ScaleOutStateRequestRecorded &&
		request.CreateEvidence != nil && request.CreateEvidence.Status == ProviderCreateStatusOutcomeUnknown &&
		request.Progress != nil {
		return computeHeld(ComputeErrorCodeEvidenceMismatch, operation)
	}
	if request.State >= ScaleOutStateInstanceCreated {
		if request.CreateEvidence == nil ||
			!computeValidCreate(*request.CreateEvidence, request.Binding, request.MaximumIdentityLength) ||
			request.CreateEvidence.Status != ProviderCreateStatusCreated ||
			request.CreateEvidence.Resource == nil ||
			request.Progress == nil ||
			!computeValidProgress(*request.Progress, request.Binding, request.MaximumIdentityLength) ||
			request.Progress.Resource == nil || *request.Progress.Resource != *request.CreateEvidence.Resource ||
			request.Progress.Node == nil {
			return computeHeld(ComputeErrorCodeMissingProof, operation)
		}
	}

	switch request.State {
	case ScaleOutStateDemandObserved:
		return computeOne(NewPersistScalePlanIntent(request.Binding, request.Plan.Resources,
			request.Plan.DesiredNodes, request.Plan.PlanIdentity), ComputeTraceCodePlanRequired)
	case ScaleOutStatePlanPersisted:
		if request.PersistedPlan == nil {
			return computeHeld(ComputeErrorCodeMissingProof, operation)
		}
		return computeOne(NewAuthorizeCapacityIntent(request.Binding, *request.PersistedPlan),
			ComputeTraceCodeAuthorizationReady)
	case ScaleOutStateAuthorized:
		if request.CreateEvidence == nil ||
			!computeValidCreate(*request.CreateEvidence, request.Binding, request.MaximumIdentityLength) ||
			request.CreateEvidence.Status != ProviderCreateStatusProvenAbsent ||
			request.PersistedPlan == nil || request.Authorization == nil {
			return computeHeld(ComputeErrorCodeMissingProof, operation)
		}
		return computeOne(NewRequestCreateIntent(request.Binding, request.CreateEvidence.CreateKey,
			*request.PersistedPlan, *request.Authorization, *request.CreateEvidence), ComputeTraceCodeCreateReady)
	case ScaleOutStateRequestRecorded:
		if request.CreateEvidence == nil ||
			!computeValidCreate(*request.CreateEvidence, request.Binding, request.MaximumIdentityLength) {
			return computeHeld(ComputeErrorCodeMissingProof, operation)
		}
		if request.CreateEvidence.Status == ProviderCreateStatusOutcomeUnknown {
			return computeOne(NewObserveCreateIntent(request.Binding, request.CreateEvidence.CreateKey),
				ComputeTraceCodeObservationRequired)
		}
		if request.CreateEvidence.Status != ProviderCreateStatusCreated || request.CreateEvidence.Resource == nil {
			return computeHeld(ComputeErrorCodeMissingProof, operation)
		}
		return computeDecideCreated(request, request.CreateEvidence.Resource)
	case ScaleOutStateInstanceCreated:
		if request.CreateEvidence == nil || request.CreateEvidence.Resource == nil {
			return computeHeld(ComputeErrorCodeMissingProof, operation)
		}
		return computeDecideCreated(request, request.CreateEvidence.Resource)
	case ScaleOutStateEnrolled:
		if request.Progress == nil ||
			!computeValidProgress(*request.Progress, request.Binding, request.MaximumIdentityLength) ||
			!computeValidOutPrefix(ScaleOutStateEnrolled, *request.Progress) ||
			request.Progress.Resource == nil || request.Progress.Node == nil ||
			request.Progress.BootstrapProof == nil || request.Progress.DiskProof == nil ||
			request.Authorization == nil || request.Authorization.PlacementProof.Value == "" {
			return computeHeld(ComputeErrorCodeMissingProof, operation)
		}
		return computeOne(NewReadyNodeIntent(request.Binding, *request.Progress.Resource, *request.Progress.Node,
			*request.Progress.BootstrapProof, *request.Progress.DiskProof, request.Authorization.PlacementProof),
			ComputeTraceCodeReadinessReady)
	case ScaleOutStateReady:
		if request.Progress == nil ||
			!computeValidProgress(*request.Progress, request.Binding, request.MaximumIdentityLength) ||
			!computeValidOutPrefix(ScaleOutStateReady, *request.Progress) {
			return computeHeld(ComputeErrorCodePlacementDenied, operation)
		}
		return computeCompleted()
	case ScaleOutStateCompleted:
		if request.Progress == nil ||
			!computeValidProgress(*request.Progress, request.Binding, request.MaximumIdentityLength) ||
			!computeValidOutPrefix(ScaleOutStateCompleted, *request.Progress) {
			return computeHeld(ComputeErrorCodeMissingProof, operation)
		}
		return computeCompleted()
	default:
		return computeHeld(ComputeErrorCodeInvalidInput, operation)
	}
}

func (computeEngine) DecideScaleIn(request *ScaleInRequest) (*ComputeDecision, error) {
	if request == nil {
		return nil, argumentNil("request")
	}
	operation := request.Binding.Compute.Operation
	if !computeValidScaleInBinding(request.Binding, request.MaximumIdentityLength) ||
		!computeDefined(computeScaleInDefined(request.State)) || request.EvaluationSequence <= 0 ||
		!computeValidScaleInAuthorization(request.Authorization, request.Binding, request.MaximumIdentityLength) ||
		!computeValidScaleInProgress(request.Progress, request.Binding, request.MaximumIdentityLength) {
		return computeHeld(ComputeErrorCodeInvalidInput, operation), nil
	}
	authorization, progress := request.Authorization, request.Progress
	if authorization.ObservationSequence > request.EvaluationSequence ||
		authorization.FreshThroughSequence < request.EvaluationSequence {
		return computeHeld(ComputeErrorCodeEvidenceStale, operation), nil
	}
	if authorization.ConflictingOperation {
		return computeHeld(ComputeErrorCodeConflictingOperation, operation), nil
	}
	if !authorization.SustainedLowUse || !authorization.CooldownPassed || !authorization.LifetimePassed {
		return computeHeld(ComputeErrorCodeMissingProof, operation), nil
	}
	if !authorization.CostBenefitPassed {
		return computeHeld(ComputeErrorCodeCostDenied, operation), nil
	}
	if authorization.ReplacementCapacity <= 0 || authorization.AvailabilityHeadroom <= 0 ||
		!authorization.RegionalControlHealthy || !authorization.NatsHealthy {
		return computeHeld(ComputeErrorCodeAvailabilityDenied, operation), nil
	}
	critical := request.Binding.Role == ComputeNodeRoleSeedController ||
		request.Binding.Role == ComputeNodeRoleControlNats ||
		request.Binding.Role == ComputeNodeRoleProductNats ||
		request.Binding.Role == ComputeNodeRoleTerraBase
	if authorization.CurrentCount <= authorization.MinimumCount || authorization.CurrentCount <= 1 ||
		(critical && (authorization.MinimumCount < 3 || authorization.CurrentCount-1 < 3)) {
		return computeHeld(ComputeErrorCodeFloorDenied, operation), nil
	}
	stateful := request.Binding.Role == ComputeNodeRoleElasticStateful ||
		request.Binding.Role == ComputeNodeRoleControlNats ||
		request.Binding.Role == ComputeNodeRoleProductNats ||
		request.Binding.Role == ComputeNodeRoleTerraBase
	if authorization.StatefulDisposition == StatefulDispositionVetoed ||
		(stateful && (authorization.StatefulDisposition != StatefulDispositionApproved ||
			!authorization.StatefulApproved)) {
		return computeHeld(ComputeErrorCodeStatefulVeto, operation), nil
	}

	if (stateful && (progress.VolumeDisposition != VolumeDispositionRetainedStateful || progress.StatefulOwner == nil)) ||
		(!stateful && (progress.VolumeDisposition != VolumeDispositionDetachedEphemeral || progress.StatefulOwner != nil)) {
		return computeHeld(ComputeErrorCodeStatefulVeto, operation), nil
	}
	if request.State == ScaleInStateTerminated && (!progress.ExactInstanceTerminated || !progress.BootVolumeAbsent) {
		return computeHeld(ComputeErrorCodeUnsafeTermination, operation), nil
	}
	if request.State == ScaleInStateAudited && !progress.OrphanAuditPassed {
		return computeHeld(ComputeErrorCodeOrphanDenied, operation), nil
	}
	if !computeValidScaleInPrefix(request.State, progress) {
		return computeHeld(ComputeErrorCodeMissingProof, operation), nil
	}
	switch request.State {
	case ScaleInStateCandidateSelected:
		return computeOne(NewCordonNodeIntent(request.Binding), ComputeTraceCodeCordonReady), nil
	case ScaleInStateCordoned:
		if progress.CordonProof == nil {
			return computeHeld(ComputeErrorCodeMissingProof, operation), nil
		}
		return computeOne(NewDrainNodeIntent(request.Binding, *progress.CordonProof), ComputeTraceCodeDrainReady), nil
	case ScaleInStateDrained:
		return computeOne(NewDeregisterNodeIntent(request.Binding, authorization.StatefulProof),
			ComputeTraceCodeDeregistrationReady), nil
	case ScaleInStateDeregistered:
		if !computeDefined(computeVolumeDispositionDefined(progress.VolumeDisposition)) ||
			(progress.VolumeDisposition == VolumeDispositionRetainedStateful && progress.StatefulOwner == nil) ||
			(progress.VolumeDisposition == VolumeDispositionDetachedEphemeral && progress.StatefulOwner != nil) {
			return computeHeld(ComputeErrorCodeStatefulVeto, operation), nil
		}
		return computeOne(NewDetachVolumeIntent(request.Binding, progress.VolumeDisposition, progress.StatefulOwner),
			ComputeTraceCodeVolumeReady), nil
	case ScaleInStateStorageHandled:
		if progress.VolumeProof == nil {
			return computeHeld(ComputeErrorCodeMissingProof, operation), nil
		}
		return computeOne(NewRevokeNodeIntent(request.Binding, *progress.VolumeProof), ComputeTraceCodeRevocationReady), nil
	case ScaleInStateRevoked:
		if progress.RevocationProof == nil {
			return computeHeld(ComputeErrorCodeMissingProof, operation), nil
		}
		return computeOne(NewTerminateNodeIntent(request.Binding, *progress.RevocationProof, authorization,
			progress), ComputeTraceCodeTerminationReady), nil
	case ScaleInStateTerminated:
		if progress.TerminationProof == nil || progress.BootAbsenceProof == nil {
			return computeHeld(ComputeErrorCodeMissingProof, operation), nil
		}
		return computeOne(NewAuditOrphansIntent(request.Binding, *progress.TerminationProof,
			*progress.BootAbsenceProof), ComputeTraceCodeAuditReady), nil
	case ScaleInStateAudited, ScaleInStateCompleted:
		return computeCompleted(), nil
	default:
		return computeHeld(ComputeErrorCodeInvalidInput, operation), nil
	}
}

func (computeEngine) DecideSurvival(request *SurvivalRequest) (*ComputeDecision, error) {
	if request == nil {
		return nil, argumentNil("request")
	}
	operation := ComputeOperationId{}
	if request.ReplacementTarget != nil {
		operation = request.ReplacementTarget.Operation
	}
	if !computeValidBundle(request.Required, request.MaximumIdentityLength) ||
		request.Evidence.Observed == nil ||
		!computeValidBundle(request.Evidence.Observed, request.MaximumIdentityLength) ||
		!computeValid(request.Evidence.BundleSignature.Value, request.MaximumIdentityLength) ||
		!computeValid(request.Evidence.EncryptionProof.Value, request.MaximumIdentityLength) ||
		request.CurrentAcceptedGeneration <= 0 || request.EvaluationPosition <= 0 ||
		!computeValidAuthority(request.Authority, request.MaximumIdentityLength) {
		return computeHeld(ComputeErrorCodeInvalidInput, operation), nil
	}
	if !computeEquivalentBundle(request.Required, request.Evidence.Observed) {
		return computeHeld(ComputeErrorCodeEvidenceMismatch, operation), nil
	}
	if request.Required.Generation < request.CurrentAcceptedGeneration {
		return computeHeld(ComputeErrorCodeEvidenceStale, operation), nil
	}
	if request.Required.Generation > request.CurrentAcceptedGeneration {
		return computeHeld(ComputeErrorCodeEvidenceMismatch, operation), nil
	}
	evidence := request.Evidence
	if !evidence.SignatureValid || !evidence.MetadataEncrypted || !evidence.ArtifactsLocal ||
		!evidence.SecretsLocal || !evidence.ProviderReady || !evidence.TrustReady ||
		!evidence.NatsReady || !evidence.DnsReady || !evidence.BackupReady {
		return computeHeld(ComputeErrorCodeBundleIncomplete, operation), nil
	}
	if request.Required.FreshThroughPosition < request.EvaluationPosition ||
		request.Required.ExpiresAfterPosition < request.EvaluationPosition {
		return computeHeld(ComputeErrorCodeBundleExpired, operation), nil
	}
	if request.Authority.Cell != request.Required.Cell ||
		request.Authority.AuthorityEpoch != request.Required.AuthorityEpoch ||
		request.Authority.JournalPosition != request.Required.JournalPosition ||
		!request.Authority.QuorumAuthoritative {
		return computeHeld(ComputeErrorCodeAuthorityDenied, operation), nil
	}
	if !request.DisconnectedReplacementRequested && request.ReplacementTarget != nil {
		return computeHeld(ComputeErrorCodeEvidenceMismatch, operation), nil
	}
	if request.DisconnectedReplacementRequested {
		if request.ReplacementTarget == nil {
			return computeHeld(ComputeErrorCodeMissingProof, operation), nil
		}
		if !computeValidReplacementTarget(request.ReplacementTarget, request.Required, request.MaximumIdentityLength) {
			return computeHeld(ComputeErrorCodeInvalidInput, operation), nil
		}
		return computeOne(NewAuthorizeSurvivalIntent(request.Required, request.Authority,
			*request.ReplacementTarget), ComputeTraceCodeAuthorizationReady), nil
	}
	return computeOne(NewReadySurvivalIntent(request.Required), ComputeTraceCodeReadinessReady), nil
}

func computeDecideCreated(request *ScaleOutRequest, resource *ProviderResourceId) *ComputeDecision {
	if request.Progress == nil ||
		!computeValidProgress(*request.Progress, request.Binding, request.MaximumIdentityLength) ||
		!computeValidOutPrefix(ScaleOutStateInstanceCreated, *request.Progress) ||
		request.Progress.Resource == nil || *request.Progress.Resource != *resource ||
		request.Progress.Node == nil || request.Progress.IdentityProof == nil {
		return computeHeld(ComputeErrorCodeMissingProof, request.Binding.Operation)
	}
	return computeOne(NewEnrollNodeIntent(request.Binding, *resource, *request.Progress.Node,
		*request.Progress.IdentityProof), ComputeTraceCodeEnrollmentReady)
}

func computeValidateAuthorization(value CapacityAuthorization, binding ComputeBinding, max int) ComputeErrorCode {
	if value.Binding != binding || value.AuthorizedNodes <= 0 ||
		value.Resources.Ocpus == 0 || value.Resources.MemoryMib == 0 || value.Resources.StorageGib == 0 ||
		value.Resources.EstimatedHourlyCostMicros == 0 || !computeValid(value.BudgetProof.Value, max) ||
		!computeValid(value.QuotaProof.Value, max) || !computeValid(value.CapacityProof.Value, max) ||
		!computeValid(value.CostProof.Value, max) || !computeValid(value.PlacementProof.Value, max) {
		return ComputeErrorCodeMissingProof
	}
	if !value.BudgetAllowed {
		return ComputeErrorCodeBudgetDenied
	}
	if !value.QuotaAllowed {
		return ComputeErrorCodeQuotaDenied
	}
	if !value.CapacityAvailable {
		return ComputeErrorCodeCapacityDenied
	}
	if !value.CostAllowed {
		return ComputeErrorCodeCostDenied
	}
	if !value.PlacementAllowed {
		return ComputeErrorCodePlacementDenied
	}
	return ComputeErrorCodeUnspecified
}

func computeValidPlan(value ScaleOutPlan, binding ComputeBinding, max int) bool {
	return value.Binding == binding && value.DesiredNodes > 0 && value.Resources.Ocpus > 0 &&
		value.Resources.MemoryMib > 0 && value.Resources.StorageGib > 0 &&
		value.Resources.EstimatedHourlyCostMicros > 0 && computeValid(value.PlanIdentity.Value, max)
}

func computeValidPersistedPlan(value *PersistedScaleOutPlan, proposal ScaleOutPlan, max int) bool {
	return value != nil && value.Plan == proposal && computeValid(value.PersistenceProof.Value, max)
}

func computeValidBinding(value ComputeBinding, max int) bool {
	return max > 0 && computeValid(value.Cell.Value, max) && computeValid(value.NodeClass.Value, max) &&
		computeValid(value.Template.Value, max) && computeValid(value.Shape.Value, max) &&
		computeValid(value.Domain.Value, max) && computeValid(value.Artifact.Value, max) &&
		computeValid(value.ArtifactDigest.Value, max) && computeValid(value.Demand.Value, max) &&
		computeValid(value.Operation.Value, max) && computeValid(value.ProviderFingerprint.Value, max) &&
		value.Generation > 0 && value.ControllerEpoch > 0
}

func computeValidDemand(value DemandEvidence, binding ComputeBinding, max int) bool {
	return value.Binding == binding && computeDefined(computeTriggerDefined(value.Trigger)) &&
		value.ObservationSequence > 0 && value.FreshThroughSequence > 0 &&
		value.FreshThroughSequence >= value.ObservationSequence && value.RequiredNodes > 0 &&
		computeValid(value.Binding.Demand.Value, max)
}

func computeValidCreate(value ProviderCreateEvidence, binding ComputeBinding, max int) bool {
	if value.Binding != binding || !computeDefined(computeProviderCreateStatusDefined(value.Status)) ||
		!computeValid(value.CreateKey.Value, max) || !computeValid(value.ObservationProof.Value, max) {
		return false
	}
	if value.Resource != nil && !computeValid(value.Resource.Value, max) {
		return false
	}
	if value.WorkRequest != nil && !computeValid(value.WorkRequest.Value, max) {
		return false
	}
	switch value.Status {
	case ProviderCreateStatusProvenAbsent:
		return value.Resource == nil && value.WorkRequest == nil
	case ProviderCreateStatusOutcomeUnknown:
		return value.Resource == nil
	case ProviderCreateStatusCreated:
		return value.Resource != nil && value.WorkRequest != nil
	default:
		return false
	}
}

func computeValidProgress(value ScaleOutProgress, binding ComputeBinding, max int) bool {
	return value.Binding == binding && (value.Resource == nil || computeValid(value.Resource.Value, max)) &&
		(value.Node == nil || computeValid(value.Node.Value, max)) &&
		computeValidOptional(value.IdentityProof, max) && computeValidOptional(value.EnrollmentProof, max) &&
		computeValidOptional(value.BootstrapProof, max) && computeValidOptional(value.DiskProof, max) &&
		computeValidOptional(value.PlacementProof, max) && computeValidOptional(value.HealthProof, max)
}

func computeValidScaleInBinding(value ScaleInBinding, max int) bool {
	return computeValidBinding(value.Compute, max) && computeValid(value.Node.Value, max) &&
		computeValid(value.Resource.Value, max) && computeValid(value.LoadBalancerRegistration.Value, max) &&
		computeValid(value.Volume.Value, max) && computeDefined(computeNodeRoleDefined(value.Role))
}

func computeValidScaleInAuthorization(value ScaleInAuthorization, binding ScaleInBinding, max int) bool {
	return value.Binding == binding && computeValid(value.LowUseObservation.Value, max) &&
		value.ObservationSequence > 0 && value.FreshThroughSequence > 0 && value.CurrentCount > 0 &&
		value.MinimumCount >= 0 && value.ReplacementCapacity >= 0 && value.AvailabilityHeadroom >= 0 &&
		computeValid(value.LowUseProof.Value, max) && computeValid(value.CooldownProof.Value, max) &&
		computeValid(value.LifetimeProof.Value, max) && computeValid(value.CostBenefitProof.Value, max) &&
		computeValid(value.ControlHealthProof.Value, max) && computeValid(value.NatsHealthProof.Value, max) &&
		computeValid(value.AvailabilityProof.Value, max) &&
		computeDefined(computeStatefulDispositionDefined(value.StatefulDisposition)) &&
		computeValid(value.StatefulProof.Value, max)
}

func computeValidScaleInProgress(value ScaleInProgress, binding ScaleInBinding, max int) bool {
	return value.Binding == binding && computeValidOptional(value.CordonProof, max) &&
		computeValidOptional(value.DrainProof, max) && computeValidOptional(value.DeregistrationProof, max) &&
		computeValidOptional(value.VolumeProof, max) && computeValidOptional(value.RevocationProof, max) &&
		computeValidOptional(value.TerminationProof, max) && computeValidOptional(value.BootAbsenceProof, max) &&
		computeValidOptional(value.OrphanAuditProof, max) &&
		computeDefined(computeVolumeDispositionDefined(value.VolumeDisposition)) &&
		(value.StatefulOwner == nil || computeValid(value.StatefulOwner.Value, max)) &&
		((value.VolumeDisposition == VolumeDispositionRetainedStateful) == (value.StatefulOwner != nil))
}

func computeValidBundle(value *RegionalSurvivalBundle, max int) bool {
	if value == nil || max <= 0 || value.Generation <= 0 ||
		!computeValid(value.Bundle.Value, max) || !computeValid(value.Cell.Value, max) ||
		!computeValid(value.ProviderFingerprint.Value, max) ||
		!computeValid(value.AcceptedArtifact.Value, max) || !computeValid(value.AcceptedDigest.Value, max) ||
		!computeValid(value.AcceptedSignature.Value, max) ||
		!computeValid(value.RollbackArtifact.Value, max) || !computeValid(value.RollbackDigest.Value, max) ||
		!computeValid(value.RollbackSignature.Value, max) ||
		value.AcceptedArtifact == value.RollbackArtifact || value.AcceptedDigest == value.RollbackDigest ||
		len(value.EncryptedSecretVersions) == 0 || len(value.Templates) == 0 {
		return false
	}
	for _, item := range value.EncryptedSecretVersions {
		if !computeValid(item.Value, max) {
			return false
		}
	}
	for _, item := range value.Templates {
		if !computeValid(item.NodeClass.Value, max) || !computeValid(item.Template.Value, max) ||
			!computeValid(item.Shape.Value, max) || !computeValid(item.Domain.Value, max) {
			return false
		}
	}
	secrets := make(map[SecretVersionId]struct{}, len(value.EncryptedSecretVersions))
	for _, item := range value.EncryptedSecretVersions {
		secrets[item] = struct{}{}
	}
	if len(secrets) != len(value.EncryptedSecretVersions) {
		return false
	}
	templates := make(map[NodeTemplateId]struct{}, len(value.Templates))
	for _, item := range value.Templates {
		templates[item.Template] = struct{}{}
	}
	if len(templates) != len(value.Templates) {
		return false
	}
	if !computeValid(value.Trust.Value, max) || !computeValid(value.Nats.Value, max) ||
		!computeValid(value.Dns.Value, max) || !computeValid(value.Backup.Value, max) ||
		value.AuthorityEpoch <= 0 || value.JournalPosition <= 0 || value.SnapshotPosition <= 0 ||
		value.FreshThroughPosition <= 0 || value.ExpiresAfterPosition <= 0 ||
		value.SnapshotPosition > value.JournalPosition || value.JournalPosition > value.FreshThroughPosition ||
		value.FreshThroughPosition > value.ExpiresAfterPosition {
		return false
	}
	return true
}

func computeValidAuthority(value RegionalAuthorityProof, max int) bool {
	return computeValid(value.Cell.Value, max) && value.AuthorityEpoch > 0 &&
		value.JournalPosition > 0 && computeValid(value.Proof.Value, max)
}

func computeValidReplacementTarget(value *SurvivalReplacementTarget, bundle *RegionalSurvivalBundle, max int) bool {
	if value == nil || !computeValid(value.Cell.Value, max) || !computeValid(value.NodeClass.Value, max) ||
		!computeValid(value.Template.Value, max) || !computeValid(value.Shape.Value, max) ||
		!computeValid(value.Domain.Value, max) || !computeValid(value.Artifact.Value, max) ||
		!computeValid(value.ArtifactDigest.Value, max) || !computeValid(value.Operation.Value, max) ||
		!computeValid(value.ProviderFingerprint.Value, max) || !computeValid(value.CreateKey.Value, max) ||
		value.BundleGeneration <= 0 || value.ControllerEpoch <= 0 ||
		value.Cell != bundle.Cell || value.ProviderFingerprint != bundle.ProviderFingerprint ||
		value.BundleGeneration != bundle.Generation || value.ControllerEpoch != bundle.AuthorityEpoch ||
		value.Artifact != bundle.AcceptedArtifact || value.ArtifactDigest != bundle.AcceptedDigest {
		return false
	}
	for _, template := range bundle.Templates {
		if template.NodeClass == value.NodeClass && template.Template == value.Template &&
			template.Shape == value.Shape && template.Domain == value.Domain {
			return true
		}
	}
	return false
}

func computeValidOutPrefix(state ScaleOutState, value ScaleOutProgress) bool {
	switch state {
	case ScaleOutStateInstanceCreated:
		return value.IdentityAttested && value.IdentityProof != nil &&
			!value.Enrolled && value.EnrollmentProof == nil &&
			!value.BootstrapPassed && value.BootstrapProof == nil &&
			!value.DiskPassed && value.DiskProof == nil &&
			!value.PlacementComplete && value.PlacementProof == nil &&
			!value.ServiceHealthy && value.HealthProof == nil
	case ScaleOutStateEnrolled:
		return value.IdentityAttested && value.Enrolled && value.BootstrapPassed &&
			value.DiskPassed && value.IdentityProof != nil && value.EnrollmentProof != nil &&
			value.BootstrapProof != nil && value.DiskProof != nil && !value.PlacementComplete &&
			value.PlacementProof == nil && !value.ServiceHealthy && value.HealthProof == nil
	case ScaleOutStateReady, ScaleOutStateCompleted:
		return value.IdentityAttested && value.Enrolled &&
			value.BootstrapPassed && value.DiskPassed && value.PlacementComplete && value.ServiceHealthy &&
			value.IdentityProof != nil && value.EnrollmentProof != nil &&
			value.BootstrapProof != nil && value.DiskProof != nil && value.PlacementProof != nil &&
			value.HealthProof != nil
	default:
		return false
	}
}

func computeValidScaleInPrefix(state ScaleInState, value ScaleInProgress) bool {
	switch state {
	case ScaleInStateCandidateSelected:
		return !value.Cordoned && value.CordonProof == nil && !value.Drained &&
			value.DrainProof == nil && !value.Deregistered && value.DeregistrationProof == nil &&
			!value.VolumeHandled && value.VolumeProof == nil && !value.Revoked &&
			value.RevocationProof == nil && !value.ExactInstanceTerminated &&
			value.TerminationProof == nil && !value.BootVolumeAbsent &&
			value.BootAbsenceProof == nil && !value.OrphanAuditPassed && value.OrphanAuditProof == nil
	case ScaleInStateCordoned:
		return value.Cordoned && !value.Drained && !value.Deregistered && !value.VolumeHandled &&
			!value.Revoked && !value.ExactInstanceTerminated && !value.BootVolumeAbsent && !value.OrphanAuditPassed &&
			value.CordonProof != nil && value.DrainProof == nil && value.DeregistrationProof == nil &&
			value.VolumeProof == nil && value.RevocationProof == nil && value.TerminationProof == nil &&
			value.BootAbsenceProof == nil && value.OrphanAuditProof == nil
	case ScaleInStateDrained:
		return value.Cordoned && value.Drained && !value.Deregistered && !value.VolumeHandled &&
			!value.Revoked && !value.ExactInstanceTerminated && !value.BootVolumeAbsent && !value.OrphanAuditPassed &&
			value.CordonProof != nil && value.DrainProof != nil && value.DeregistrationProof == nil &&
			value.VolumeProof == nil && value.RevocationProof == nil && value.TerminationProof == nil &&
			value.BootAbsenceProof == nil && value.OrphanAuditProof == nil
	case ScaleInStateDeregistered:
		return value.Cordoned && value.Drained && value.Deregistered && !value.VolumeHandled &&
			!value.Revoked && !value.ExactInstanceTerminated && !value.BootVolumeAbsent && !value.OrphanAuditPassed &&
			value.CordonProof != nil && value.DrainProof != nil && value.DeregistrationProof != nil &&
			value.VolumeProof == nil && value.RevocationProof == nil && value.TerminationProof == nil &&
			value.BootAbsenceProof == nil && value.OrphanAuditProof == nil
	case ScaleInStateStorageHandled:
		return value.Cordoned && value.Drained && value.Deregistered && value.VolumeHandled &&
			!value.Revoked && !value.ExactInstanceTerminated && !value.BootVolumeAbsent && !value.OrphanAuditPassed &&
			value.CordonProof != nil && value.DrainProof != nil && value.DeregistrationProof != nil &&
			value.VolumeProof != nil && value.RevocationProof == nil && value.TerminationProof == nil &&
			value.BootAbsenceProof == nil && value.OrphanAuditProof == nil
	case ScaleInStateRevoked:
		return value.Cordoned && value.Drained && value.Deregistered && value.VolumeHandled &&
			value.Revoked && !value.ExactInstanceTerminated && !value.BootVolumeAbsent && !value.OrphanAuditPassed &&
			value.CordonProof != nil && value.DrainProof != nil && value.DeregistrationProof != nil &&
			value.VolumeProof != nil && value.RevocationProof != nil && value.TerminationProof == nil &&
			value.BootAbsenceProof == nil && value.OrphanAuditProof == nil
	case ScaleInStateTerminated:
		return value.Cordoned && value.Drained && value.Deregistered && value.VolumeHandled &&
			value.Revoked && value.ExactInstanceTerminated && value.BootVolumeAbsent && !value.OrphanAuditPassed &&
			value.CordonProof != nil && value.DrainProof != nil && value.DeregistrationProof != nil &&
			value.VolumeProof != nil && value.RevocationProof != nil && value.TerminationProof != nil &&
			value.BootAbsenceProof != nil && value.OrphanAuditProof == nil
	case ScaleInStateAudited, ScaleInStateCompleted:
		return value.Cordoned && value.Drained && value.Deregistered &&
			value.VolumeHandled && value.Revoked && value.ExactInstanceTerminated && value.BootVolumeAbsent &&
			value.OrphanAuditPassed && value.CordonProof != nil && value.DrainProof != nil &&
			value.DeregistrationProof != nil && value.VolumeProof != nil && value.RevocationProof != nil &&
			value.TerminationProof != nil && value.BootAbsenceProof != nil && value.OrphanAuditProof != nil
	default:
		return false
	}
}

func computeEquivalentBundle(left, right *RegionalSurvivalBundle) bool {
	if left.Bundle != right.Bundle || left.Cell != right.Cell || left.Generation != right.Generation ||
		left.ProviderFingerprint != right.ProviderFingerprint ||
		left.AcceptedArtifact != right.AcceptedArtifact || left.AcceptedDigest != right.AcceptedDigest ||
		left.AcceptedSignature != right.AcceptedSignature ||
		left.RollbackArtifact != right.RollbackArtifact || left.RollbackDigest != right.RollbackDigest ||
		left.RollbackSignature != right.RollbackSignature || left.Trust != right.Trust ||
		left.Nats != right.Nats || left.Dns != right.Dns || left.Backup != right.Backup ||
		left.AuthorityEpoch != right.AuthorityEpoch || left.JournalPosition != right.JournalPosition ||
		left.SnapshotPosition != right.SnapshotPosition ||
		left.FreshThroughPosition != right.FreshThroughPosition ||
		left.ExpiresAfterPosition != right.ExpiresAfterPosition {
		return false
	}
	leftSecrets := make([]SecretVersionId, len(left.EncryptedSecretVersions))
	copy(leftSecrets, left.EncryptedSecretVersions)
	sort.Slice(leftSecrets, func(i, j int) bool { return leftSecrets[i].Value < leftSecrets[j].Value })
	rightSecrets := make([]SecretVersionId, len(right.EncryptedSecretVersions))
	copy(rightSecrets, right.EncryptedSecretVersions)
	sort.Slice(rightSecrets, func(i, j int) bool { return rightSecrets[i].Value < rightSecrets[j].Value })
	if len(leftSecrets) != len(rightSecrets) {
		return false
	}
	for index := range leftSecrets {
		if leftSecrets[index] != rightSecrets[index] {
			return false
		}
	}
	leftTemplates := make([]SurvivalNodeTemplate, len(left.Templates))
	copy(leftTemplates, left.Templates)
	sort.Slice(leftTemplates, func(i, j int) bool {
		return leftTemplates[i].Template.Value < leftTemplates[j].Template.Value
	})
	rightTemplates := make([]SurvivalNodeTemplate, len(right.Templates))
	copy(rightTemplates, right.Templates)
	sort.Slice(rightTemplates, func(i, j int) bool {
		return rightTemplates[i].Template.Value < rightTemplates[j].Template.Value
	})
	if len(leftTemplates) != len(rightTemplates) {
		return false
	}
	for index := range leftTemplates {
		if leftTemplates[index] != rightTemplates[index] {
			return false
		}
	}
	return true
}

func computeValid(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	runes := []rune(value)
	for index := 0; index < len(runes); index++ {
		character := runes[index]
		if isSpaceRune(character) || isControlRune(character) {
			return false
		}
		if character >= 0xD800 && character <= 0xDFFF {
			if !(character >= 0xD800 && character <= 0xDBFF) || index+1 >= len(runes) ||
				!(runes[index+1] >= 0xDC00 && runes[index+1] <= 0xDFFF) {
				return false
			}
			index++
		}
	}
	return true
}

func computeValidOptional(value *ComputeProofId, max int) bool {
	return value == nil || computeValid(value.Value, max)
}

func computeScaleOutDefined(value ScaleOutState) bool {
	return value != ScaleOutStateUnspecified && scaleOutStateIsDefined(value)
}

func computeScaleInDefined(value ScaleInState) bool {
	return value != ScaleInStateUnspecified && scaleInStateIsDefined(value)
}

func computeTriggerDefined(value ComputeTrigger) bool {
	return value != ComputeTriggerUnspecified && computeTriggerIsDefined(value)
}

func computeProviderCreateStatusDefined(value ProviderCreateStatus) bool {
	return value != ProviderCreateStatusUnspecified && providerCreateStatusIsDefined(value)
}
func computeStatefulDispositionDefined(value StatefulDisposition) bool {
	return value != StatefulDispositionUnspecified && statefulDispositionIsDefined(value)
}
func computeVolumeDispositionDefined(value VolumeDisposition) bool {
	return value != VolumeDispositionUnspecified && volumeDispositionIsDefined(value)
}
func computeNodeRoleDefined(value ComputeNodeRole) bool {
	return value != ComputeNodeRoleUnspecified && computeNodeRoleIsDefined(value)
}

// computeDefined mirrors the C# Defined<T> helper: defined and non-zero.
func computeDefined(defined bool) bool { return defined }

func computeOne(intent ComputeIntent, code ComputeTraceCode) *ComputeDecision {
	return computeDecision([]ComputeIntent{intent}, []ComputeError{}, []ComputeTrace{{1, code, intent.computeIntentAction()}}, nil)
}

func computeCompleted() *ComputeDecision {
	return computeDecision([]ComputeIntent{}, []ComputeError{},
		[]ComputeTrace{{1, ComputeTraceCodeCompleted, ComputeActionReady}}, nil)
}

func computeHeld(code ComputeErrorCode, operation ComputeOperationId) *ComputeDecision {
	err := ComputeError{Code: code, Requirement: computeEngineRequirement, Operation: &operation}
	hold := NewHoldComputeIntent(code, &operation)
	return computeDecision([]ComputeIntent{hold}, []ComputeError{err},
		[]ComputeTrace{{1, ComputeTraceCodeHeld, hold.computeIntentAction()}}, nil)
}

func computeDecision(intents []ComputeIntent, errors []ComputeError, trace []ComputeTrace,
	acceptedScaleOutRequest *ScaleOutRequest) *ComputeDecision {
	return &ComputeDecision{Intents: intents, Errors: errors, Trace: trace,
		AcceptedScaleOutRequest: acceptedScaleOutRequest}
}
