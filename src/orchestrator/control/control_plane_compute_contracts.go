package control

// ComputeTechnicalInputLimits ports the technical caller-input snapshot
// limits; these are not scaling, replica, or capacity policy caps.
const (
	ComputeTechnicalInputLimitsMaximumSurvivalSecretVersionCount = 4096
	ComputeTechnicalInputLimitsMaximumSurvivalNodeTemplateCount  = 4096
)

// computeInputSnapshotCopy ports the internal ComputeInputSnapshot.Copy.
func computeInputSnapshotCopy[T any](source []T, maximum int, parameterName, inputName string) ([]T, error) {
	if source == nil {
		return nil, argumentNil(parameterName)
	}
	if len(source) > maximum {
		return nil, invalidArgument(inputName + " exceeds the technical snapshot bound.")
	}
	result := make([]T, len(source))
	copy(result, source)
	return result, nil
}

// Identity records (value objects with a required string).
type ComputeCellId struct{ Value string }
type ComputeNodeId struct{ Value string }
type NodeClassId struct{ Value string }
type NodeTemplateId struct{ Value string }
type ComputeShapeId struct{ Value string }
type PlacementDomainId struct{ Value string }
type ComputeArtifactId struct{ Value string }
type ComputeDigestId struct{ Value string }
type SecretVersionId struct{ Value string }
type SurvivalBundleId struct{ Value string }
type DemandObservationId struct{ Value string }
type ComputeOperationId struct{ Value string }
type ProviderFingerprintId struct{ Value string }
type ProviderResourceId struct{ Value string }
type ProviderCreateKey struct{ Value string }
type WorkRequestId struct{ Value string }
type ComputeProofId struct{ Value string }
type StatefulOwnerId struct{ Value string }
type LoadBalancerRegistrationId struct{ Value string }
type ComputeVolumeId struct{ Value string }
type TrustReferenceId struct{ Value string }
type NatsReferenceId struct{ Value string }
type DnsReferenceId struct{ Value string }
type BackupReferenceId struct{ Value string }

type ComputeTrigger int

const (
	ComputeTriggerUnspecified ComputeTrigger = iota
	ComputeTriggerUnschedulable
	ComputeTriggerUtilization
	ComputeTriggerQueueBacklog
	ComputeTriggerConcurrency
	ComputeTriggerDatabaseMember
	ComputeTriggerRolloutSurge
	ComputeTriggerPredictiveWarm
	ComputeTriggerFailedHostReplacement
	ComputeTriggerSafetyRecovery
)

func computeTriggerIsDefined(v ComputeTrigger) bool {
	return v >= ComputeTriggerUnspecified && v <= ComputeTriggerSafetyRecovery
}

type ComputeNodeRole int

const (
	ComputeNodeRoleUnspecified ComputeNodeRole = iota
	ComputeNodeRoleElasticStateless
	ComputeNodeRoleElasticStateful
	ComputeNodeRoleSeedController
	ComputeNodeRoleControlNats
	ComputeNodeRoleProductNats
	ComputeNodeRoleTerraBase
)

func computeNodeRoleIsDefined(v ComputeNodeRole) bool {
	return v >= ComputeNodeRoleUnspecified && v <= ComputeNodeRoleTerraBase
}

type ScaleOutState int

const (
	ScaleOutStateUnspecified ScaleOutState = iota
	ScaleOutStateDemandObserved
	ScaleOutStatePlanPersisted
	ScaleOutStateAuthorized
	ScaleOutStateRequestRecorded
	ScaleOutStateInstanceCreated
	ScaleOutStateEnrolled
	ScaleOutStateReady
	ScaleOutStateCompleted
)

func scaleOutStateIsDefined(v ScaleOutState) bool {
	return v >= ScaleOutStateUnspecified && v <= ScaleOutStateCompleted
}

type ScaleInState int

const (
	ScaleInStateUnspecified ScaleInState = iota
	ScaleInStateCandidateSelected
	ScaleInStateCordoned
	ScaleInStateDrained
	ScaleInStateDeregistered
	ScaleInStateStorageHandled
	ScaleInStateRevoked
	ScaleInStateTerminated
	ScaleInStateAudited
	ScaleInStateCompleted
)

func scaleInStateIsDefined(v ScaleInState) bool {
	return v >= ScaleInStateUnspecified && v <= ScaleInStateCompleted
}

type ProviderCreateStatus int

const (
	ProviderCreateStatusUnspecified ProviderCreateStatus = iota
	ProviderCreateStatusProvenAbsent
	ProviderCreateStatusOutcomeUnknown
	ProviderCreateStatusCreated
)

func providerCreateStatusIsDefined(v ProviderCreateStatus) bool {
	return v >= ProviderCreateStatusUnspecified && v <= ProviderCreateStatusCreated
}

type StatefulDisposition int

const (
	StatefulDispositionUnspecified StatefulDisposition = iota
	StatefulDispositionNotStateful
	StatefulDispositionApproved
	StatefulDispositionVetoed
)

func statefulDispositionIsDefined(v StatefulDisposition) bool {
	return v >= StatefulDispositionUnspecified && v <= StatefulDispositionVetoed
}

type VolumeDisposition int

const (
	VolumeDispositionUnspecified VolumeDisposition = iota
	VolumeDispositionDetachedEphemeral
	VolumeDispositionRetainedStateful
)

func volumeDispositionIsDefined(v VolumeDisposition) bool {
	return v >= VolumeDispositionUnspecified && v <= VolumeDispositionRetainedStateful
}

type ComputeAction int

const (
	ComputeActionUnspecified ComputeAction = iota
	ComputeActionObserve
	ComputeActionPersistPlan
	ComputeActionAuthorize
	ComputeActionRequestCreate
	ComputeActionEnroll
	ComputeActionReady
	ComputeActionCordon
	ComputeActionDrain
	ComputeActionDeregister
	ComputeActionDetach
	ComputeActionRevoke
	ComputeActionTerminate
	ComputeActionAudit
	ComputeActionHold
)

func computeActionIsDefined(v ComputeAction) bool {
	return v >= ComputeActionUnspecified && v <= ComputeActionHold
}

type ComputeErrorCode int

const (
	ComputeErrorCodeUnspecified ComputeErrorCode = iota
	ComputeErrorCodeInvalidInput
	ComputeErrorCodeEvidenceMismatch
	ComputeErrorCodeEvidenceStale
	ComputeErrorCodeMissingProof
	ComputeErrorCodeBudgetDenied
	ComputeErrorCodeQuotaDenied
	ComputeErrorCodeCapacityDenied
	ComputeErrorCodeCostDenied
	ComputeErrorCodePlacementDenied
	ComputeErrorCodeConflictingOperation
	ComputeErrorCodeFloorDenied
	ComputeErrorCodeAvailabilityDenied
	ComputeErrorCodeStatefulVeto
	ComputeErrorCodeUnsafeTermination
	ComputeErrorCodeOrphanDenied
	ComputeErrorCodeBundleIncomplete
	ComputeErrorCodeBundleExpired
	ComputeErrorCodeAuthorityDenied
)

func computeErrorCodeIsDefined(v ComputeErrorCode) bool {
	return v >= ComputeErrorCodeUnspecified && v <= ComputeErrorCodeAuthorityDenied
}

type ComputeTraceCode int

const (
	ComputeTraceCodeUnspecified ComputeTraceCode = iota
	ComputeTraceCodeObservationRequired
	ComputeTraceCodePlanRequired
	ComputeTraceCodeAuthorizationReady
	ComputeTraceCodeCreateReady
	ComputeTraceCodeEnrollmentReady
	ComputeTraceCodeReadinessReady
	ComputeTraceCodeCordonReady
	ComputeTraceCodeDrainReady
	ComputeTraceCodeDeregistrationReady
	ComputeTraceCodeVolumeReady
	ComputeTraceCodeRevocationReady
	ComputeTraceCodeTerminationReady
	ComputeTraceCodeAuditReady
	ComputeTraceCodeCompleted
	ComputeTraceCodeHeld
)

func computeTraceCodeIsDefined(v ComputeTraceCode) bool {
	return v >= ComputeTraceCodeUnspecified && v <= ComputeTraceCodeHeld
}

type ComputeRequirementCode int

const (
	ComputeRequirementCodeUnspecified ComputeRequirementCode = 0
	ComputeRequirementCodeInv005      ComputeRequirementCode = 5
	ComputeRequirementCodeReqO011     ComputeRequirementCode = 11
)

type ComputeBinding struct {
	Cell                ComputeCellId
	NodeClass           NodeClassId
	Template            NodeTemplateId
	Shape               ComputeShapeId
	Domain              PlacementDomainId
	Artifact            ComputeArtifactId
	ArtifactDigest      ComputeDigestId
	Demand              DemandObservationId
	Operation           ComputeOperationId
	ProviderFingerprint ProviderFingerprintId
	Generation          int64
	ControllerEpoch     int64
}

type ResourceEnvelope struct {
	Ocpus                     uint64
	MemoryMib                 uint64
	StorageGib                uint64
	EstimatedHourlyCostMicros uint64
}

type DemandEvidence struct {
	Binding              ComputeBinding
	Trigger              ComputeTrigger
	ObservationSequence  int64
	FreshThroughSequence int64
	RequiredNodes        int
	ExplicitDemand       bool
	Sustained            bool
	SafetyBounded        bool
}

type CapacityAuthorization struct {
	Binding           ComputeBinding
	Resources         ResourceEnvelope
	AuthorizedNodes   int
	BudgetProof       ComputeProofId
	QuotaProof        ComputeProofId
	CapacityProof     ComputeProofId
	CostProof         ComputeProofId
	PlacementProof    ComputeProofId
	BudgetAllowed     bool
	QuotaAllowed      bool
	CapacityAvailable bool
	CostAllowed       bool
	PlacementAllowed  bool
}

type ScaleOutPlan struct {
	Binding      ComputeBinding
	Resources    ResourceEnvelope
	DesiredNodes int
	PlanIdentity ComputeProofId
}

type PersistedScaleOutPlan struct {
	Plan             ScaleOutPlan
	PersistenceProof ComputeProofId
}

type ProviderCreateEvidence struct {
	Binding          ComputeBinding
	CreateKey        ProviderCreateKey
	Status           ProviderCreateStatus
	Resource         *ProviderResourceId
	WorkRequest      *WorkRequestId
	ObservationProof ComputeProofId
}

type ScaleOutProgress struct {
	Binding           ComputeBinding
	Resource          *ProviderResourceId
	Node              *ComputeNodeId
	IdentityProof     *ComputeProofId
	EnrollmentProof   *ComputeProofId
	BootstrapProof    *ComputeProofId
	DiskProof         *ComputeProofId
	PlacementProof    *ComputeProofId
	HealthProof       *ComputeProofId
	IdentityAttested  bool
	Enrolled          bool
	BootstrapPassed   bool
	DiskPassed        bool
	PlacementComplete bool
	ServiceHealthy    bool
}

type ScaleOutRequest struct {
	Binding               ComputeBinding
	State                 ScaleOutState
	Demand                DemandEvidence
	Plan                  ScaleOutPlan
	PersistedPlan         *PersistedScaleOutPlan
	Authorization         *CapacityAuthorization
	CreateEvidence        *ProviderCreateEvidence
	Progress              *ScaleOutProgress
	EvaluationSequence    int64
	MaximumIdentityLength int
}

type ScaleInBinding struct {
	Compute                  ComputeBinding
	Node                     ComputeNodeId
	Resource                 ProviderResourceId
	LoadBalancerRegistration LoadBalancerRegistrationId
	Volume                   ComputeVolumeId
	Role                     ComputeNodeRole
}

type ScaleInAuthorization struct {
	Binding                ScaleInBinding
	LowUseObservation      DemandObservationId
	ObservationSequence    int64
	FreshThroughSequence   int64
	CurrentCount           int
	MinimumCount           int
	ReplacementCapacity    int
	AvailabilityHeadroom   int
	LowUseProof            ComputeProofId
	CooldownProof          ComputeProofId
	LifetimeProof          ComputeProofId
	CostBenefitProof       ComputeProofId
	ControlHealthProof     ComputeProofId
	NatsHealthProof        ComputeProofId
	AvailabilityProof      ComputeProofId
	StatefulDisposition    StatefulDisposition
	StatefulProof          ComputeProofId
	SustainedLowUse        bool
	CooldownPassed         bool
	LifetimePassed         bool
	CostBenefitPassed      bool
	RegionalControlHealthy bool
	NatsHealthy            bool
	ConflictingOperation   bool
	StatefulApproved       bool
}

type ScaleInProgress struct {
	Binding                 ScaleInBinding
	CordonProof             *ComputeProofId
	DrainProof              *ComputeProofId
	DeregistrationProof     *ComputeProofId
	VolumeProof             *ComputeProofId
	RevocationProof         *ComputeProofId
	TerminationProof        *ComputeProofId
	BootAbsenceProof        *ComputeProofId
	OrphanAuditProof        *ComputeProofId
	VolumeDisposition       VolumeDisposition
	StatefulOwner           *StatefulOwnerId
	Cordoned                bool
	Drained                 bool
	Deregistered            bool
	VolumeHandled           bool
	Revoked                 bool
	ExactInstanceTerminated bool
	BootVolumeAbsent        bool
	OrphanAuditPassed       bool
}

type ScaleInRequest struct {
	Binding               ScaleInBinding
	State                 ScaleInState
	Authorization         ScaleInAuthorization
	Progress              ScaleInProgress
	EvaluationSequence    int64
	MaximumIdentityLength int
}

type RegionalSurvivalBundle struct {
	Bundle                  SurvivalBundleId
	Cell                    ComputeCellId
	Generation              int64
	ProviderFingerprint     ProviderFingerprintId
	AcceptedArtifact        ComputeArtifactId
	AcceptedDigest          ComputeDigestId
	AcceptedSignature       ComputeProofId
	RollbackArtifact        ComputeArtifactId
	RollbackDigest          ComputeDigestId
	RollbackSignature       ComputeProofId
	EncryptedSecretVersions []SecretVersionId
	Templates               []SurvivalNodeTemplate
	Trust                   TrustReferenceId
	Nats                    NatsReferenceId
	Dns                     DnsReferenceId
	Backup                  BackupReferenceId
	AuthorityEpoch          int64
	JournalPosition         int64
	SnapshotPosition        int64
	FreshThroughPosition    int64
	ExpiresAfterPosition    int64
}

func NewRegionalSurvivalBundle(bundle SurvivalBundleId, cell ComputeCellId, generation int64,
	providerFingerprint ProviderFingerprintId, acceptedArtifact ComputeArtifactId, acceptedDigest ComputeDigestId,
	acceptedSignature ComputeProofId, rollbackArtifact ComputeArtifactId, rollbackDigest ComputeDigestId,
	rollbackSignature ComputeProofId, encryptedSecretVersions []SecretVersionId,
	templates []SurvivalNodeTemplate, trust TrustReferenceId, nats NatsReferenceId, dns DnsReferenceId,
	backup BackupReferenceId, authorityEpoch, journalPosition, snapshotPosition,
	freshThroughPosition, expiresAfterPosition int64) (*RegionalSurvivalBundle, error) {
	secrets, err := computeInputSnapshotCopy(encryptedSecretVersions,
		ComputeTechnicalInputLimitsMaximumSurvivalSecretVersionCount, "encryptedSecretVersions",
		"Survival secret versions")
	if err != nil {
		return nil, err
	}
	templateCopy, err := computeInputSnapshotCopy(templates,
		ComputeTechnicalInputLimitsMaximumSurvivalNodeTemplateCount, "templates", "Survival node templates")
	if err != nil {
		return nil, err
	}
	return &RegionalSurvivalBundle{bundle, cell, generation, providerFingerprint, acceptedArtifact,
		acceptedDigest, acceptedSignature, rollbackArtifact, rollbackDigest, rollbackSignature, secrets,
		templateCopy, trust, nats, dns, backup, authorityEpoch, journalPosition, snapshotPosition,
		freshThroughPosition, expiresAfterPosition}, nil
}

type SurvivalNodeTemplate struct {
	NodeClass NodeClassId
	Template  NodeTemplateId
	Shape     ComputeShapeId
	Domain    PlacementDomainId
}

type SurvivalBundleEvidence struct {
	Observed          *RegionalSurvivalBundle
	BundleSignature   ComputeProofId
	EncryptionProof   ComputeProofId
	SignatureValid    bool
	MetadataEncrypted bool
	ArtifactsLocal    bool
	SecretsLocal      bool
	ProviderReady     bool
	TrustReady        bool
	NatsReady         bool
	DnsReady          bool
	BackupReady       bool
}

type RegionalAuthorityProof struct {
	Cell                ComputeCellId
	AuthorityEpoch      int64
	JournalPosition     int64
	Proof               ComputeProofId
	QuorumAuthoritative bool
}

type SurvivalRequest struct {
	Required                         *RegionalSurvivalBundle
	Evidence                         SurvivalBundleEvidence
	Authority                        RegionalAuthorityProof
	CurrentAcceptedGeneration        int64
	EvaluationPosition               int64
	DisconnectedReplacementRequested bool
	ReplacementTarget                *SurvivalReplacementTarget
	MaximumIdentityLength            int
}

type SurvivalReplacementTarget struct {
	Cell                ComputeCellId
	NodeClass           NodeClassId
	Template            NodeTemplateId
	Shape               ComputeShapeId
	Domain              PlacementDomainId
	Artifact            ComputeArtifactId
	ArtifactDigest      ComputeDigestId
	Operation           ComputeOperationId
	ProviderFingerprint ProviderFingerprintId
	CreateKey           ProviderCreateKey
	BundleGeneration    int64
	ControllerEpoch     int64
}

type ComputeError struct {
	Code        ComputeErrorCode
	Requirement ComputeRequirementCode
	Operation   *ComputeOperationId
}

type ComputeTrace struct {
	Sequence int
	Code     ComputeTraceCode
	Action   ComputeAction
}

// ComputeIntent is the Go form of the abstract ComputeIntent class.
type ComputeIntent interface {
	computeIntentAction() ComputeAction
}

type computeIntentBase struct{ action ComputeAction }

func (b computeIntentBase) computeIntentAction() ComputeAction { return b.action }

type ObserveCreateIntent struct {
	computeIntentBase
	Binding   ComputeBinding
	CreateKey ProviderCreateKey
}

func NewObserveCreateIntent(binding ComputeBinding, key ProviderCreateKey) *ObserveCreateIntent {
	return &ObserveCreateIntent{computeIntentBase{ComputeActionObserve}, binding, key}
}

type PersistScalePlanIntent struct {
	computeIntentBase
	Binding      ComputeBinding
	Resources    ResourceEnvelope
	DesiredNodes int
	PlanIdentity ComputeProofId
}

func NewPersistScalePlanIntent(binding ComputeBinding, resources ResourceEnvelope, desiredNodes int,
	planIdentity ComputeProofId) *PersistScalePlanIntent {
	return &PersistScalePlanIntent{computeIntentBase{ComputeActionPersistPlan}, binding, resources, desiredNodes, planIdentity}
}

type AuthorizeCapacityIntent struct {
	computeIntentBase
	Binding       ComputeBinding
	PersistedPlan PersistedScaleOutPlan
}

func NewAuthorizeCapacityIntent(binding ComputeBinding, persistedPlan PersistedScaleOutPlan) *AuthorizeCapacityIntent {
	return &AuthorizeCapacityIntent{computeIntentBase{ComputeActionAuthorize}, binding, persistedPlan}
}

type RequestCreateIntent struct {
	computeIntentBase
	Binding        ComputeBinding
	CreateKey      ProviderCreateKey
	PersistedPlan  PersistedScaleOutPlan
	Authorization  CapacityAuthorization
	CreateEvidence ProviderCreateEvidence
}

func NewRequestCreateIntent(binding ComputeBinding, key ProviderCreateKey, persistedPlan PersistedScaleOutPlan,
	authorization CapacityAuthorization, createEvidence ProviderCreateEvidence) *RequestCreateIntent {
	return &RequestCreateIntent{computeIntentBase{ComputeActionRequestCreate}, binding, key, persistedPlan,
		authorization, createEvidence}
}

type EnrollNodeIntent struct {
	computeIntentBase
	Binding       ComputeBinding
	Resource      ProviderResourceId
	Node          ComputeNodeId
	IdentityProof ComputeProofId
}

func NewEnrollNodeIntent(binding ComputeBinding, resource ProviderResourceId, node ComputeNodeId,
	identityProof ComputeProofId) *EnrollNodeIntent {
	return &EnrollNodeIntent{computeIntentBase{ComputeActionEnroll}, binding, resource, node, identityProof}
}

type ReadyNodeIntent struct {
	computeIntentBase
	Binding        ComputeBinding
	Resource       ProviderResourceId
	Node           ComputeNodeId
	BootstrapProof ComputeProofId
	DiskProof      ComputeProofId
	PlacementProof ComputeProofId
}

func NewReadyNodeIntent(binding ComputeBinding, resource ProviderResourceId, node ComputeNodeId,
	bootstrapProof, diskProof, placementProof ComputeProofId) *ReadyNodeIntent {
	return &ReadyNodeIntent{computeIntentBase{ComputeActionReady}, binding, resource, node, bootstrapProof,
		diskProof, placementProof}
}

type CordonNodeIntent struct {
	computeIntentBase
	Binding ScaleInBinding
}

func NewCordonNodeIntent(binding ScaleInBinding) *CordonNodeIntent {
	return &CordonNodeIntent{computeIntentBase{ComputeActionCordon}, binding}
}

type DrainNodeIntent struct {
	computeIntentBase
	Binding     ScaleInBinding
	CordonProof ComputeProofId
}

func NewDrainNodeIntent(binding ScaleInBinding, cordonProof ComputeProofId) *DrainNodeIntent {
	return &DrainNodeIntent{computeIntentBase{ComputeActionDrain}, binding, cordonProof}
}

type DeregisterNodeIntent struct {
	computeIntentBase
	Binding       ScaleInBinding
	StatefulProof ComputeProofId
}

func NewDeregisterNodeIntent(binding ScaleInBinding, statefulProof ComputeProofId) *DeregisterNodeIntent {
	return &DeregisterNodeIntent{computeIntentBase{ComputeActionDeregister}, binding, statefulProof}
}

type DetachVolumeIntent struct {
	computeIntentBase
	Binding       ScaleInBinding
	Disposition   VolumeDisposition
	StatefulOwner *StatefulOwnerId
}

func NewDetachVolumeIntent(binding ScaleInBinding, disposition VolumeDisposition, owner *StatefulOwnerId) *DetachVolumeIntent {
	return &DetachVolumeIntent{computeIntentBase{ComputeActionDetach}, binding, disposition, owner}
}

type RevokeNodeIntent struct {
	computeIntentBase
	Binding     ScaleInBinding
	VolumeProof ComputeProofId
}

func NewRevokeNodeIntent(binding ScaleInBinding, volumeProof ComputeProofId) *RevokeNodeIntent {
	return &RevokeNodeIntent{computeIntentBase{ComputeActionRevoke}, binding, volumeProof}
}

type TerminateNodeIntent struct {
	computeIntentBase
	Binding         ScaleInBinding
	RevocationProof ComputeProofId
	Authorization   ScaleInAuthorization
	Progress        ScaleInProgress
}

func NewTerminateNodeIntent(binding ScaleInBinding, revocationProof ComputeProofId,
	authorization ScaleInAuthorization, progress ScaleInProgress) *TerminateNodeIntent {
	return &TerminateNodeIntent{computeIntentBase{ComputeActionTerminate}, binding, revocationProof,
		authorization, progress}
}

type AuditOrphansIntent struct {
	computeIntentBase
	Binding          ScaleInBinding
	TerminationProof ComputeProofId
	BootAbsenceProof ComputeProofId
}

func NewAuditOrphansIntent(binding ScaleInBinding, terminationProof, bootAbsenceProof ComputeProofId) *AuditOrphansIntent {
	return &AuditOrphansIntent{computeIntentBase{ComputeActionAudit}, binding, terminationProof, bootAbsenceProof}
}

type AuthorizeSurvivalIntent struct {
	computeIntentBase
	Bundle    *RegionalSurvivalBundle
	Authority RegionalAuthorityProof
	Target    SurvivalReplacementTarget
}

func NewAuthorizeSurvivalIntent(bundle *RegionalSurvivalBundle, authority RegionalAuthorityProof,
	target SurvivalReplacementTarget) *AuthorizeSurvivalIntent {
	return &AuthorizeSurvivalIntent{computeIntentBase{ComputeActionAuthorize}, bundle, authority, target}
}

type ReadySurvivalIntent struct {
	computeIntentBase
	Bundle *RegionalSurvivalBundle
}

func NewReadySurvivalIntent(bundle *RegionalSurvivalBundle) *ReadySurvivalIntent {
	return &ReadySurvivalIntent{computeIntentBase{ComputeActionReady}, bundle}
}

type HoldComputeIntent struct {
	computeIntentBase
	Reason    ComputeErrorCode
	Operation *ComputeOperationId
}

func NewHoldComputeIntent(reason ComputeErrorCode, operation *ComputeOperationId) *HoldComputeIntent {
	return &HoldComputeIntent{computeIntentBase{ComputeActionHold}, reason, operation}
}

type ComputeDecision struct {
	Intents                 []ComputeIntent
	Errors                  []ComputeError
	Trace                   []ComputeTrace
	AcceptedScaleOutRequest *ScaleOutRequest
}
