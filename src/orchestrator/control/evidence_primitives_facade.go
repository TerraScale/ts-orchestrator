package control

import "terrascale.tech/orchestrator/src/orchestrator/evidence"

// Evidence primitives live in the dependency-neutral evidence package. These
// aliases preserve the control package API while callers migrate gradually.
type (
	EvidenceTreeId            = evidence.EvidenceTreeId
	EvidenceDependencyLockId  = evidence.EvidenceDependencyLockId
	EvidenceSchemaId          = evidence.EvidenceSchemaId
	EvidenceTestBinaryId      = evidence.EvidenceTestBinaryId
	EvidenceArtifactId        = evidence.EvidenceArtifactId
	EvidenceSuiteId           = evidence.EvidenceSuiteId
	EvidenceTraceId           = evidence.EvidenceTraceId
	EvidenceFuzzTargetId      = evidence.EvidenceFuzzTargetId
	EvidenceCorpusId          = evidence.EvidenceCorpusId
	EvidenceL0CId             = evidence.EvidenceL0CId
	EvidenceApproverId        = evidence.EvidenceApproverId
	EvidenceSigningProfileId  = evidence.EvidenceSigningProfileId
	EvidenceSigningIdentityId = evidence.EvidenceSigningIdentityId
	EvidenceSignatureId       = evidence.EvidenceSignatureId
	EvidenceManifestId        = evidence.EvidenceManifestId
	EvidenceExclusionId       = evidence.EvidenceExclusionId
	EvidenceSha256            = evidence.EvidenceSha256
	EvidenceCount             = evidence.EvidenceCount
	EvidencePercentage        = evidence.EvidencePercentage
	EvidenceNonNegativeCount  = evidence.EvidenceNonNegativeCount
	EvidenceDurationSeconds   = evidence.EvidenceDurationSeconds
	EvidenceGeneration        = evidence.EvidenceGeneration
	EvidenceSequence          = evidence.EvidenceSequence
	EvidenceLane              = evidence.EvidenceLane
	EvidenceExecutionKind     = evidence.EvidenceExecutionKind
	EvidenceDomain            = evidence.EvidenceDomain
	EvidenceArchitecture      = evidence.EvidenceArchitecture
	EvidenceResult            = evidence.EvidenceResult
	EvidenceExclusionKind     = evidence.EvidenceExclusionKind
	EvidenceChangeKind        = evidence.EvidenceChangeKind
	EvidenceGateTarget        = evidence.EvidenceGateTarget
	EvidenceAction            = evidence.EvidenceAction
	EvidenceCode              = evidence.EvidenceCode
	EvidenceOpaqueSignature   = evidence.EvidenceOpaqueSignature
)

const (
	EvidenceLaneUnknown = evidence.EvidenceLaneUnknown
	EvidenceLaneFeature = evidence.EvidenceLaneFeature
	EvidenceLaneFull    = evidence.EvidenceLaneFull

	EvidenceExecutionKindUnknown               = evidence.EvidenceExecutionKindUnknown
	EvidenceExecutionKindCold                  = evidence.EvidenceExecutionKindCold
	EvidenceExecutionKindContentAddressedReuse = evidence.EvidenceExecutionKindContentAddressedReuse

	EvidenceDomainUnknown       = evidence.EvidenceDomainUnknown
	EvidenceDomainControl       = evidence.EvidenceDomainControl
	EvidenceDomainScheduling    = evidence.EvidenceDomainScheduling
	EvidenceDomainMessaging     = evidence.EvidenceDomainMessaging
	EvidenceDomainCompute       = evidence.EvidenceDomainCompute
	EvidenceDomainStorage       = evidence.EvidenceDomainStorage
	EvidenceDomainTerraBase     = evidence.EvidenceDomainTerraBase
	EvidenceDomainSecurity      = evidence.EvidenceDomainSecurity
	EvidenceDomainDelivery      = evidence.EvidenceDomainDelivery
	EvidenceDomainObservability = evidence.EvidenceDomainObservability
	EvidenceDomainNetworking    = evidence.EvidenceDomainNetworking
	EvidenceDomainBudgets       = evidence.EvidenceDomainBudgets
	EvidenceDomainProvisioning  = evidence.EvidenceDomainProvisioning
	EvidenceDomainRuntime       = evidence.EvidenceDomainRuntime

	EvidenceArchitectureUnknown    = evidence.EvidenceArchitectureUnknown
	EvidenceArchitectureLinuxX64   = evidence.EvidenceArchitectureLinuxX64
	EvidenceArchitectureLinuxArm64 = evidence.EvidenceArchitectureLinuxArm64

	EvidenceResultUnknown = evidence.EvidenceResultUnknown
	EvidenceResultPassed  = evidence.EvidenceResultPassed
	EvidenceResultFailed  = evidence.EvidenceResultFailed

	EvidenceExclusionKindUnknown               = evidence.EvidenceExclusionKindUnknown
	EvidenceExclusionKindGeneratedCode         = evidence.EvidenceExclusionKindGeneratedCode
	EvidenceExclusionKindTrivialWiring         = evidence.EvidenceExclusionKindTrivialWiring
	EvidenceExclusionKindSafety                = evidence.EvidenceExclusionKindSafety
	EvidenceExclusionKindAuthorization         = evidence.EvidenceExclusionKindAuthorization
	EvidenceExclusionKindDurability            = evidence.EvidenceExclusionKindDurability
	EvidenceExclusionKindDeletion              = evidence.EvidenceExclusionKindDeletion
	EvidenceExclusionKindStateTransition       = evidence.EvidenceExclusionKindStateTransition
	EvidenceExclusionKindValidation            = evidence.EvidenceExclusionKindValidation
	EvidenceExclusionKindOwnership             = evidence.EvidenceExclusionKindOwnership
	EvidenceExclusionKindFencing               = evidence.EvidenceExclusionKindFencing
	EvidenceExclusionKindRetry                 = evidence.EvidenceExclusionKindRetry
	EvidenceExclusionKindCompensation          = evidence.EvidenceExclusionKindCompensation
	EvidenceExclusionKindAdapterClassification = evidence.EvidenceExclusionKindAdapterClassification

	EvidenceChangeKindUnknown            = evidence.EvidenceChangeKindUnknown
	EvidenceChangeKindNone               = evidence.EvidenceChangeKindNone
	EvidenceChangeKindShardOnly          = evidence.EvidenceChangeKindShardOnly
	EvidenceChangeKindSharedContract     = evidence.EvidenceChangeKindSharedContract
	EvidenceChangeKindSecurity           = evidence.EvidenceChangeKindSecurity
	EvidenceChangeKindToolchain          = evidence.EvidenceChangeKindToolchain
	EvidenceChangeKindColdFirstCandidate = evidence.EvidenceChangeKindColdFirstCandidate

	EvidenceGateTargetUnknown               = evidence.EvidenceGateTargetUnknown
	EvidenceGateTargetDependencyConformance = evidence.EvidenceGateTargetDependencyConformance
	EvidenceGateTargetL1SCredentialRelease  = evidence.EvidenceGateTargetL1SCredentialRelease

	EvidenceActionUnknown                    = evidence.EvidenceActionUnknown
	EvidenceActionHold                       = evidence.EvidenceActionHold
	EvidenceActionAllowDependencyConformance = evidence.EvidenceActionAllowDependencyConformance
	EvidenceActionAllowL1SCredentialRelease  = evidence.EvidenceActionAllowL1SCredentialRelease

	EvidenceCodeUnknown                     = evidence.EvidenceCodeUnknown
	EvidenceCodeAllowed                     = evidence.EvidenceCodeAllowed
	EvidenceCodeInvalidInput                = evidence.EvidenceCodeInvalidInput
	EvidenceCodeWrongSubject                = evidence.EvidenceCodeWrongSubject
	EvidenceCodeMissingDomain               = evidence.EvidenceCodeMissingDomain
	EvidenceCodeDuplicateDomain             = evidence.EvidenceCodeDuplicateDomain
	EvidenceCodeThresholdNotMet             = evidence.EvidenceCodeThresholdNotMet
	EvidenceCodeForbiddenExclusion          = evidence.EvidenceCodeForbiddenExclusion
	EvidenceCodeSafetyMutantSurvived        = evidence.EvidenceCodeSafetyMutantSurvived
	EvidenceCodeResultFailed                = evidence.EvidenceCodeResultFailed
	EvidenceCodeInvalidArchitecture         = evidence.EvidenceCodeInvalidArchitecture
	EvidenceCodeReuseDenied                 = evidence.EvidenceCodeReuseDenied
	EvidenceCodeFullExecutionRequired       = evidence.EvidenceCodeFullExecutionRequired
	EvidenceCodeFeatureLaneCannotRelease    = evidence.EvidenceCodeFeatureLaneCannotRelease
	EvidenceCodeWrongSigningProfile         = evidence.EvidenceCodeWrongSigningProfile
	EvidenceCodeWrongSigningIdentity        = evidence.EvidenceCodeWrongSigningIdentity
	EvidenceCodeWrongSignature              = evidence.EvidenceCodeWrongSignature
	EvidenceCodeStaleGeneration             = evidence.EvidenceCodeStaleGeneration
	EvidenceCodeFutureGeneration            = evidence.EvidenceCodeFutureGeneration
	EvidenceCodeStaleExpiry                 = evidence.EvidenceCodeStaleExpiry
	EvidenceCodeFutureExpiry                = evidence.EvidenceCodeFutureExpiry
	EvidenceCodeExpired                     = evidence.EvidenceCodeExpired
	EvidenceCodeInvalidSignature            = evidence.EvidenceCodeInvalidSignature
	EvidenceCodeSignatureVerificationFailed = evidence.EvidenceCodeSignatureVerificationFailed
	EvidenceCodeArithmeticOverflow          = evidence.EvidenceCodeArithmeticOverflow
)

func EvidenceTreeIdTryCreate(value string, maximumLength int) (EvidenceTreeId, bool) {
	return evidence.EvidenceTreeIdTryCreate(value, maximumLength)
}
func EvidenceDependencyLockIdTryCreate(value string, maximumLength int) (EvidenceDependencyLockId, bool) {
	return evidence.EvidenceDependencyLockIdTryCreate(value, maximumLength)
}
func EvidenceSchemaIdTryCreate(value string, maximumLength int) (EvidenceSchemaId, bool) {
	return evidence.EvidenceSchemaIdTryCreate(value, maximumLength)
}
func EvidenceTestBinaryIdTryCreate(value string, maximumLength int) (EvidenceTestBinaryId, bool) {
	return evidence.EvidenceTestBinaryIdTryCreate(value, maximumLength)
}
func EvidenceArtifactIdTryCreate(value string, maximumLength int) (EvidenceArtifactId, bool) {
	return evidence.EvidenceArtifactIdTryCreate(value, maximumLength)
}
func EvidenceSuiteIdTryCreate(value string, maximumLength int) (EvidenceSuiteId, bool) {
	return evidence.EvidenceSuiteIdTryCreate(value, maximumLength)
}
func EvidenceTraceIdTryCreate(value string, maximumLength int) (EvidenceTraceId, bool) {
	return evidence.EvidenceTraceIdTryCreate(value, maximumLength)
}
func EvidenceFuzzTargetIdTryCreate(value string, maximumLength int) (EvidenceFuzzTargetId, bool) {
	return evidence.EvidenceFuzzTargetIdTryCreate(value, maximumLength)
}
func EvidenceCorpusIdTryCreate(value string, maximumLength int) (EvidenceCorpusId, bool) {
	return evidence.EvidenceCorpusIdTryCreate(value, maximumLength)
}
func EvidenceL0CIdTryCreate(value string, maximumLength int) (EvidenceL0CId, bool) {
	return evidence.EvidenceL0CIdTryCreate(value, maximumLength)
}
func EvidenceApproverIdTryCreate(value string, maximumLength int) (EvidenceApproverId, bool) {
	return evidence.EvidenceApproverIdTryCreate(value, maximumLength)
}
func EvidenceSigningProfileIdTryCreate(value string, maximumLength int) (EvidenceSigningProfileId, bool) {
	return evidence.EvidenceSigningProfileIdTryCreate(value, maximumLength)
}
func EvidenceSigningIdentityIdTryCreate(value string, maximumLength int) (EvidenceSigningIdentityId, bool) {
	return evidence.EvidenceSigningIdentityIdTryCreate(value, maximumLength)
}
func EvidenceSignatureIdTryCreate(value string, maximumLength int) (EvidenceSignatureId, bool) {
	return evidence.EvidenceSignatureIdTryCreate(value, maximumLength)
}
func EvidenceManifestIdTryCreate(value string, maximumLength int) (EvidenceManifestId, bool) {
	return evidence.EvidenceManifestIdTryCreate(value, maximumLength)
}
func EvidenceExclusionIdTryCreate(value string, maximumLength int) (EvidenceExclusionId, bool) {
	return evidence.EvidenceExclusionIdTryCreate(value, maximumLength)
}
func EvidenceSha256TryCreate(source []byte) (EvidenceSha256, bool) {
	return evidence.EvidenceSha256TryCreate(source)
}
func EvidenceCountTryCreate(value uint64) (EvidenceCount, bool) {
	return evidence.EvidenceCountTryCreate(value)
}
func EvidencePercentageTryCreate(value uint16) (EvidencePercentage, bool) {
	return evidence.EvidencePercentageTryCreate(value)
}
func EvidenceNonNegativeCountTryCreate(value uint64) (EvidenceNonNegativeCount, bool) {
	return evidence.EvidenceNonNegativeCountTryCreate(value)
}
func EvidenceDurationSecondsTryCreate(value uint64) (EvidenceDurationSeconds, bool) {
	return evidence.EvidenceDurationSecondsTryCreate(value)
}
func EvidenceGenerationTryCreate(value uint64) (EvidenceGeneration, bool) {
	return evidence.EvidenceGenerationTryCreate(value)
}
func EvidenceSequenceTryCreate(value uint64) (EvidenceSequence, bool) {
	return evidence.EvidenceSequenceTryCreate(value)
}
func NewEvidenceOpaqueSignature(bytes []byte, maximumBytes int) EvidenceOpaqueSignature {
	return evidence.NewEvidenceOpaqueSignature(bytes, maximumBytes)
}

func evidenceValidId(value string, maximumLength int) bool {
	return evidence.EvidenceValidID(value, maximumLength)
}
func evidenceLaneIsDefined(value EvidenceLane) bool { return evidence.LaneIsDefined(value) }
func evidenceExecutionKindIsDefined(value EvidenceExecutionKind) bool {
	return evidence.ExecutionKindIsDefined(value)
}
func evidenceDomainIsDefined(value EvidenceDomain) bool { return evidence.DomainIsDefined(value) }
func evidenceArchitectureIsDefined(value EvidenceArchitecture) bool {
	return evidence.ArchitectureIsDefined(value)
}
func evidenceResultIsDefined(value EvidenceResult) bool { return evidence.ResultIsDefined(value) }
func evidenceExclusionKindIsDefined(value EvidenceExclusionKind) bool {
	return evidence.ExclusionKindIsDefined(value)
}
func evidenceChangeKindIsDefined(value EvidenceChangeKind) bool {
	return evidence.ChangeKindIsDefined(value)
}
func evidenceGateTargetIsDefined(value EvidenceGateTarget) bool {
	return evidence.GateTargetIsDefined(value)
}
func evidenceCollectionsSnapshot[T any](source []T, maximum int, requireNonEmpty bool) ([]T, bool) {
	return evidence.CollectionsSnapshot(source, maximum, requireNonEmpty)
}
