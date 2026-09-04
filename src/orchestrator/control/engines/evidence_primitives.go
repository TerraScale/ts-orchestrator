package engines

func evidenceValidId(value string, maximumLength int) bool {
	if maximumLength <= 0 || len(value) == 0 || len(value) > maximumLength {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		isAlnum := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !isAlnum && c != '-' && c != '_' && c != '.' && c != '/' && c != ':' {
			return false
		}
	}
	return true
}

// evidenceIdentity is the Go form of the abstract EvidenceIdentity record.
type evidenceIdentity struct {
	Value string
	valid bool
}

func (i evidenceIdentity) IsValid() bool { return i.valid }

type EvidenceTreeId struct{ evidenceIdentity }

func EvidenceTreeIdTryCreate(value string, maximumLength int) (EvidenceTreeId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceTreeId{}, false
	}
	return EvidenceTreeId{evidenceIdentity{value, true}}, true
}

type EvidenceDependencyLockId struct{ evidenceIdentity }

func EvidenceDependencyLockIdTryCreate(value string, maximumLength int) (EvidenceDependencyLockId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceDependencyLockId{}, false
	}
	return EvidenceDependencyLockId{evidenceIdentity{value, true}}, true
}

type EvidenceSchemaId struct{ evidenceIdentity }

func EvidenceSchemaIdTryCreate(value string, maximumLength int) (EvidenceSchemaId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceSchemaId{}, false
	}
	return EvidenceSchemaId{evidenceIdentity{value, true}}, true
}

type EvidenceTestBinaryId struct{ evidenceIdentity }

func EvidenceTestBinaryIdTryCreate(value string, maximumLength int) (EvidenceTestBinaryId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceTestBinaryId{}, false
	}
	return EvidenceTestBinaryId{evidenceIdentity{value, true}}, true
}

type EvidenceArtifactId struct{ evidenceIdentity }

func EvidenceArtifactIdTryCreate(value string, maximumLength int) (EvidenceArtifactId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceArtifactId{}, false
	}
	return EvidenceArtifactId{evidenceIdentity{value, true}}, true
}

type EvidenceSuiteId struct{ evidenceIdentity }

func EvidenceSuiteIdTryCreate(value string, maximumLength int) (EvidenceSuiteId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceSuiteId{}, false
	}
	return EvidenceSuiteId{evidenceIdentity{value, true}}, true
}

type EvidenceTraceId struct{ evidenceIdentity }

func EvidenceTraceIdTryCreate(value string, maximumLength int) (EvidenceTraceId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceTraceId{}, false
	}
	return EvidenceTraceId{evidenceIdentity{value, true}}, true
}

type EvidenceFuzzTargetId struct{ evidenceIdentity }

func EvidenceFuzzTargetIdTryCreate(value string, maximumLength int) (EvidenceFuzzTargetId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceFuzzTargetId{}, false
	}
	return EvidenceFuzzTargetId{evidenceIdentity{value, true}}, true
}

type EvidenceCorpusId struct{ evidenceIdentity }

func EvidenceCorpusIdTryCreate(value string, maximumLength int) (EvidenceCorpusId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceCorpusId{}, false
	}
	return EvidenceCorpusId{evidenceIdentity{value, true}}, true
}

type EvidenceL0CId struct{ evidenceIdentity }

func EvidenceL0CIdTryCreate(value string, maximumLength int) (EvidenceL0CId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceL0CId{}, false
	}
	return EvidenceL0CId{evidenceIdentity{value, true}}, true
}

type EvidenceApproverId struct{ evidenceIdentity }

func EvidenceApproverIdTryCreate(value string, maximumLength int) (EvidenceApproverId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceApproverId{}, false
	}
	return EvidenceApproverId{evidenceIdentity{value, true}}, true
}

type EvidenceSigningProfileId struct{ evidenceIdentity }

func EvidenceSigningProfileIdTryCreate(value string, maximumLength int) (EvidenceSigningProfileId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceSigningProfileId{}, false
	}
	return EvidenceSigningProfileId{evidenceIdentity{value, true}}, true
}

type EvidenceSigningIdentityId struct{ evidenceIdentity }

func EvidenceSigningIdentityIdTryCreate(value string, maximumLength int) (EvidenceSigningIdentityId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceSigningIdentityId{}, false
	}
	return EvidenceSigningIdentityId{evidenceIdentity{value, true}}, true
}

type EvidenceSignatureId struct{ evidenceIdentity }

func EvidenceSignatureIdTryCreate(value string, maximumLength int) (EvidenceSignatureId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceSignatureId{}, false
	}
	return EvidenceSignatureId{evidenceIdentity{value, true}}, true
}

type EvidenceManifestId struct{ evidenceIdentity }

func EvidenceManifestIdTryCreate(value string, maximumLength int) (EvidenceManifestId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceManifestId{}, false
	}
	return EvidenceManifestId{evidenceIdentity{value, true}}, true
}

type EvidenceExclusionId struct{ evidenceIdentity }

func EvidenceExclusionIdTryCreate(value string, maximumLength int) (EvidenceExclusionId, bool) {
	if !evidenceValidId(value, maximumLength) {
		return EvidenceExclusionId{}, false
	}
	return EvidenceExclusionId{evidenceIdentity{value, true}}, true
}

type EvidenceSha256 struct {
	bytes [32]byte
}

func EvidenceSha256TryCreate(source []byte) (EvidenceSha256, bool) {
	if len(source) != 32 {
		return EvidenceSha256{}, false
	}
	var digest EvidenceSha256
	copy(digest.bytes[:], source)
	return digest, true
}

func (d EvidenceSha256) CopyBytes() []byte {
	copied := make([]byte, 32)
	copy(copied, d.bytes[:])
	return copied
}

func (d EvidenceSha256) Equal(other EvidenceSha256) bool { return d.bytes == other.bytes }

type EvidenceCount struct{ Value uint64 }

func (c EvidenceCount) IsValid() bool { return c.Value > 0 }

func EvidenceCountTryCreate(value uint64) (EvidenceCount, bool) {
	if value > 0 {
		return EvidenceCount{value}, true
	}
	return EvidenceCount{}, false
}

type EvidencePercentage struct{ Value uint16 }

func (p EvidencePercentage) IsValid() bool { return p.Value <= 100 }

func EvidencePercentageTryCreate(value uint16) (EvidencePercentage, bool) {
	if value <= 100 {
		return EvidencePercentage{value}, true
	}
	return EvidencePercentage{}, false
}

type EvidenceNonNegativeCount struct{ Value uint64 }

func (c EvidenceNonNegativeCount) IsValid() bool { return true }

func EvidenceNonNegativeCountTryCreate(value uint64) (EvidenceNonNegativeCount, bool) {
	return EvidenceNonNegativeCount{value}, true
}

type EvidenceDurationSeconds struct{ Value uint64 }

func (d EvidenceDurationSeconds) IsValid() bool { return d.Value > 0 }

func EvidenceDurationSecondsTryCreate(value uint64) (EvidenceDurationSeconds, bool) {
	if value > 0 {
		return EvidenceDurationSeconds{value}, true
	}
	return EvidenceDurationSeconds{}, false
}

type EvidenceGeneration struct{ Value uint64 }

func (g EvidenceGeneration) IsValid() bool { return g.Value > 0 }

func EvidenceGenerationTryCreate(value uint64) (EvidenceGeneration, bool) {
	if value > 0 {
		return EvidenceGeneration{value}, true
	}
	return EvidenceGeneration{}, false
}

type EvidenceSequence struct{ Value uint64 }

func (s EvidenceSequence) IsValid() bool { return s.Value > 0 }

func EvidenceSequenceTryCreate(value uint64) (EvidenceSequence, bool) {
	if value > 0 {
		return EvidenceSequence{value}, true
	}
	return EvidenceSequence{}, false
}

type EvidenceLane int

const (
	EvidenceLaneUnknown EvidenceLane = 0
	EvidenceLaneFeature EvidenceLane = 1
	EvidenceLaneFull    EvidenceLane = 2
)

func evidenceLaneIsDefined(v EvidenceLane) bool {
	return v >= EvidenceLaneUnknown && v <= EvidenceLaneFull
}

type EvidenceExecutionKind int

const (
	EvidenceExecutionKindUnknown               EvidenceExecutionKind = 0
	EvidenceExecutionKindCold                  EvidenceExecutionKind = 1
	EvidenceExecutionKindContentAddressedReuse EvidenceExecutionKind = 2
)

func evidenceExecutionKindIsDefined(v EvidenceExecutionKind) bool {
	return v >= EvidenceExecutionKindUnknown && v <= EvidenceExecutionKindContentAddressedReuse
}

type EvidenceDomain int

const (
	EvidenceDomainUnknown       EvidenceDomain = 0
	EvidenceDomainControl       EvidenceDomain = 1
	EvidenceDomainScheduling    EvidenceDomain = 2
	EvidenceDomainMessaging     EvidenceDomain = 3
	EvidenceDomainCompute       EvidenceDomain = 4
	EvidenceDomainStorage       EvidenceDomain = 5
	EvidenceDomainTerraBase     EvidenceDomain = 6
	EvidenceDomainSecurity      EvidenceDomain = 7
	EvidenceDomainDelivery      EvidenceDomain = 8
	EvidenceDomainObservability EvidenceDomain = 9
	EvidenceDomainNetworking    EvidenceDomain = 10
	EvidenceDomainBudgets       EvidenceDomain = 11
	EvidenceDomainProvisioning  EvidenceDomain = 12
	EvidenceDomainRuntime       EvidenceDomain = 13
)

func evidenceDomainIsDefined(v EvidenceDomain) bool {
	return v >= EvidenceDomainUnknown && v <= EvidenceDomainRuntime
}

type EvidenceArchitecture int

const (
	EvidenceArchitectureUnknown    EvidenceArchitecture = 0
	EvidenceArchitectureLinuxX64   EvidenceArchitecture = 1
	EvidenceArchitectureLinuxArm64 EvidenceArchitecture = 2
)

func evidenceArchitectureIsDefined(v EvidenceArchitecture) bool {
	return v >= EvidenceArchitectureUnknown && v <= EvidenceArchitectureLinuxArm64
}

type EvidenceResult int

const (
	EvidenceResultUnknown EvidenceResult = 0
	EvidenceResultPassed  EvidenceResult = 1
	EvidenceResultFailed  EvidenceResult = 2
)

func evidenceResultIsDefined(v EvidenceResult) bool {
	return v >= EvidenceResultUnknown && v <= EvidenceResultFailed
}

type EvidenceExclusionKind int

const (
	EvidenceExclusionKindUnknown               EvidenceExclusionKind = 0
	EvidenceExclusionKindGeneratedCode         EvidenceExclusionKind = 1
	EvidenceExclusionKindTrivialWiring         EvidenceExclusionKind = 2
	EvidenceExclusionKindSafety                EvidenceExclusionKind = 3
	EvidenceExclusionKindAuthorization         EvidenceExclusionKind = 4
	EvidenceExclusionKindDurability            EvidenceExclusionKind = 5
	EvidenceExclusionKindDeletion              EvidenceExclusionKind = 6
	EvidenceExclusionKindStateTransition       EvidenceExclusionKind = 7
	EvidenceExclusionKindValidation            EvidenceExclusionKind = 8
	EvidenceExclusionKindOwnership             EvidenceExclusionKind = 9
	EvidenceExclusionKindFencing               EvidenceExclusionKind = 10
	EvidenceExclusionKindRetry                 EvidenceExclusionKind = 11
	EvidenceExclusionKindCompensation          EvidenceExclusionKind = 12
	EvidenceExclusionKindAdapterClassification EvidenceExclusionKind = 13
)

func evidenceExclusionKindIsDefined(v EvidenceExclusionKind) bool {
	return v >= EvidenceExclusionKindUnknown && v <= EvidenceExclusionKindAdapterClassification
}

type EvidenceChangeKind int

const (
	EvidenceChangeKindUnknown            EvidenceChangeKind = 0
	EvidenceChangeKindNone               EvidenceChangeKind = 1
	EvidenceChangeKindShardOnly          EvidenceChangeKind = 2
	EvidenceChangeKindSharedContract     EvidenceChangeKind = 3
	EvidenceChangeKindSecurity           EvidenceChangeKind = 4
	EvidenceChangeKindToolchain          EvidenceChangeKind = 5
	EvidenceChangeKindColdFirstCandidate EvidenceChangeKind = 6
)

func evidenceChangeKindIsDefined(v EvidenceChangeKind) bool {
	return v >= EvidenceChangeKindUnknown && v <= EvidenceChangeKindColdFirstCandidate
}

type EvidenceGateTarget int

const (
	EvidenceGateTargetUnknown               EvidenceGateTarget = 0
	EvidenceGateTargetDependencyConformance EvidenceGateTarget = 1
	EvidenceGateTargetL1SCredentialRelease  EvidenceGateTarget = 2
)

func evidenceGateTargetIsDefined(v EvidenceGateTarget) bool {
	return v >= EvidenceGateTargetUnknown && v <= EvidenceGateTargetL1SCredentialRelease
}

type EvidenceAction int

const (
	EvidenceActionUnknown                    EvidenceAction = 0
	EvidenceActionHold                       EvidenceAction = 1
	EvidenceActionAllowDependencyConformance EvidenceAction = 2
	EvidenceActionAllowL1SCredentialRelease  EvidenceAction = 3
)

type EvidenceCode int

const (
	EvidenceCodeUnknown                     EvidenceCode = 0
	EvidenceCodeAllowed                     EvidenceCode = 1
	EvidenceCodeInvalidInput                EvidenceCode = 2
	EvidenceCodeWrongSubject                EvidenceCode = 3
	EvidenceCodeMissingDomain               EvidenceCode = 4
	EvidenceCodeDuplicateDomain             EvidenceCode = 5
	EvidenceCodeThresholdNotMet             EvidenceCode = 6
	EvidenceCodeForbiddenExclusion          EvidenceCode = 7
	EvidenceCodeSafetyMutantSurvived        EvidenceCode = 8
	EvidenceCodeResultFailed                EvidenceCode = 9
	EvidenceCodeInvalidArchitecture         EvidenceCode = 10
	EvidenceCodeReuseDenied                 EvidenceCode = 11
	EvidenceCodeFullExecutionRequired       EvidenceCode = 12
	EvidenceCodeFeatureLaneCannotRelease    EvidenceCode = 13
	EvidenceCodeWrongSigningProfile         EvidenceCode = 14
	EvidenceCodeWrongSigningIdentity        EvidenceCode = 15
	EvidenceCodeWrongSignature              EvidenceCode = 16
	EvidenceCodeStaleGeneration             EvidenceCode = 17
	EvidenceCodeFutureGeneration            EvidenceCode = 18
	EvidenceCodeStaleExpiry                 EvidenceCode = 19
	EvidenceCodeFutureExpiry                EvidenceCode = 20
	EvidenceCodeExpired                     EvidenceCode = 21
	EvidenceCodeInvalidSignature            EvidenceCode = 22
	EvidenceCodeSignatureVerificationFailed EvidenceCode = 23
	EvidenceCodeArithmeticOverflow          EvidenceCode = 24
)

type EvidenceOpaqueSignature struct {
	bytes   []byte
	isValid bool
}

func NewEvidenceOpaqueSignature(bytes []byte, maximumBytes int) EvidenceOpaqueSignature {
	isValid := maximumBytes > 0 && len(bytes) > 0 && len(bytes) <= maximumBytes
	if !isValid {
		return EvidenceOpaqueSignature{bytes: []byte{}, isValid: false}
	}
	copied := make([]byte, len(bytes))
	copy(copied, bytes)
	return EvidenceOpaqueSignature{bytes: copied, isValid: true}
}

func (s EvidenceOpaqueSignature) IsValid() bool { return s.isValid }

func (s EvidenceOpaqueSignature) CopyBytes() []byte {
	copied := make([]byte, len(s.bytes))
	copy(copied, s.bytes)
	return copied
}

// evidenceCollectionsSnapshot ports the internal EvidenceCollections.Snapshot.
func evidenceCollectionsSnapshot[T any](source []T, maximum int, requireNonEmpty bool) ([]T, bool) {
	if source == nil || maximum <= 0 {
		return []T{}, false
	}
	count := len(source)
	if count > maximum {
		count = maximum
	}
	result := make([]T, count)
	copy(result, source[:count])
	return result, !requireNonEmpty || count > 0
}
