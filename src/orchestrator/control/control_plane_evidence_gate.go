// Port of src/TerraScale.Orchestrator/ControlPlane/Evidence/EvidenceGate.cs
package control

type EvidenceSignatureVerificationOutcome int

const (
	EvidenceSignatureVerificationOutcomeUnknown EvidenceSignatureVerificationOutcome = 0
	EvidenceSignatureVerificationOutcomeValid   EvidenceSignatureVerificationOutcome = 1
	EvidenceSignatureVerificationOutcomeInvalid EvidenceSignatureVerificationOutcome = 2
)

type EvidenceSignedMaterial struct {
	PayloadDigest     EvidenceSha256
	SigningProfile    EvidenceSigningProfileId
	SigningIdentity   EvidenceSigningIdentityId
	SignatureIdentity EvidenceSignatureId
	Generation        EvidenceGeneration
	ExpirySequence    EvidenceSequence
}

type EvidenceSignedEnvelope struct {
	Material     EvidenceSignedMaterial
	Signature    EvidenceOpaqueSignature
	IsWellFormed bool
}

func NewEvidenceSignedEnvelope(material EvidenceSignedMaterial, signature EvidenceOpaqueSignature) *EvidenceSignedEnvelope {
	wellFormed := !material.PayloadDigest.Equal(EvidenceSha256{}) &&
		material.SigningProfile.IsValid() && material.SigningIdentity.IsValid() &&
		material.SignatureIdentity.IsValid() && material.Generation.IsValid() &&
		material.ExpirySequence.IsValid() && signature.IsValid()
	return &EvidenceSignedEnvelope{Material: material, Signature: signature, IsWellFormed: wellFormed}
}

// IEvidenceSignatureVerifier ports the verifier interface.
type IEvidenceSignatureVerifier interface {
	Verify(material EvidenceSignedMaterial, signature EvidenceOpaqueSignature) EvidenceSignatureVerificationOutcome
}

type EvidenceGateContext struct {
	ExpectedManifest          EvidenceManifestId
	ExpectedSubject           *EvidenceSubject
	ExpectedPayloadDigest     EvidenceSha256
	ExpectedSigningProfile    EvidenceSigningProfileId
	ExpectedSigningIdentity   EvidenceSigningIdentityId
	ExpectedSignatureIdentity EvidenceSignatureId
	ExpectedGeneration        EvidenceGeneration
	ExpectedExpirySequence    EvidenceSequence
	CurrentSequence           EvidenceSequence
	Target                    EvidenceGateTarget
	Verifier                  IEvidenceSignatureVerifier
	IsWellFormed              bool
}

func NewEvidenceGateContext(expectedManifest EvidenceManifestId, expectedSubject *EvidenceSubject,
	expectedPayloadDigest EvidenceSha256, expectedSigningProfile EvidenceSigningProfileId,
	expectedSigningIdentity EvidenceSigningIdentityId, expectedSignatureIdentity EvidenceSignatureId,
	expectedGeneration EvidenceGeneration, expectedExpirySequence EvidenceSequence,
	currentSequence EvidenceSequence, target EvidenceGateTarget,
	verifier IEvidenceSignatureVerifier) *EvidenceGateContext {
	wellFormed := expectedManifest.IsValid() && expectedSubject != nil && expectedSubject.IsWellFormed &&
		expectedSigningProfile.IsValid() && expectedSigningIdentity.IsValid() &&
		expectedSignatureIdentity.IsValid() && expectedGeneration.IsValid() &&
		expectedExpirySequence.IsValid() && currentSequence.IsValid() &&
		evidenceGateTargetIsDefined(target) && target != EvidenceGateTargetUnknown && verifier != nil
	return &EvidenceGateContext{ExpectedManifest: expectedManifest, ExpectedSubject: expectedSubject,
		ExpectedPayloadDigest: expectedPayloadDigest, ExpectedSigningProfile: expectedSigningProfile,
		ExpectedSigningIdentity: expectedSigningIdentity, ExpectedSignatureIdentity: expectedSignatureIdentity,
		ExpectedGeneration: expectedGeneration, ExpectedExpirySequence: expectedExpirySequence,
		CurrentSequence: currentSequence, Target: target, Verifier: verifier, IsWellFormed: wellFormed}
}

type EvidenceNumericTrace struct {
	Generation      EvidenceGeneration
	CurrentSequence EvidenceSequence
	ExpirySequence  EvidenceSequence
	DomainCount     uint64
	TestBinaryCount uint64
}

type EvidenceDecisionSubject struct {
	PayloadDigest EvidenceSha256
	Report        *EvidenceSubject
}

func (s *EvidenceDecisionSubject) Equal(other *EvidenceDecisionSubject) bool {
	return other != nil && s.PayloadDigest.Equal(other.PayloadDigest) && s.Report.ExactEquals(other.Report)
}

type EvidenceAuthorizationScope struct {
	Manifest          EvidenceManifestId
	Lane              EvidenceLane
	Target            EvidenceGateTarget
	SigningProfile    EvidenceSigningProfileId
	SigningIdentity   EvidenceSigningIdentityId
	SignatureIdentity EvidenceSignatureId
	Generation        EvidenceGeneration
	ExpirySequence    EvidenceSequence
}

type EvidenceDecision struct {
	Action             EvidenceAction
	Code               EvidenceCode
	Subject            *EvidenceDecisionSubject
	Trace              *EvidenceNumericTrace
	AuthorizationScope *EvidenceAuthorizationScope
}

func (d EvidenceDecision) IsAuthorized() bool {
	return d.Action == EvidenceActionAllowDependencyConformance ||
		d.Action == EvidenceActionAllowL1SCredentialRelease
}

func evidenceDecisionHold(code EvidenceCode, trace *EvidenceNumericTrace) EvidenceDecision {
	return EvidenceDecision{Action: EvidenceActionHold, Code: code, Trace: trace}
}

func evidenceDecisionAllow(action EvidenceAction, digest EvidenceSha256, report *EvidenceSubject,
	scope EvidenceAuthorizationScope, trace EvidenceNumericTrace) EvidenceDecision {
	return EvidenceDecision{Action: action, Code: EvidenceCodeAllowed,
		Subject:            &EvidenceDecisionSubject{PayloadDigest: digest, Report: report},
		AuthorizationScope: &scope, Trace: &trace}
}

// PreDeploymentEvidenceGate ports the pre-deployment evidence gate.
var PreDeploymentEvidenceGate preDeploymentEvidenceGate

type preDeploymentEvidenceGate struct{}

func (preDeploymentEvidenceGate) Verify(manifest *EvidenceManifest, policy *EvidencePolicy,
	envelope *EvidenceSignedEnvelope, context *EvidenceGateContext) EvidenceDecision {
	if manifest == nil || !manifest.IsWellFormed || policy == nil || !policy.IsWellFormed ||
		envelope == nil || !envelope.IsWellFormed || context == nil || !context.IsWellFormed {
		return evidenceDecisionHold(EvidenceCodeInvalidInput, nil)
	}
	trace := EvidenceNumericTrace{Generation: envelope.Material.Generation,
		CurrentSequence: context.CurrentSequence, ExpirySequence: envelope.Material.ExpirySequence,
		DomainCount:     uint64(len(manifest.Subject.Suites)),
		TestBinaryCount: uint64(len(manifest.Subject.TestBinaries))}
	tracePointer := &trace
	if manifest.Identity != context.ExpectedManifest ||
		!manifest.Subject.ExactEquals(context.ExpectedSubject) ||
		!manifest.CanonicalPayloadDigest.Equal(context.ExpectedPayloadDigest) ||
		!envelope.Material.PayloadDigest.Equal(manifest.CanonicalPayloadDigest) {
		return evidenceDecisionHold(EvidenceCodeWrongSubject, tracePointer)
	}
	policyResult := EvidencePolicyEvaluator.Evaluate(manifest, policy)
	if !policyResult.IsAccepted() {
		return evidenceDecisionHold(policyResult.Code, tracePointer)
	}
	if envelope.Material.SigningProfile != context.ExpectedSigningProfile {
		return evidenceDecisionHold(EvidenceCodeWrongSigningProfile, tracePointer)
	}
	if envelope.Material.SigningIdentity != context.ExpectedSigningIdentity {
		return evidenceDecisionHold(EvidenceCodeWrongSigningIdentity, tracePointer)
	}
	if envelope.Material.SignatureIdentity != context.ExpectedSignatureIdentity {
		return evidenceDecisionHold(EvidenceCodeWrongSignature, tracePointer)
	}
	if envelope.Material.Generation.Value < context.ExpectedGeneration.Value {
		return evidenceDecisionHold(EvidenceCodeStaleGeneration, tracePointer)
	}
	if envelope.Material.Generation.Value > context.ExpectedGeneration.Value {
		return evidenceDecisionHold(EvidenceCodeFutureGeneration, tracePointer)
	}
	if envelope.Material.ExpirySequence.Value < context.ExpectedExpirySequence.Value {
		return evidenceDecisionHold(EvidenceCodeStaleExpiry, tracePointer)
	}
	if envelope.Material.ExpirySequence.Value > context.ExpectedExpirySequence.Value {
		return evidenceDecisionHold(EvidenceCodeFutureExpiry, tracePointer)
	}
	if context.CurrentSequence.Value > envelope.Material.ExpirySequence.Value {
		return evidenceDecisionHold(EvidenceCodeExpired, tracePointer)
	}
	verification := context.Verifier.Verify(envelope.Material, envelope.Signature)
	if verification == EvidenceSignatureVerificationOutcomeInvalid {
		return evidenceDecisionHold(EvidenceCodeInvalidSignature, tracePointer)
	}
	if verification != EvidenceSignatureVerificationOutcomeValid {
		return evidenceDecisionHold(EvidenceCodeSignatureVerificationFailed, tracePointer)
	}
	if context.Target == EvidenceGateTargetL1SCredentialRelease && manifest.Lane != EvidenceLaneFull {
		return evidenceDecisionHold(EvidenceCodeFeatureLaneCannotRelease, tracePointer)
	}
	action := EvidenceActionAllowL1SCredentialRelease
	if context.Target == EvidenceGateTargetDependencyConformance {
		action = EvidenceActionAllowDependencyConformance
	}
	scope := EvidenceAuthorizationScope{Manifest: manifest.Identity, Lane: manifest.Lane,
		Target: context.Target, SigningProfile: envelope.Material.SigningProfile,
		SigningIdentity:   envelope.Material.SigningIdentity,
		SignatureIdentity: envelope.Material.SignatureIdentity,
		Generation:        envelope.Material.Generation, ExpirySequence: envelope.Material.ExpirySequence}
	return evidenceDecisionAllow(action, manifest.CanonicalPayloadDigest, manifest.Subject, scope, trace)
}
