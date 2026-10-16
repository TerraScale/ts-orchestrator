package release

import (
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// NetBirdImageScope gives the image signer a dedicated NetBird capability.
func NetBirdImageScope(receipt ImageReceipt, environment string) trust.Scope {
	scope := ImageScope(receipt, environment)
	scope.Role = "netbird-manager"
	scope.Slot = NetBirdProductionRuntime + "/linux-arm64"
	return scope
}

// VerifyNetBirdImageCurrent admits only an exact GRU ARM64 NetBird foundation
// image with its own independent runtime qualification.
func VerifyNetBirdImageCurrent(envelopeWire, delegationWire []byte, roots trust.Keyring,
	expected ImageExpectation, now time.Time,
) (VerifiedImage, error) {
	if err := validateImageExpectation(expected); err != nil {
		return VerifiedImage{}, err
	}
	if expected.LogicalRegion != "GRU" || expected.Architecture != "arm64" || expected.OCIImageOCID == "" {
		return VerifiedImage{}, fmt.Errorf("%w: NetBird requires an exact GRU ARM64 image", ErrExpectationMismatch)
	}
	envelope, delegationEnvelope, err := decodeEnvelopePair(envelopeWire, delegationWire)
	if err != nil {
		return VerifiedImage{}, err
	}
	receipt, err := decodeCanonicalPayload[ImageReceipt](envelope.Payload)
	if err != nil {
		return VerifiedImage{}, err
	}
	if err := receipt.Validate(); err != nil {
		return VerifiedImage{}, err
	}
	if err := matchImageExpectation(receipt, expected); err != nil {
		return VerifiedImage{}, err
	}
	delegation, err := trust.VerifyDelegationCurrent(delegationEnvelope, roots, now, delegationPolicy())
	if err != nil {
		return VerifiedImage{}, fmt.Errorf("verify current NetBird image delegation: %w", err)
	}
	if _, err := trust.VerifyDelegatedCurrent(envelope, NetBirdImageScope(receipt, expected.Environment), delegation, now, receiptPolicy()); err != nil {
		return VerifiedImage{}, fmt.Errorf("verify current signed NetBird image: %w", err)
	}
	production, ok := receipt.HostProduction["netbird-manager"]
	if !ok {
		return VerifiedImage{}, fmt.Errorf("%w: missing independent NetBird image qualification", ErrProductionQualification)
	}
	candidate := ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256,
		QualificationSHA256: receipt.QualificationSHA256, Cell: receipt.OCIRegion, Environment: expected.Environment,
		Runtime: NetBirdProductionRuntime, Architecture: receipt.Architecture, Role: "netbird-manager"}
	if _, err := VerifyProductionCurrent(production.Qualification, production.Delegation, roots, candidate, now); err != nil {
		return VerifiedImage{}, err
	}
	proof, err := proofFor(envelope)
	if err != nil {
		return VerifiedImage{}, err
	}
	// Every authority must be current; the shortest interval bounds admission.
	for _, wire := range [][]byte{delegationWire, production.Qualification, production.Delegation} {
		if len(wire) == 0 {
			continue
		}
		authority, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return VerifiedImage{}, err
		}
		if authority.ExpiresAt.Before(proof.expiresAt) {
			proof.expiresAt = authority.ExpiresAt
		}
	}
	return VerifiedImage{receipt: receipt, proof: proof}, nil
}
