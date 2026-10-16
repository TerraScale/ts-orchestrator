package bootstrap

import (
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// HistoricalManifest proves that a manifest was validly signed for its exact
// scope and signed interval. It does not authorize current bootstrap actions
// or restart. Restart callers must separately verify the private
// accepted-install marker, exact self-instance and VNIC identity, unchanged
// installed binary and local material, and live TLS/JWT validity.
type HistoricalManifest struct {
	manifest      Manifest
	envelope      trust.Envelope
	digest        string
	delegation    trust.VerifiedDelegation
	hasDelegation bool
	issuedAt      time.Time
	expiresAt     time.Time
	verified      bool
}

// Manifest returns a defensive copy of the historically verified manifest.
func (verified HistoricalManifest) Manifest() Manifest { return cloneManifest(verified.manifest) }

// Digest returns the canonical root-signed envelope digest.
func (verified HistoricalManifest) Digest() string { return verified.digest }

// Profile returns the historically authorized launch profile for one slot.
func (verified HistoricalManifest) Profile(slot string) (LaunchProfile, bool) {
	if !verified.verified {
		return LaunchProfile{}, false
	}
	profile, ok := manifestProfile(verified.manifest, slot)
	if !ok {
		return LaunchProfile{}, false
	}
	return cloneProfile(profile), true
}

// VerifyHistoricalManifest verifies root authorization, exact manifest scope,
// bounded signed validity, and any historical peer receipt delegation. The
// returned proof records no current authorization.
func VerifyHistoricalManifest(envelope trust.Envelope, roots trust.Keyring, expected ManifestExpectation, policy trust.Policy) (HistoricalManifest, error) {
	if err := validateManifestEnvelopeSize(envelope); err != nil {
		return HistoricalManifest{}, err
	}
	if err := expected.validate(); err != nil {
		return HistoricalManifest{}, err
	}
	scope := manifestScope(expected.DeploymentID, string(expected.Cell), expected.Environment, "controller", expected.Slot)
	payload, err := trust.VerifyHistorical(envelope, scope, roots, policy)
	if err != nil {
		return HistoricalManifest{}, fmt.Errorf("verify historical bootstrap manifest signature: %w", err)
	}
	if len(payload) > MaxManifestBytes {
		return HistoricalManifest{}, fmt.Errorf("%w: manifest exceeds its size limit", ErrManifestInvalid)
	}
	manifest, digest, err := verifiedManifestPayload(envelope, payload, expected)
	if err != nil {
		return HistoricalManifest{}, err
	}
	verified := HistoricalManifest{
		manifest: cloneManifest(manifest), envelope: cloneEnvelope(envelope), digest: digest,
		issuedAt: envelope.IssuedAt, expiresAt: envelope.ExpiresAt, verified: true,
	}
	if manifest.PeerReceiptDelegation != nil {
		delegation, err := trust.VerifyDelegationHistorical(*manifest.PeerReceiptDelegation, roots, policy)
		if err != nil {
			return HistoricalManifest{}, fmt.Errorf("verify historical peer receipt delegation: %w", err)
		}
		if err := validatePeerDelegation(manifest, delegation); err != nil {
			return HistoricalManifest{}, err
		}
		verified.delegation = delegation
		verified.hasDelegation = true
	}
	return verified, nil
}

func validateHistoricalManifest(manifest HistoricalManifest) error {
	if !manifest.verified || manifest.digest == "" || manifest.manifest.Validate() != nil {
		return fmt.Errorf("%w: historical manifest proof is absent or invalid", ErrManifestInvalid)
	}
	return nil
}

// HistoricalReceipt proves that a receipt was validly signed and matched the
// supplied authenticated facts within its manifest's signed interval. It does
// not authorize a restart or any other current action; restart callers must
// separately verify the accepted-install marker, exact self-instance and VNIC
// identity, unchanged installed binary and local material, and live TLS/JWT
// validity.
type HistoricalReceipt struct {
	receipt        Receipt
	manifestDigest string
	issuedAt       time.Time
	expiresAt      time.Time
	verified       bool
}

// Receipt returns a value copy of the historically verified receipt.
func (verified HistoricalReceipt) Receipt() Receipt { return verified.receipt }

// InstanceOCID returns the exact instance identity bound by the receipt.
func (verified HistoricalReceipt) InstanceOCID() string { return verified.receipt.InstanceOCID }

// Slot returns the exact controller slot bound by the receipt.
func (verified HistoricalReceipt) Slot() string { return verified.receipt.Slot }

// ManifestDigest returns the root-authorized manifest digest bound by the receipt.
func (verified HistoricalReceipt) ManifestDigest() string { return verified.manifestDigest }
