package bootstrap

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// HistoricalDerivedStartupAuthority verifies the source/grant chain within its
// original signed interval. It grants no current effect capability.
type HistoricalDerivedStartupAuthority struct{ source DerivedStartupAuthority }

func (historical HistoricalDerivedStartupAuthority) Manifest() Manifest {
	return historical.source.Manifest()
}
func (historical HistoricalDerivedStartupAuthority) Digest() string {
	return historical.source.Digest()
}
func (historical HistoricalDerivedStartupAuthority) Profile(slot string) (LaunchProfile, bool) {
	return historical.source.Profile(slot)
}
func (historical HistoricalDerivedStartupAuthority) verifyHistoricalStartupAuthority() error {
	return historical.source.verifyStartupAuthority()
}

func VerifyHistoricalDerivedStartupAuthority(ctx context.Context, grantWire []byte, anchor HistoricalBootstrapAnchor, roots trust.Keyring, client ObjectStorageClient, wire []byte) (HistoricalDerivedStartupAuthority, error) {
	if !anchor.IsVerified() {
		return HistoricalDerivedStartupAuthority{}, ErrManifestInvalid
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchor.Wire())
	if err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	identity := anchor.Anchor()
	// Reuse the full verifier at the original signed instant, exposing only an
	// evidence seal; current admission always verifies again at the real clock.
	original, err := VerifyBootstrapAnchor(anchorEnvelope, roots, BootstrapAnchorExpectation{DeploymentID: identity.DeploymentID, Environment: identity.Environment, Cell: identity.Cell}, envelope.IssuedAt, BootstrapAnchorTrustPolicy())
	if err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	source, err := RestoreDerivedStartupAuthority(ctx, grantWire, original, roots, client, wire, envelope.IssuedAt)
	if err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	return HistoricalDerivedStartupAuthority{source: source}, nil
}

func (authority DerivedStartupAuthority) historical(ctx context.Context, wire []byte) (HistoricalDerivedStartupAuthority, error) {
	if authority.template.bindings != nil && authority.template.bindings.original != nil {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return HistoricalDerivedStartupAuthority{}, err
		}
		proof := authority.template.bindings.original
		source, err := RestoreBoundOriginalDerivedStartupAuthority(ctx, proof.factory, authority.GrantWire(), proof.genesis, authority.template.anchor, authority.template.identity.Cell, authority.client, wire, envelope.IssuedAt)
		if err != nil {
			return HistoricalDerivedStartupAuthority{}, err
		}
		return HistoricalDerivedStartupAuthority{source: source}, nil
	}
	identity := authority.template.anchor.Anchor()
	envelope, err := trust.DecodeEnvelope(authority.template.anchor.Wire())
	if err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	anchor, err := VerifyHistoricalBootstrapAnchor(envelope, authority.template.roots, BootstrapAnchorExpectation{DeploymentID: identity.DeploymentID, Environment: identity.Environment, Cell: identity.Cell}, authority.IssuedAt(), BootstrapAnchorTrustPolicy())
	if err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	return VerifyHistoricalDerivedStartupAuthority(ctx, authority.GrantWire(), anchor, authority.template.roots, authority.client, wire)
}

func verifyHistoricalDerivedReceipt(envelope trust.Envelope, historical HistoricalDerivedStartupAuthority, facts InstanceFacts, seed bool, policy trust.Policy) (HistoricalReceipt, error) {
	if historical.verifyHistoricalStartupAuthority() != nil {
		return HistoricalReceipt{}, ErrReceiptInvalid
	}
	currentAtSigning, err := verifyDerivedReceipt(envelope, historical.source, facts, seed, envelope.IssuedAt, policy)
	if err != nil {
		return HistoricalReceipt{}, err
	}
	return HistoricalReceipt{receipt: currentAtSigning.receipt, manifestDigest: currentAtSigning.manifestDigest, issuedAt: currentAtSigning.issuedAt, expiresAt: currentAtSigning.expiresAt, verified: true}, nil
}
