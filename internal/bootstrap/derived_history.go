package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// HistoricalDerivedStartupAuthority retains signed evidence only; it cannot
// supply a current template, source, Link or startup effect capability.
type HistoricalDerivedStartupAuthority struct{ source derivedStartupEvidence }

func (historical HistoricalDerivedStartupAuthority) Manifest() Manifest {
	return cloneManifest(historical.source.binding.Manifest)
}
func (historical HistoricalDerivedStartupAuthority) Digest() string { return historical.source.digest }
func (historical HistoricalDerivedStartupAuthority) Profile(slot string) (LaunchProfile, bool) {
	if historical.verifyHistoricalStartupAuthority() != nil {
		return LaunchProfile{}, false
	}
	for _, profile := range historical.source.binding.Manifest.Profiles {
		if profile.Slot == slot {
			return cloneProfile(profile), true
		}
	}
	return LaunchProfile{}, false
}
func (historical HistoricalDerivedStartupAuthority) verifyHistoricalStartupAuthority() error {
	if historical.source.digest == "" || historical.source.binding.Manifest.validateStructure(true) != nil {
		return ErrManifestInvalid
	}
	return nil
}

func VerifyHistoricalDerivedStartupAuthority(ctx context.Context, grantWire []byte, anchor HistoricalBootstrapAnchor, roots trust.Keyring, client ObjectStorageClient, wire []byte) (HistoricalDerivedStartupAuthority, error) {
	if ctx == nil || ctx.Err() != nil || client == nil || !anchor.IsVerified() {
		return HistoricalDerivedStartupAuthority{}, ErrManifestInvalid
	}
	// Historical signed deadlines constrain evidence, not today's protected reads.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchor.Wire())
	if err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	identity := anchor.Anchor()
	original, err := VerifyHistoricalBootstrapAnchor(anchorEnvelope, roots, BootstrapAnchorExpectation{DeploymentID: identity.DeploymentID, Environment: identity.Environment, Cell: identity.Cell}, envelope.IssuedAt, BootstrapAnchorTrustPolicy())
	if err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	template, err := verifyHistoricalStartupTemplate(grantWire, roots, original, envelope.IssuedAt)
	if err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	proof, err := decodeDerivedStartupEvidence(template, wire, envelope.IssuedAt)
	if err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	linkRefs := map[string]SecretReference{}
	if proof.binding.Link != nil {
		expires, err := verifyHistoricalStartupLink(ctx, template, original, client, *proof.binding.Link, envelope.IssuedAt)
		if err != nil {
			return HistoricalDerivedStartupAuthority{}, err
		}
		proof.authorityExpires = minTimeLink(proof.authorityExpires, expires)
		for _, ref := range proof.binding.Link.References {
			if linkRefs[ref.TargetFile].TargetFile != "" || !slices.Contains(proof.binding.Manifest.Secrets, ref) {
				return HistoricalDerivedStartupAuthority{}, ErrManifestInvalid
			}
			linkRefs[ref.TargetFile] = ref
		}
	}
	stateWire, err := readStartupEvidenceObject(ctx, client, template.sourceDomain(), template.sourceKey())
	if err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	if err := validateDerivedSourceEvidence(template, proof, stateWire, linkRefs, envelope.IssuedAt); err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	if err := ctx.Err(); err != nil {
		return HistoricalDerivedStartupAuthority{}, err
	}
	return HistoricalDerivedStartupAuthority{source: proof}, nil
}

func verifyHistoricalStartupLink(ctx context.Context, template startupTemplateEvidence, anchor HistoricalBootstrapAnchor, client ObjectStorageClient, evidence RegionalLinkEvidence, instant time.Time) (time.Time, error) {
	regional, err := loadHistoricalRegionalSourceEvidence(ctx, template, client, instant)
	if err != nil {
		return time.Time{}, err
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchor.Wire())
	if err != nil {
		return time.Time{}, err
	}
	homeIdentity := template.identity
	if homeIdentity.Cell != oci.RegionGRU {
		homeIdentity, err = regionalStartupIdentity(template.grantWire, template.roots, anchor.Anchor(), anchorEnvelope.ExpiresAt, oci.RegionGRU, nil, instant)
		if err != nil {
			return time.Time{}, err
		}
	}
	homeTemplate, err := verifyHistoricalStartupTemplateForIdentity(template.grantWire, template.roots, anchor, homeIdentity, instant)
	if err != nil {
		return time.Time{}, err
	}
	home, err := loadHistoricalRegionalSourceEvidence(ctx, homeTemplate, client, instant)
	if err != nil {
		return time.Time{}, err
	}
	kind, binding, key, err := startupLinkLocator(template, regional, home, evidence, instant)
	if err != nil {
		return time.Time{}, err
	}
	if len(evidence.Delivery) != 0 {
		delivery, err := trust.DecodeEnvelope(evidence.Delivery)
		if err != nil || instant.Before(delivery.IssuedAt) || !instant.Before(delivery.ExpiresAt) {
			return time.Time{}, ErrManifestInvalid
		}
	}
	stateWire, err := readStartupEvidenceObject(ctx, client, home.StorageDomain(), key)
	if err != nil {
		return time.Time{}, err
	}
	return validateStartupLinkEvidence(template, regional, home, evidence, kind, binding, stateWire, instant)
}

func readStartupEvidenceObject(ctx context.Context, client ObjectStorageClient, domain StorageDomain, key string) ([]byte, error) {
	response, err := client.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(key)})
	if err != nil {
		return nil, err
	}
	if response.Content == nil {
		return nil, ErrManifestInvalid
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, 2<<20))
	if err != nil || len(wire) >= 2<<20 || response.ETag == nil || *response.ETag == "" {
		return nil, fmt.Errorf("%w: historical source revision", ErrManifestInvalid)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return bytes.Clone(wire), nil
}

func (authority DerivedStartupAuthority) historical(ctx context.Context, wire []byte) (HistoricalDerivedStartupAuthority, error) {
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
	receipt, err := verifyDerivedReceiptEvidence(envelope, historical.source, facts, seed, envelope.IssuedAt, policy)
	if err != nil {
		return HistoricalReceipt{}, err
	}
	return HistoricalReceipt{receipt: receipt, manifestDigest: historical.Digest(), issuedAt: envelope.IssuedAt, expiresAt: envelope.ExpiresAt, verified: true}, nil
}

func loadHistoricalRegionalSourceEvidence(ctx context.Context, template startupTemplateEvidence, client ObjectStorageClient, instant time.Time) (regionalSourceEvidence, error) {
	source, err := loadRegionalSourceEvidence(ctx, template, client, instant)
	if err != nil {
		return regionalSourceEvidence{}, err
	}
	envelope, err := trust.DecodeEnvelope(source.wire)
	if err != nil || instant.Before(envelope.IssuedAt) || !instant.Before(envelope.ExpiresAt) {
		return regionalSourceEvidence{}, ErrManifestInvalid
	}
	return source, nil
}
