package region

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// SignFoundationDiscovery extends the existing offline-root ceremony. Only
// public signed bytes leave it; credential generation stays in the Vault path.
func SignFoundationDiscovery(ctx context.Context, grant FoundationGrant, anchor bootstrap.BootstrapAnchor, chainWire []byte, genesis trust.Keyring, private ed25519.PrivateKey, issued, expires time.Time) (RetainedFoundation, error) {
	if err := ctx.Err(); err != nil {
		return RetainedFoundation{}, err
	}
	chain, err := trust.DecodeRootChain(chainWire)
	if err != nil {
		return RetainedFoundation{}, err
	}
	lineage, err := trust.VerifyRootChain(genesis, foundationChainIdentity(anchor.DeploymentID), chain)
	if err != nil {
		return RetainedFoundation{}, err
	}
	if len(private) != ed25519.PrivateKeySize {
		return RetainedFoundation{}, errors.New("foundation signing requires the existing offline root key")
	}
	id, err := trust.KeyID(private.Public().(ed25519.PublicKey))
	if err != nil || !bytes.Equal(lineage.Current[id], private.Public().(ed25519.PublicKey)) {
		return RetainedFoundation{}, errors.New("foundation signing key is outside the current root lineage")
	}
	home := anchor.FoundationScope
	if home == nil || home.InstallationID != grant.InstallationID || home.TenancyID != grant.TenancyID || anchor.Cell != oci.RegionGRU || anchor.Environment != "production" || home.StorageDomain.HeadBucket != foundationDiscoveryBucket || grant.InfrastructureSpend == nil || grant.InfrastructureSpend.Bootstrap == nil || grant.OCIRIssuance == nil {
		return RetainedFoundation{}, errors.New("foundation ceremony requires the complete approved production installation, spending allocation and OCIR scope")
	}
	if err := ValidatePreparedFoundation(grant); err != nil {
		return RetainedFoundation{}, err
	}
	if err := ValidateFoundationOCIRIssuer(grant); err != nil {
		return RetainedFoundation{}, err
	}
	if err := ValidateContainerReleaseAuthorities(grant, lineage.Current, home.StorageDomain, issued); err != nil {
		return RetainedFoundation{}, err
	}
	boundExpiry := func(deadline time.Time) {
		if deadline.Before(expires) {
			expires = deadline
		}
	}
	boundEnvelopeExpiry := func(wires ...[]byte) error {
		for _, wire := range wires {
			if len(wire) == 0 {
				continue
			}
			envelope, err := trust.DecodeEnvelope(wire)
			if err != nil {
				return err
			}
			boundExpiry(envelope.ExpiresAt)
		}
		return nil
	}
	for _, authority := range grant.ReleaseAuthorities {
		if err := boundEnvelopeExpiry(authority.DelegationWire); err != nil {
			return RetainedFoundation{}, err
		}
	}
	for _, regional := range grant.Regions {
		startup := regional.BootstrapMaterial.Startup
		cell := regional.Plan["cell"].(string)
		image, err := release.VerifyImageCurrent(startup.ReleaseImageReceiptWire, startup.ReleaseDelegationWire, lineage.Current,
			release.ImageExpectation{Environment: "production", LogicalRegion: cell, OCIImageOCID: startup.ImageOCID, Architecture: "arm64"}, issued)
		if err != nil {
			return RetainedFoundation{}, fmt.Errorf("verify prepared %s controller image: %w", cell, err)
		}
		boundExpiry(image.ExpiresAt())
		if err := boundEnvelopeExpiry(startup.ReleaseDelegationWire); err != nil {
			return RetainedFoundation{}, err
		}
		boundExpiry(startup.FounderResources.LaunchDeadline)
		if regional.NetBirdManager == nil {
			continue
		}
		manager := regional.NetBirdManager
		image, err = release.VerifyNetBirdImageCurrent(manager.ImageReceiptWire, manager.ImageDelegationWire, lineage.Current,
			release.ImageExpectation{Environment: "production", LogicalRegion: "GRU", OCIImageOCID: manager.ImageOCID, Architecture: "arm64"}, issued)
		if err != nil {
			return RetainedFoundation{}, err
		}
		boundExpiry(image.ExpiresAt())
		receipt := image.Receipt()
		if _, err := release.VerifyProductionCurrent(manager.QualificationWire, manager.QualificationDelegationWire, lineage.Current,
			release.ProductionExpectation{SourceRevision: receipt.SourceRevision, ArtifactSHA256: receipt.ImageSHA256, QualificationSHA256: receipt.QualificationSHA256, Cell: "GRU", Environment: "production", Runtime: release.NetBirdProductionRuntime, Architecture: "arm64", Role: NetBirdManagerRole}, issued); err != nil {
			return RetainedFoundation{}, err
		}
		if err := boundEnvelopeExpiry(manager.ImageDelegationWire, manager.QualificationWire, manager.QualificationDelegationWire); err != nil {
			return RetainedFoundation{}, err
		}
	}
	if !expires.After(issued) {
		return RetainedFoundation{}, errors.New("prepared foundation leaves no current image or qualification validity")
	}
	digest, err := FoundationInfrastructureScopeDigest(grant)
	if err != nil {
		return RetainedFoundation{}, err
	}
	if grant.InfrastructureSpend.ScopeSHA256 != digest {
		return RetainedFoundation{}, errors.New("approved spending digest differs from the prepared footprint")
	}
	payload, err := trust.EncodePayload(grant)
	if err != nil {
		return RetainedFoundation{}, err
	}
	signedGrant, err := trust.Sign(payload, trust.Scope{Domain: foundationGrantDomain, DeploymentID: home.DeploymentID, Cell: "GRU", Environment: "production", Role: "foundation", Slot: home.ClusterID}, issued, expires, private)
	if err != nil {
		return RetainedFoundation{}, err
	}
	grantWire, err := trust.EncodeEnvelope(signedGrant)
	if err != nil || len(grantWire) > foundationRecordLimit {
		return RetainedFoundation{}, errors.Join(errors.New("foundation grant exceeds its document bound"), err)
	}
	home = new(*home)
	anchor.FoundationScope = home
	hash := sha256.Sum256(grantWire)
	home.GrantSHA256, home.GrantGeneration = hex.EncodeToString(hash[:]), grant.Generation
	for _, regional := range grant.Regions {
		if regional.Plan["cell"] == "GRU" && regional.BootstrapMaterial.SourceRegistration != nil {
			if len(anchor.LedgerDelegationWire) != 0 {
				return RetainedFoundation{}, errors.New("initial source registration cannot replace a pinned ledger signer")
			}
			registration := regional.BootstrapMaterial.SourceRegistration.Clone()
			anchor.InitialSourceRegistration = &registration
		}
	}
	signedAnchor, err := bootstrap.SignBootstrapAnchor(anchor, issued, expires, private)
	if err != nil {
		return RetainedFoundation{}, err
	}
	anchorWire, err := trust.EncodeEnvelope(signedAnchor)
	if err != nil || len(anchorWire) > bootstrap.MaxBootstrapAnchorBytes {
		return RetainedFoundation{}, errors.Join(errors.New("foundation anchor exceeds its document bound"), err)
	}
	verified, err := verifyDiscoveryAnchor(anchorWire, lineage.Current, grant.TenancyID, home.StorageDomain.Namespace)
	if err != nil {
		return RetainedFoundation{}, err
	}
	reader, err := newSignedFootprint(nil, verified, lineage.Current, grant.TenancyID)
	if err != nil {
		return RetainedFoundation{}, err
	}
	reader.retainedGrant = bytes.Clone(grantWire)
	if _, _, err := reader.verifyGrant(grantWire); err != nil {
		return RetainedFoundation{}, err
	}
	return RetainedFoundation{TenancyID: grant.TenancyID, Namespace: home.StorageDomain.Namespace, RootChainWire: bytes.Clone(chainWire), AnchorWire: anchorWire, GrantWire: grantWire}, ctx.Err()
}
