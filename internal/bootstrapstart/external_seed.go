package bootstrapstart

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

var ErrExternalSeedObservation = errors.New("external seed OCI observation differs from signed authority")

// NewOperatorLedger opens the exact current anchor-scoped ledger with an
// operator-supplied OCI provider. It never creates compute resources.
func NewOperatorLedger(ctx context.Context, anchor bootstrap.VerifiedBootstrapAnchor,
	roots trust.Keyring, provider common.ConfigurationProvider,
) (*bootstrap.Ledger, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config, err := currentLedgerConfig(anchor, roots)
	if err != nil {
		return nil, err
	}
	ledger, err := bootstrap.NewInstancePrincipalLedgerWithProvider(config.Cell, config, provider)
	if err != nil {
		return nil, fmt.Errorf("open exact operator bootstrap ledger: %w", err)
	}
	return ledger, ctx.Err()
}

// VerifyExternalSeedObservation compares a fresh GetInstance/VNIC observation
// with the first signed external intent and current signed seed manifest. The
// create key is an additional OCI readback check, never a source of authority.
func VerifyExternalSeedObservation(anchor bootstrap.VerifiedBootstrapAnchor,
	manifest bootstrap.VerifiedManifest, state bootstrap.SlotState,
	observed InstanceObservation, expectedPrivateIP string,
) (bootstrap.InstanceFacts, error) {
	if !anchor.IsVerified() || manifest.Digest() == "" || state.IntentRecord.SHA256 == "" ||
		state.Intent.Mode != bootstrap.IntentModeExternalSeed || state.Intent.SchemaVersion != 1 ||
		state.Intent.Attempt != 1 || state.Intent.Generation != 1 ||
		state.Head.Attempt != 1 || state.Head.Generation != 1 ||
		state.Head.IntentDigest != state.IntentRecord.SHA256 ||
		state.Intent.ManifestDigest != manifest.Digest() ||
		state.Intent.Slot != manifest.Manifest().SeedSlot ||
		state.Intent.DeploymentID != anchor.Anchor().DeploymentID ||
		state.Intent.Cell != string(anchor.Anchor().Cell) ||
		state.Intent.Environment != anchor.Anchor().Environment {
		return bootstrap.InstanceFacts{}, ErrExternalSeedObservation
	}
	intent := state.Intent
	profile, ok := manifest.Profile(intent.Slot)
	if !ok || profile.CompartmentOCID != intent.CompartmentOCID ||
		profile.AvailabilityDomain != intent.AvailabilityDomain ||
		profile.FaultDomain != intent.FaultDomain || profile.SubnetOCID != intent.SubnetOCID ||
		profile.Shape != intent.Shape || !sameOCIDSet(profile.NetworkSecurityGroupOCIDs, intent.NetworkSecurityGroupIDs) ||
		observed.InstanceOCID == "" || observed.BootstrapCreateKey != intent.CreateKey ||
		observed.CompartmentOCID != intent.CompartmentOCID || observed.ImageOCID != intent.ImageOCID ||
		observed.AvailabilityDomain != intent.AvailabilityDomain || observed.FaultDomain != intent.FaultDomain ||
		observed.Shape != intent.Shape || observed.SubnetOCID != intent.SubnetOCID ||
		!sameOCIDSet(observed.NSGOCIDs, intent.NetworkSecurityGroupIDs) ||
		!observed.PrimaryVNIC || observed.PrimaryVNICOCID == "" ||
		observed.PrimaryPrivateIP != expectedPrivateIP || observed.ETag == "" ||
		observed.LifecycleState != "RUNNING" {
		return bootstrap.InstanceFacts{}, ErrExternalSeedObservation
	}
	profile.NetworkSecurityGroupOCIDs = slices.Clone(profile.NetworkSecurityGroupOCIDs)
	return bootstrap.InstanceFacts{
		DeploymentID: intent.DeploymentID, Environment: intent.Environment,
		ClusterID: anchor.Anchor().ClusterID, Cell: anchor.Anchor().Cell,
		OCIRegion: intent.OCIRegion, Role: intent.Role, Slot: intent.Slot,
		InstanceOCID: observed.InstanceOCID, CompartmentOCID: observed.CompartmentOCID,
		ImageOCID: observed.ImageOCID, CreateKey: intent.CreateKey,
		IntentSHA256: state.IntentRecord.SHA256, Profile: profile,
	}, nil
}
