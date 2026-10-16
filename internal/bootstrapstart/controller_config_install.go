package bootstrapstart

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

var ErrControllerConfigInstall = errors.New("controller configuration install proof is invalid")

// VerifyControllerConfigInstall authenticates the public launch transport
// before a guest writes any role configuration. The descriptor selects a slot;
// only the baked root, signed manifest, release image proof, and OCI readback
// authorize the result. The later Gate independently checks the slot ledger.
func VerifyControllerConfigInstall(ctx context.Context, baked BakedInputs, wire []byte,
	descriptor DescriptorSource, instances InstanceObserver, now time.Time,
) (bootstrap.Manifest, InstanceObservation, error) {
	if len(wire) == 0 || len(wire) > MaxControllerManifestMetadataBytes ||
		descriptor == nil || instances == nil || now.IsZero() || now.Location() != time.UTC {
		return bootstrap.Manifest{}, InstanceObservation{}, ErrControllerConfigInstall
	}
	anchorEnvelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return bootstrap.Manifest{}, InstanceObservation{}, err
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(anchorEnvelope, baked.Roots,
		baked.Identity.AnchorExpectation(), now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return bootstrap.Manifest{}, InstanceObservation{}, fmt.Errorf("verify baked controller anchor: %w", err)
	}
	desc, err := descriptor.FetchDescriptor(ctx)
	if err != nil || desc.SchemaVersion != 1 || !slices.Contains(anchor.Anchor().ControllerSlots, desc.Slot) {
		return bootstrap.Manifest{}, InstanceObservation{}, ErrControllerConfigInstall
	}
	instanceID, err := descriptor.FetchInstanceID(ctx)
	if err != nil || !instanceIDRE.MatchString(instanceID) {
		return bootstrap.Manifest{}, InstanceObservation{}, ErrControllerConfigInstall
	}
	manifestEnvelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return bootstrap.Manifest{}, InstanceObservation{}, err
	}
	unsigned, err := bootstrap.ManifestPayload(manifestEnvelope.Payload)
	if err != nil || unsigned.Slot != desc.Slot {
		return bootstrap.Manifest{}, InstanceObservation{}, ErrControllerConfigInstall
	}
	expected, err := anchor.ManifestExpectation(desc.Slot, unsigned.ImageOCID)
	if err != nil {
		return bootstrap.Manifest{}, InstanceObservation{}, err
	}
	verified, err := bootstrap.VerifyManifest(manifestEnvelope, baked.Roots, expected, now,
		bootstrap.ManifestTrustPolicy())
	if err != nil {
		return bootstrap.Manifest{}, InstanceObservation{}, fmt.Errorf("verify root-signed controller manifest: %w", err)
	}
	manifest := verified.Manifest()
	_, err = release.VerifyImageCurrent(manifest.ReleaseImageReceiptWire, manifest.ReleaseDelegationWire,
		baked.Roots, release.ImageExpectation{Environment: manifest.Environment,
			LogicalRegion: string(manifest.Cell), OCIImageOCID: manifest.ImageOCID,
			Architecture: strings.TrimPrefix(manifest.ImageArchitecture, "linux-")}, now)
	if err != nil {
		return bootstrap.Manifest{}, InstanceObservation{}, fmt.Errorf("%w: release image proof: %v", ErrControllerConfigInstall, err)
	}
	observed, err := instances.ObserveInstance(ctx, instanceID)
	if err != nil {
		return bootstrap.Manifest{}, InstanceObservation{}, fmt.Errorf("observe local OCI instance: %w", err)
	}
	profile, ok := verified.Profile(desc.Slot)
	if !ok || observed.InstanceOCID != instanceID || observed.ImageOCID != manifest.ImageOCID ||
		observed.CompartmentOCID != profile.CompartmentOCID ||
		observed.AvailabilityDomain != profile.AvailabilityDomain || observed.FaultDomain != profile.FaultDomain ||
		observed.Shape != profile.Shape || observed.SubnetOCID != profile.SubnetOCID ||
		!sameOCIDSet(observed.NSGOCIDs, profile.NetworkSecurityGroupOCIDs) ||
		observed.LifecycleState != "RUNNING" || !observed.PrimaryVNIC ||
		!validPrivateIPv4(observed.PrimaryPrivateIP) {
		return bootstrap.Manifest{}, InstanceObservation{}, ErrControllerConfigInstall
	}
	return manifest, observed, nil
}
