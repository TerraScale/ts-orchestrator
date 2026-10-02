package bootstrapstart

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
)

// AdmitRestartLocal is the offline subset of AdmitRestart. It uses only the
// root-owned accepted-install marker, the baked roots, the root-installed
// signed manifest, the link-local IMDS identity, and installed files. It reads
// no OCI API, writes no ledger record, and does not consult NTP.
//
// It proves that this VM is the exact accepted install running the signed
// controller config with unmodified materials, which is enough to rejoin
// broker routes. It never replaces AdmitRestart: the caller must still pass
// full restart admission (ledger, VNIC observation, current continuation and
// clock) before any authority, broker-gate, or mutation path starts.
func (gate Gate) AdmitRestartLocal(ctx context.Context, installedManifest []byte) (AcceptedInstall, error) {
	if len(gate.Roots) == 0 || len(gate.AnchorWire) == 0 || gate.Descriptor == nil ||
		gate.Material == nil || gate.Credentials == nil || gate.Markers.directory == "" ||
		!markerDigestRE.MatchString(gate.LoadedControllerConfigSHA256) {
		return AcceptedInstall{}, fmt.Errorf("%w: trusted input or required local verifier is absent", ErrAdmission)
	}
	marker, err := gate.Markers.Read()
	if err != nil {
		return AcceptedInstall{}, fmt.Errorf("read accepted-install marker: %w", err)
	}
	anchorEnvelope, err := proofEnvelope(gate.AnchorWire)
	if err != nil {
		return AcceptedInstall{}, err
	}
	anchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(anchorEnvelope, gate.Roots, gate.Expected,
		marker.AcceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || anchor.Digest() != marker.AnchorSHA256 {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted anchor differs from baked root proof: %v", ErrAdmission, err)
	}
	scope, instanceID, err := gate.locate(ctx)
	if err != nil {
		return AcceptedInstall{}, err
	}
	if scope.DeploymentID != marker.DeploymentID || scope.Cell != marker.Cell ||
		scope.Slot != marker.Slot || instanceID != marker.InstanceOCID {
		return AcceptedInstall{}, fmt.Errorf("%w: local locator differs from accepted install", ErrAdmission)
	}
	if digest(installedManifest) != marker.ManifestSHA256 {
		return AcceptedInstall{}, fmt.Errorf("%w: installed controller manifest differs from accepted install", ErrAdmission)
	}
	anchored := anchor.Anchor()
	expected := bootstrap.ManifestExpectation{
		DeploymentID: anchored.DeploymentID, Environment: anchored.Environment,
		ClusterID: anchored.ClusterID, Cell: anchored.Cell, Slot: scope.Slot,
		ImageOCID: marker.ImageOCID, StorageDomain: anchored.StorageDomain,
		ControllerSlots:  slices.Clone(anchored.ControllerSlots),
		IntentGeneration: anchored.InitialRegionIntentGeneration,
		IntentSHA256:     anchored.InitialRegionIntentSHA256,
	}
	manifestEnvelope, err := proofEnvelope(installedManifest)
	if err != nil {
		return AcceptedInstall{}, err
	}
	manifest, err := bootstrap.VerifyHistoricalManifest(manifestEnvelope, gate.Roots, expected, bootstrap.ManifestTrustPolicy())
	if err != nil || manifest.Digest() != marker.ManifestSHA256 ||
		!coveredAt(manifestEnvelope.IssuedAt, manifestEnvelope.ExpiresAt, marker.AcceptedAt) {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted historical manifest is invalid: %v", ErrAdmission, err)
	}
	payload := manifest.Manifest()
	if payload.ControllerConfigSHA256 != gate.LoadedControllerConfigSHA256 {
		return AcceptedInstall{}, fmt.Errorf("%w: loaded controller config differs from accepted manifest", ErrAdmission)
	}
	if marker.SeedSlot != payload.SeedSlot {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted seed role differs from signed manifest", ErrAdmission)
	}
	if payload.ReleaseReceiptSHA256 != marker.ImageReceiptSHA256 ||
		digest(payload.ReleaseImageReceiptWire) != marker.ImageReceiptSHA256 ||
		payload.ImageOCID != marker.ImageOCID {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted release image differs", ErrAdmission)
	}
	image, err := release.VerifyImageHistorical(payload.ReleaseImageReceiptWire, payload.ReleaseDelegationWire,
		gate.Roots, release.ImageExpectation{Environment: payload.Environment, LogicalRegion: string(payload.Cell),
			OCIImageOCID: payload.ImageOCID, Architecture: strings.TrimPrefix(payload.ImageArchitecture, "linux-")})
	if err != nil || !coveredAt(image.IssuedAt(), image.ExpiresAt(), marker.AcceptedAt) {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted historical release image is invalid: %v", ErrAdmission, err)
	}
	binary, err := gate.binaryChecker().VerifyHistorical(image)
	if err != nil || binary.SHA256 != marker.BinarySHA256 {
		return AcceptedInstall{}, fmt.Errorf("%w: installed executable differs: %v", ErrAdmission, err)
	}
	materials := expectedMaterials(payload, scope.Slot)
	if len(materials) == 0 || len(materials) != len(marker.MaterialSHA256) {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted material inventory differs", ErrAdmission)
	}
	for name, want := range materials {
		if marker.MaterialSHA256[name] != want {
			return AcceptedInstall{}, fmt.Errorf("%w: accepted material digest differs", ErrAdmission)
		}
	}
	if (payload.ManagedMaterial == nil) != (marker.ManagedMaterial == nil) ||
		payload.ManagedMaterial != nil && *payload.ManagedMaterial != *marker.ManagedMaterial {
		return AcceptedInstall{}, fmt.Errorf("%w: accepted managed material domain differs", ErrAdmission)
	}
	if err := gate.Material.VerifyRestart(ctx, manifest, materials); err != nil {
		return AcceptedInstall{}, fmt.Errorf("verify installed controller materials: %w", err)
	}
	if err := gate.Credentials.VerifyLiveCredentials(ctx, materials, payload); err != nil {
		return AcceptedInstall{}, fmt.Errorf("verify live controller credentials: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return AcceptedInstall{}, fmt.Errorf("%w: local restart admission ended: %w", ErrAdmission, err)
	}
	return marker, nil
}
