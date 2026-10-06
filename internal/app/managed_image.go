package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
)

type managedImageReadback interface {
	GetImage(context.Context, core.GetImageRequest) (core.GetImageResponse, error)
	GetImageShapeCompatibilityEntry(context.Context, core.GetImageShapeCompatibilityEntryRequest) (core.GetImageShapeCompatibilityEntryResponse, error)
}

type managedImageVerifier struct {
	region         oci.RegionConfig
	environment    string
	architecture   string
	roots          trust.Keyring
	receiptWire    []byte
	delegationWire []byte
	images         managedImageReadback
	now            func() time.Time
	// hostImages returns the cell spec's host images, whose hosts stay fleet
	// members besides those of the pinned image, its launch image, and the
	// current roots that qualify a launch from them.
	hostImages func() hostImageSnapshot
	// holdLaunch holds the cell spec's launch fence until its release; nil
	// fences nothing.
	holdLaunch func() func()
}

var (
	_ oci.ImageQualificationVerifier = (*managedImageVerifier)(nil)
	_ oci.HostImageAllowList         = (*managedImageVerifier)(nil)
)

type managedFleetFactory func(oci.RegionConfig, oci.RegionIntent, oci.Journal, authority.Fencer,
	oci.DrainRequester, oci.WriterStopVerifier, oci.ImageQualificationVerifier, map[string]string) (oci.Fleet, error)

// Keep the production constructor's qualification dependency explicit. A nil
// verifier must never silently turn managed retained volumes into held work.
func openManagedControllerFleet(ctx context.Context, region oci.RegionConfig, intent oci.RegionIntent,
	journal oci.Journal, fencer authority.Fencer, hostMetadata map[string]string,
	newVerifier func(context.Context, oci.RegionConfig) (oci.ImageQualificationVerifier, error),
	newFleet managedFleetFactory,
) (oci.Fleet, error) {
	if newVerifier == nil || newFleet == nil {
		return nil, errors.New("managed OCI image and fleet constructors are required")
	}
	verifier, err := newVerifier(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("configure managed OCI image qualification: %w", err)
	}
	if verifier == nil {
		return nil, errors.New("managed OCI image qualification is unavailable")
	}
	return newFleet(region, intent, journal, fencer, nil, nil, verifier, hostMetadata)
}

// managedImageVerifierFor selects the managed-host image qualification
// source. By default the image must be the controller's own accepted boot
// image. When both host image files are configured, the host image is
// qualified independently from its own root-delegated image receipt, so
// hosts can move to a newer qualified image without a controller re-install.
// Either way, hostImages names the cell spec's host images and launch image,
// and holdLaunch fences them during a provider launch.
func managedImageVerifierFor(controller ControllerConfig, hostImages func() hostImageSnapshot, holdLaunch func() func(),
) func(context.Context, oci.RegionConfig) (oci.ImageQualificationVerifier, error) {
	newVerifier := managedImageVerifierFromFiles(controller)
	return func(ctx context.Context, region oci.RegionConfig) (oci.ImageQualificationVerifier, error) {
		verifier, err := newVerifier(ctx, region)
		if err != nil {
			return nil, err
		}
		verifier.hostImages, verifier.holdLaunch = hostImages, holdLaunch
		return verifier, nil
	}
}

func managedImageVerifierFromFiles(controller ControllerConfig) func(context.Context, oci.RegionConfig) (*managedImageVerifier, error) {
	receiptFile, delegationFile := controller.ManagedHostImageReceiptFile, controller.ManagedHostImageDelegationFile
	if receiptFile == "" && delegationFile == "" {
		return newManagedImageVerifier
	}
	return func(ctx context.Context, region oci.RegionConfig) (*managedImageVerifier, error) {
		if receiptFile == "" || delegationFile == "" {
			return nil, errors.New("managed host image receipt and delegation files are required together")
		}
		receiptWire, err := readBoundedConfigFile(receiptFile)
		if err != nil {
			return nil, fmt.Errorf("read managed host image receipt: %w", err)
		}
		delegationWire, err := readBoundedConfigFile(delegationFile)
		if err != nil {
			return nil, fmt.Errorf("read managed host image delegation: %w", err)
		}
		baked, err := bootstrapstart.LoadBakedInputs()
		if err != nil {
			return nil, fmt.Errorf("load baked image trust roots: %w", err)
		}
		marker, err := bootstrapstart.NewMarkerStore().Read()
		if err != nil {
			return nil, fmt.Errorf("read accepted image install: %w", err)
		}
		if marker.DeploymentID != baked.Identity.DeploymentID || marker.Cell != string(baked.Identity.Cell) {
			return nil, errors.New("accepted install differs from baked root scope")
		}
		proof, err := independentManagedImageProof(region, baked.Identity.Cell, baked.Identity.Environment,
			baked.Roots, receiptWire, delegationWire, time.Now().Round(0).UTC())
		if err != nil {
			return nil, err
		}
		if proof.images, err = newManagedImageReadback(region); err != nil {
			return nil, err
		}
		return proof, nil
	}
}

// independentManagedImageProof qualifies the configured host image from its
// own receipt. The receipt must be currently valid under the baked roots for
// the cell's environment, exact image OCID, region and shape architecture;
// VerifyImageQualified re-checks it and the OCI readback on every use.
func independentManagedImageProof(region oci.RegionConfig, cell oci.Region, environment string, roots trust.Keyring,
	receiptWire, delegationWire []byte, now time.Time,
) (*managedImageVerifier, error) {
	if region.Region != cell {
		return nil, errors.New("managed image region differs from baked cell")
	}
	architecture, err := imageArchitectureForShape(region.Shape)
	if err != nil {
		return nil, err
	}
	image, err := release.VerifyImageCurrent(receiptWire, delegationWire, roots, release.ImageExpectation{
		Environment: environment, LogicalRegion: string(region.Region), OCIImageOCID: region.ImageID, Architecture: architecture,
	}, now)
	if err != nil {
		return nil, fmt.Errorf("verify independent managed host image receipt: %w", err)
	}
	if !image.IsVerified() {
		return nil, errors.New("managed host image proof is absent")
	}
	return &managedImageVerifier{
		region: region, environment: environment, architecture: architecture, roots: roots,
		receiptWire: receiptWire, delegationWire: delegationWire, now: time.Now,
	}, nil
}

// The accepted slot ledger is the source of the release image proof. The
// marker alone carries only digests and never grants a new cloud operation.
func newManagedImageVerifier(ctx context.Context, region oci.RegionConfig) (*managedImageVerifier, error) {
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return nil, fmt.Errorf("load baked image trust roots: %w", err)
	}
	marker, err := bootstrapstart.NewMarkerStore().Read()
	if err != nil {
		return nil, fmt.Errorf("read accepted image install: %w", err)
	}
	anchorWire, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return nil, fmt.Errorf("decode baked image anchor: %w", err)
	}
	anchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(anchorWire, baked.Roots,
		baked.Identity.AnchorExpectation(), marker.AcceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return nil, fmt.Errorf("verify accepted image anchor: %w", err)
	}
	if anchor.Digest() != marker.AnchorSHA256 {
		return nil, errors.New("accepted image anchor differs from install marker")
	}
	ledger, err := (bootstrapstart.InstancePrincipalLedgerOpener{}).OpenHistoricalLedger(ctx, anchor, baked.Roots)
	if err != nil {
		return nil, fmt.Errorf("open accepted image slot: %w", err)
	}
	proof, err := acceptedManagedImageProof(ctx, region, baked, marker, anchor, ledger)
	if err != nil {
		return nil, err
	}
	if proof.images, err = newManagedImageReadback(region); err != nil {
		return nil, err
	}
	return proof, nil
}

func newManagedImageReadback(region oci.RegionConfig) (managedImageReadback, error) {
	ociRegion, err := region.Region.OCIRegion()
	if err != nil {
		return nil, err
	}
	factory, err := ociclient.InstancePrincipal(ociRegion)
	if err != nil {
		return nil, fmt.Errorf("create regional image readback principal: %w", err)
	}
	compute, err := factory.Compute()
	if err != nil {
		return nil, fmt.Errorf("create regional image readback client: %w", err)
	}
	compute.SetRegion(ociRegion)
	compute.HTTPClient, err = bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("configure image readback transport: %w", err)
	}
	return &compute, nil
}

func acceptedManagedImageProof(ctx context.Context, region oci.RegionConfig, baked bootstrapstart.BakedInputs,
	marker bootstrapstart.AcceptedInstall, anchor bootstrap.HistoricalBootstrapAnchor,
	ledger bootstrapstart.SlotReader,
) (*managedImageVerifier, error) {
	if ledger == nil || marker.DeploymentID != baked.Identity.DeploymentID ||
		marker.Cell != string(baked.Identity.Cell) || region.Region != baked.Identity.Cell ||
		region.ImageID != marker.ImageOCID || anchor.Digest() != marker.AnchorSHA256 {
		return nil, errors.New("managed image differs from accepted controller image and root scope")
	}
	architecture, err := imageArchitectureForShape(region.Shape)
	if err != nil {
		return nil, err
	}
	state, err := ledger.ReadSlot(ctx, bootstrap.BootstrapScope{
		DeploymentID: marker.DeploymentID, Cell: marker.Cell, Slot: marker.Slot,
	})
	if err != nil {
		return nil, fmt.Errorf("read accepted controller image ledger: %w", err)
	}
	if state.ManifestRecord == nil || state.ManifestRecord.SHA256 != marker.ManifestSHA256 ||
		state.Head.Attempt != marker.HeadAttempt || state.Head.Generation != marker.HeadGeneration ||
		state.Head.ResultDigest != marker.ResultSHA256 || state.Intent.ImageOCID != marker.ImageOCID ||
		state.Intent.ManifestDigest != marker.ManifestSHA256 ||
		state.Intent.ReleaseReceiptDigest != marker.ImageReceiptSHA256 ||
		state.Result == nil || state.ResultRecord == nil || state.ResultRecord.SHA256 != marker.ResultSHA256 ||
		state.Result.InstanceOCID != marker.InstanceOCID {
		return nil, errors.New("accepted controller image ledger does not match install marker")
	}
	anchored := anchor.Anchor()
	expected := bootstrap.ManifestExpectation{
		DeploymentID: anchored.DeploymentID, Environment: anchored.Environment,
		ClusterID: anchored.ClusterID, Cell: anchored.Cell, Slot: marker.Slot,
		ImageOCID: marker.ImageOCID, StorageDomain: anchored.StorageDomain,
		ControllerSlots:  slices.Clone(anchored.ControllerSlots),
		IntentGeneration: anchored.InitialRegionIntentGeneration,
		IntentSHA256:     anchored.InitialRegionIntentSHA256,
	}
	manifestWire, err := trust.DecodeEnvelope(state.ManifestRecord.Bytes)
	if err != nil {
		return nil, fmt.Errorf("decode accepted image manifest: %w", err)
	}
	manifest, err := bootstrap.VerifyHistoricalManifest(manifestWire, baked.Roots,
		expected, bootstrap.ManifestTrustPolicy())
	if err != nil {
		return nil, fmt.Errorf("verify accepted image manifest: %w", err)
	}
	if manifest.Digest() != marker.ManifestSHA256 ||
		marker.AcceptedAt.Before(manifestWire.IssuedAt) || !marker.AcceptedAt.Before(manifestWire.ExpiresAt) {
		return nil, errors.New("accepted image manifest differs from install marker")
	}
	payload := manifest.Manifest()
	if payload.ReleaseReceiptSHA256 != marker.ImageReceiptSHA256 ||
		digestManagedImageWire(payload.ReleaseImageReceiptWire) != marker.ImageReceiptSHA256 ||
		payload.ImageOCID != region.ImageID || payload.ImageArchitecture != "linux-"+architecture {
		return nil, errors.New("accepted manifest image proof differs from managed image")
	}
	return &managedImageVerifier{
		region: region, environment: baked.Identity.Environment, architecture: architecture,
		roots: baked.Roots, receiptWire: payload.ReleaseImageReceiptWire,
		delegationWire: payload.ReleaseDelegationWire, now: time.Now,
	}, nil
}

func (verifier *managedImageVerifier) hostImageSnapshot() hostImageSnapshot {
	if verifier == nil || verifier.hostImages == nil {
		return hostImageSnapshot{}
	}
	return verifier.hostImages()
}

// HostImages returns one cell spec generation's host image IDs and launch
// image, "" for the pin.
func (verifier *managedImageVerifier) HostImages() ([]string, string) {
	snapshot := verifier.hostImageSnapshot()
	return snapshot.ids(), snapshot.launch
}

// VerifyImageQualified proves the fleet pin, or a host image of the cell
// spec, from its own current receipt and the exact OCI readback. The pin's
// receipt verifies with the baked roots its install was accepted under; a
// spec image's with the cell's current roots, as the leader admitted it.
func (verifier *managedImageVerifier) VerifyImageQualified(ctx context.Context, region oci.Region, imageID string) error {
	return verifier.verifyQualified(ctx, region, imageID, verifier.hostImageSnapshot())
}

// QualifiedLaunchImage chooses and qualifies the image new hosts boot from
// one cell spec snapshot, its launch image or the pin, and returns the
// snapshot's version.
func (verifier *managedImageVerifier) QualifiedLaunchImage(ctx context.Context, region oci.Region, pin string) (string, string, error) {
	if verifier == nil || pin != verifier.region.ImageID {
		return "", "", errors.New("launch image request differs from managed fleet pin")
	}
	spec := verifier.hostImageSnapshot()
	image := pin
	if spec.launch != "" && slices.Contains(spec.ids(), spec.launch) {
		image = spec.launch
	}
	return image, spec.version, verifier.verifyQualified(ctx, region, image, spec)
}

// AdmitLaunch holds the cell spec's launch fence, then qualifies imageID
// from the fenced spec, which must still be at version when one is given.
// The fence stays held until release, so no spec or root change lands
// before the provider launch returns.
func (verifier *managedImageVerifier) AdmitLaunch(ctx context.Context, region oci.Region, imageID, version string) (func(), error) {
	release := func() {}
	if verifier != nil && verifier.holdLaunch != nil {
		release = verifier.holdLaunch()
	}
	spec := verifier.hostImageSnapshot()
	if version != "" && spec.version != version {
		release()
		return nil, errors.New("the cell spec changed after the launch image was chosen")
	}
	if err := verifier.verifyQualified(ctx, region, imageID, spec); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

func (verifier *managedImageVerifier) verifyQualified(ctx context.Context, region oci.Region, imageID string,
	spec hostImageSnapshot,
) error {
	if verifier == nil || verifier.images == nil || verifier.now == nil || region != verifier.region.Region {
		return errors.New("image verification request differs from managed fleet region")
	}
	receiptWire, delegationWire, roots := verifier.receiptWire, verifier.delegationWire, verifier.roots
	if imageID != verifier.region.ImageID {
		index := slices.IndexFunc(spec.images, func(image cellspec.HostImage) bool { return image.ImageID == imageID })
		if index < 0 {
			return errors.New("image verification request names neither the managed fleet pin nor a host image")
		}
		receiptWire, delegationWire, roots = spec.images[index].Receipt, spec.images[index].Delegation, spec.roots
	}
	image, err := release.VerifyImageCurrent(receiptWire, delegationWire,
		roots, release.ImageExpectation{Environment: verifier.environment,
			LogicalRegion: string(region), OCIImageOCID: imageID, Architecture: verifier.architecture},
		verifier.now().Round(0).UTC())
	if err != nil {
		return fmt.Errorf("verify current qualified image receipt: %w", err)
	}
	if !image.IsVerified() || image.Receipt().QualificationSHA256 == "" {
		return errors.New("qualified image proof is absent")
	}
	response, err := verifier.images.GetImage(ctx, core.GetImageRequest{ImageId: new(imageID)})
	if err != nil {
		return fmt.Errorf("read exact OCI image: %w", err)
	}
	if response.Id == nil || *response.Id != imageID ||
		response.CompartmentId == nil || *response.CompartmentId != verifier.region.ImageCompartmentID ||
		response.LifecycleState != core.ImageLifecycleStateAvailable {
		return errors.New("OCI image readback differs from admitted image identity or is unavailable")
	}
	compatible, err := verifier.images.GetImageShapeCompatibilityEntry(ctx,
		core.GetImageShapeCompatibilityEntryRequest{ImageId: new(imageID), ShapeName: new(verifier.region.Shape)})
	if err != nil {
		return fmt.Errorf("read OCI image shape compatibility: %w", err)
	}
	if compatible.ImageId == nil || *compatible.ImageId != imageID ||
		compatible.Shape == nil || *compatible.Shape != verifier.region.Shape {
		return errors.New("OCI image is not confirmed compatible with managed host shape")
	}
	return ctx.Err()
}

func imageArchitectureForShape(shape string) (string, error) {
	switch {
	case shape == "VM.Standard.A1.Flex":
		return "arm64", nil
	case strings.HasPrefix(shape, "VM.Standard.E4."), strings.HasPrefix(shape, "VM.Standard.E5."):
		return "amd64", nil
	default:
		return "", fmt.Errorf("managed image architecture is unknown for shape %q", shape)
	}
}

func digestManagedImageWire(wire []byte) string {
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}
