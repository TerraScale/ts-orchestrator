package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
)

type managedImageReadback interface {
	ListShapes(context.Context, core.ListShapesRequest) (core.ListShapesResponse, error)
	GetImage(context.Context, core.GetImageRequest) (core.GetImageResponse, error)
	GetImageShapeCompatibilityEntry(context.Context, core.GetImageShapeCompatibilityEntryRequest) (core.GetImageShapeCompatibilityEntryResponse, error)
}

type managedImageVerifier struct {
	region         oci.RegionConfig
	environment    string
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
		accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
		if err != nil {
			return nil, err
		}
		if err := bootstrapstart.CheckIdentityRekeyPrestart(accepted); err != nil {
			return nil, err
		}
		inputs, err := bootstrapstart.LoadTrustInputs(accepted)
		if err != nil {
			return nil, err
		}
		proof, err := independentManagedImageProof(region, oci.Region(accepted.Cell), accepted.Environment,
			inputs.Roots.Current, receiptWire, delegationWire, time.Now().Round(0).UTC())
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
// the cell's environment, exact image OCID and region;
// VerifyImageQualified re-checks it and the OCI readback on every use.
func independentManagedImageProof(region oci.RegionConfig, cell oci.Region, environment string, roots trust.Keyring,
	receiptWire, delegationWire []byte, now time.Time,
) (*managedImageVerifier, error) {
	if region.Region != cell {
		return nil, errors.New("managed image region differs from baked cell")
	}
	image, err := release.VerifyImageCurrent(receiptWire, delegationWire, roots, release.ImageExpectation{
		Environment: environment, LogicalRegion: string(region.Region), OCIImageOCID: region.ImageID,
	}, now)
	if err != nil {
		return nil, fmt.Errorf("verify independent managed host image receipt: %w", err)
	}
	if !image.IsVerified() {
		return nil, errors.New("managed host image proof is absent")
	}
	return &managedImageVerifier{
		region: region, environment: environment, roots: roots,
		receiptWire: receiptWire, delegationWire: delegationWire, now: time.Now,
	}, nil
}

// An accepted installation pins its existing image; future launches still
// require independent current qualification and exact OCI readback.
func newManagedImageVerifier(ctx context.Context, region oci.RegionConfig) (*managedImageVerifier, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return nil, err
	}
	inputs, err := bootstrapstart.LoadTrustInputs(accepted)
	if err != nil {
		return nil, err
	}
	receipt, delegation, err := bootstrapstart.LoadAcceptedManagedImageMaterialContext(ctx, accepted)
	if err != nil {
		return nil, err
	}
	proof, err := acceptedManagedImageProof(region, accepted, inputs.Roots.Historical, receipt, delegation)
	if err != nil {
		return nil, err
	}
	proof.roots = inputs.Roots.Current
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

func acceptedManagedImageProof(region oci.RegionConfig, accepted bootstrapstart.AcceptedIdentity,
	roots trust.Keyring, receipt, delegation []byte,
) (*managedImageVerifier, error) {
	if err := accepted.Validate(); err != nil {
		return nil, err
	}
	if region.Region != oci.Region(accepted.Cell) {
		return nil, errors.New("managed image belongs to another accepted region")
	}
	return independentManagedImageProof(region, oci.Region(accepted.Cell), accepted.Environment, roots, receipt, delegation, accepted.AcceptedAt)
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
	architecture, err := observedManagedImageArchitecture(ctx, verifier.images, verifier.region, imageID)
	if err != nil {
		return err
	}
	image, err := release.VerifyImageCurrent(receiptWire, delegationWire,
		roots, release.ImageExpectation{Environment: verifier.environment,
			LogicalRegion: string(region), OCIImageOCID: imageID, Architecture: architecture},
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

func managedImageArchitecture(ctx context.Context, region oci.RegionConfig) (string, error) {
	images, err := newManagedImageReadback(region)
	if err != nil {
		return "", err
	}
	return observedManagedImageArchitecture(ctx, images, region, region.ImageID)
}

func observedManagedImageArchitecture(ctx context.Context, images managedImageReadback, region oci.RegionConfig, imageID string) (string, error) {
	if !release.ValidOCIImageIDForRegion(imageID, string(region.Region)) || region.CompartmentID == "" ||
		region.AvailabilityDomain == "" || region.Shape == "" {
		return "", errors.New("managed image shape observation requires exact regional image, compartment, availability domain and shape")
	}
	request := core.ListShapesRequest{CompartmentId: new(region.CompartmentID),
		AvailabilityDomain: new(region.AvailabilityDomain), ImageId: new(imageID), Shape: new(region.Shape)}
	architecture := ""
	pages := map[string]bool{}
	for {
		response, err := images.ListShapes(ctx, request)
		if err != nil {
			return "", fmt.Errorf("read OCI managed image shapes: %w", err)
		}
		for _, shape := range response.Items {
			if shape.Shape == nil || *shape.Shape != region.Shape {
				continue
			}
			if architecture != "" || shape.ProcessorDescription == nil {
				return "", errors.New("OCI managed image shape has missing or ambiguous processor identity")
			}
			architecture, err = catalog.ShapeArchitecture(*shape.ProcessorDescription)
			if err != nil {
				return "", err
			}
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			break
		}
		if pages[*response.OpcNextPage] {
			return "", errors.New("OCI managed image shape pagination repeated")
		}
		pages[*response.OpcNextPage] = true
		request.Page = response.OpcNextPage
	}
	if architecture == "" {
		return "", errors.New("OCI managed image shape is unavailable in its availability domain")
	}
	return architecture, ctx.Err()
}

func digestManagedImageWire(wire []byte) string {
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}
