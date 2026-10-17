package rootociread

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func (b *Backend) ObserveImage(ctx context.Context, call rootoci.Call, request rootoci.ImageRequest) (rootoci.ImageObservation, error) {
	ctx, cancel, scope, err := b.begin(ctx, call, rootoci.OperationObserveImage)
	defer cancel()
	if err != nil {
		return rootoci.ImageObservation{}, err
	}
	accepted, _, config, err := bootstrapstart.LoadAcceptedOCIConfig()
	if err != nil || string(config.Region) != scope.cell || !release.ValidOCIImageIDForRegion(request.ImageID, scope.cell) {
		return rootoci.ImageObservation{}, errors.Join(ErrPending, err)
	}
	b.mu.RLock()
	verifier := b.images
	b.mu.RUnlock()
	expectedArchitecture := ""
	if request.ImageID != config.ImageID {
		if verifier == nil {
			return rootoci.ImageObservation{}, errors.New("requested image is outside the accepted root image pin")
		}
		if err := verifier.VerifyImageQualified(ctx, config.Region, request.ImageID); err != nil {
			return rootoci.ImageObservation{}, err
		}
	} else {
		receipt, delegation, err := bootstrapstart.LoadAcceptedManagedImageMaterial(accepted)
		if err != nil {
			return rootoci.ImageObservation{}, err
		}
		proof, err := scope.footprint.VerifyReadImage(ctx, scope.cell, request.ImageID, receipt, delegation)
		if err != nil {
			return rootoci.ImageObservation{}, err
		}
		expectedArchitecture = proof.Receipt().Architecture
	}
	client, err := b.factory.Compute()
	if err != nil {
		return rootoci.ImageObservation{}, err
	}
	image, err := client.GetImage(ociclient.RequestContext(ctx), core.GetImageRequest{ImageId: new(request.ImageID)})
	if err != nil {
		return rootoci.ImageObservation{}, err
	}
	if image.Id == nil || *image.Id != request.ImageID || image.CompartmentId == nil ||
		*image.CompartmentId != config.ImageCompartmentID || image.LifecycleState != core.ImageLifecycleStateAvailable {
		return rootoci.ImageObservation{}, errors.New("OCI image differs from root-admitted image identity")
	}
	compatible, err := client.GetImageShapeCompatibilityEntry(ociclient.RequestContext(ctx), core.GetImageShapeCompatibilityEntryRequest{
		ImageId: new(request.ImageID), ShapeName: new(config.Shape),
	})
	if err != nil {
		return rootoci.ImageObservation{}, err
	}
	if compatible.ImageId == nil || *compatible.ImageId != request.ImageID || compatible.Shape == nil || *compatible.Shape != config.Shape {
		return rootoci.ImageObservation{}, errors.New("OCI image is incompatible with the accepted host shape")
	}
	architecture := ""
	var page *string
	seen := map[string]bool{}
	for range 32 {
		shapes, err := client.ListShapes(ociclient.RequestContext(ctx), core.ListShapesRequest{
			CompartmentId: new(config.CompartmentID), AvailabilityDomain: new(config.AvailabilityDomain),
			ImageId: new(request.ImageID), Shape: new(config.Shape), Page: page,
		})
		if err != nil {
			return rootoci.ImageObservation{}, err
		}
		for _, shape := range shapes.Items {
			if shape.Shape == nil || *shape.Shape != config.Shape {
				continue
			}
			if architecture != "" || shape.ProcessorDescription == nil {
				return rootoci.ImageObservation{}, errors.New("OCI image shape architecture is absent or ambiguous")
			}
			architecture, err = catalog.ShapeArchitecture(*shape.ProcessorDescription)
			if err != nil {
				return rootoci.ImageObservation{}, err
			}
		}
		if shapes.OpcNextPage == nil || *shapes.OpcNextPage == "" {
			if architecture == "" || expectedArchitecture != "" && architecture != expectedArchitecture {
				return rootoci.ImageObservation{}, errors.New("OCI image shape is unavailable in the accepted availability domain")
			}
			if err := b.finish(ctx, call, scope); err != nil {
				return rootoci.ImageObservation{}, err
			}
			return rootoci.ImageObservation{ImageID: request.ImageID, CompartmentID: *image.CompartmentId,
				State: string(image.LifecycleState), Shape: config.Shape, Architecture: architecture}, nil
		}
		if seen[*shapes.OpcNextPage] {
			return rootoci.ImageObservation{}, errors.New("OCI image shape pagination repeated")
		}
		seen[*shapes.OpcNextPage] = true
		page = shapes.OpcNextPage
	}
	return rootoci.ImageObservation{}, errors.New("OCI image shape pagination exceeds its bound")
}
