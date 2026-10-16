package app

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (r *capacityReservations) imageInputs(role string) []nodescale.ImageQualification {
	if r == nil || r.specs == nil {
		return nil
	}
	images := r.specs.hostImageSnapshot().images
	if accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity(); err == nil {
		if receipt, delegation, err := bootstrapstart.LoadAcceptedManagedImageMaterial(accepted); err == nil {
			images = append(images, cellspec.HostImage{Receipt: receipt, Delegation: delegation})
		}
	}
	var inputs []nodescale.ImageQualification
	for _, image := range images {
		envelope, err := trust.DecodeEnvelope(image.Receipt)
		if err != nil {
			continue
		}
		var receipt release.ImageReceipt
		if json.Unmarshal(envelope.Payload, &receipt, json.RejectUnknownMembers(true)) != nil {
			continue
		}
		input := nodescale.ImageQualification{Receipt: image.Receipt, Delegation: image.Delegation, Role: role,
			Expected: release.ImageExpectation{Environment: r.environment, LogicalRegion: strings.ToUpper(r.cell),
				OCIImageOCID: receipt.OCIImageOCID, Architecture: receipt.Architecture}}
		if proof, found := receipt.HostProduction[role]; found {
			input.RoleProduction = new(proof)
		}
		inputs = append(inputs, input)
	}
	return inputs
}

func (r *capacityReservations) qualify(ctx context.Context, input nodescale.ImageQualification) (nodescale.QualifiedImage, time.Time, error) {
	region, err := oci.Region(strings.ToUpper(r.cell)).OCIRegion()
	if err != nil {
		return nodescale.QualifiedImage{}, time.Time{}, err
	}
	location, err := instancePrincipalChannel(region, strings.ToUpper(r.cell)).get(ctx)
	if err != nil {
		return nodescale.QualifiedImage{}, time.Time{}, err
	}
	return nodescale.QualifyImage(ctx, input, r.specs.hostImageSnapshot().roots,
		func(ctx context.Context, digest string) (io.ReadCloser, error) {
			return releasechannel.OpenImageProductionEvidence(ctx, location, digest)
		}, time.Now())
}

// choose uses observed SDK compatibility and current tariffs across every native
// candidate. The running controller's shape supplies no purchasing preference.
func (r *capacityReservations) choose(ctx context.Context, base nodescale.Recipe, pool *nodescale.OCIPool,
	factory *ociclient.Factory, store nodescale.RecordStore, architecture string,
) (nodescale.Recipe, error) {
	if r == nil {
		return nodescale.Recipe{}, fmt.Errorf("%w: home capacity authority is unavailable", nodescale.ErrCapacityPending)
	}
	record, _, err := store.Load(ctx)
	if err != nil {
		return nodescale.Recipe{}, err
	}
	if record.Action != nil && record.Action.Kind == nodescale.Up && record.Recipe != nil {
		if _, err := r.prepare(ctx, record.Action.ID, *record.Recipe, pool.CompartmentID()); err != nil {
			return nodescale.Recipe{}, err
		}
		return *record.Recipe, nil
	}
	reader, proof, snapshot, err := r.facts(ctx)
	if err != nil {
		return nodescale.Recipe{}, fmt.Errorf("%w: current complete spending facts: %v", nodescale.ErrCapacityPending, err)
	}
	compute, err := factory.Compute()
	if err != nil {
		return nodescale.Recipe{}, err
	}
	quotas, err := factory.Limits()
	if err != nil {
		return nodescale.Recipe{}, err
	}
	expires := snapshot.ExpiresAt
	var images []nodescale.QualifiedImage
	var shapes, pending []string
	for _, input := range r.imageInputs(base.Capacity.Role) {
		image, deadline, err := r.qualify(ctx, input)
		if err != nil {
			pending = append(pending, err.Error())
			continue
		}
		images = append(images, image)
		if deadline.Before(expires) {
			expires = deadline
		}
		for _, domain := range base.AvailabilityDomains {
			var page *string
			for {
				response, err := compute.ListShapes(ctx, core.ListShapesRequest{CompartmentId: new(pool.CompartmentID()),
					AvailabilityDomain: new(domain), ImageId: new(image.ID), Page: page})
				if err != nil {
					return nodescale.Recipe{}, fmt.Errorf("%w: current candidate compatibility: %v", nodescale.ErrCapacityPending, err)
				}
				for _, shape := range response.Items {
					if shape.Shape != nil {
						shapes = append(shapes, *shape.Shape)
					}
				}
				if response.OpcNextPage == nil {
					break
				}
				page = response.OpcNextPage
			}
		}
	}
	prices, priceErr := reader.Prices(ctx, proof.Footprint(), shapes)
	if priceErr != nil {
		pending = append(pending, priceErr.Error())
	}
	headroom, err := budget.InfrastructureHeadroom(ctx, r.global.reader, proof, snapshot, "", time.Now())
	if err != nil {
		return nodescale.Recipe{}, fmt.Errorf("%w: authorized headroom: %v", nodescale.ErrCapacityPending, err)
	}
	if deadline := time.Now().Add(2 * time.Minute); deadline.Before(expires) {
		expires = deadline
	}
	architectures := []string{"arm64", "amd64"}
	if architecture != "" {
		architectures = []string{architecture}
	}
	selection, err := nodescale.DiscoverCapacity(ctx, compute, quotas, nodescale.CapacityRequest{
		TenancyID: proof.Footprint().TenancyID, CompartmentID: pool.CompartmentID(), AvailabilityDomains: base.AvailabilityDomains,
		Role: base.Capacity.Role, Architectures: architectures, OCPUs: base.OCPUs, MemoryGB: base.MemoryGB,
		BootGB: nodescale.BootVolumeGB, Images: images, Prices: prices, MonthlyHeadroomCents: new(headroom), FactsExpireAt: expires})
	if err != nil {
		return nodescale.Recipe{}, err
	}
	if len(selection.Candidates) == 0 {
		return nodescale.Recipe{}, fmt.Errorf("%w: %s", nodescale.ErrCapacityPending, strings.Join(append(pending, selection.Pending...), "; "))
	}
	chosen := selection.Candidates[0]
	base.Capacity, base.ImageID = chosen.Capacity, chosen.ImageID
	base.OCPUs, base.MemoryGB = chosen.OCPUs, chosen.MemoryGB
	base.AvailabilityDomains = []string{chosen.AvailabilityDomain}
	return base, base.Validate()
}

func (r *capacityReservations) prepare(ctx context.Context, operationID string, recipe nodescale.Recipe, compartment string) (capacityReservationRequest, error) {
	request := capacityReservationRequest{Recipe: recipe}
	reader, proof, snapshot, err := r.facts(ctx)
	if err != nil {
		return request, fmt.Errorf("%w: current complete spending facts: %v", nodescale.ErrCapacityPending, err)
	}
	cell := ""
	for _, scope := range proof.Footprint().Regions {
		if strings.EqualFold(scope.Cell, recipe.Cell) {
			cell = scope.Cell
		}
	}
	quote, err := reader.Quote(ctx, proof.Footprint(), cell, compartment, recipe.Capacity.Shape,
		float64(recipe.OCPUs), float64(recipe.MemoryGB), nodescale.BootVolumeGB)
	if err != nil {
		return request, err
	}
	for _, input := range r.imageInputs(recipe.Capacity.Role) {
		if input.Expected.OCIImageOCID != recipe.ImageID || input.Expected.Architecture != recipe.Capacity.Architecture {
			continue
		}
		_, expires, err := r.qualify(ctx, input)
		if err != nil {
			continue
		}
		for _, deadline := range []time.Time{quote.ExpiresAt(), snapshot.ExpiresAt, proof.ExpiresAt()} {
			if deadline.Before(expires) {
				expires = deadline
			}
		}
		request.Image = input
		request.Request = budget.ReservationRequest{OperationID: operationID, RecipeSHA256: recipe.SHA256(), Cell: cell,
			CompartmentID: compartment, Shape: recipe.Capacity.Shape, OCPUs: float64(recipe.OCPUs), MemoryGB: float64(recipe.MemoryGB),
			BootGB: nodescale.BootVolumeGB, MonthlyCents: quote.MonthlyCents(), FactsExpireAt: expires}
		return request, nil
	}
	return request, fmt.Errorf("%w: no currently qualified exact host image and isolation role", nodescale.ErrCapacityPending)
}

func (r *capacityReservations) admit(pool *nodescale.OCIPool, store nodescale.RecordStore, leader authority.Fencer) func(context.Context, nodescale.Recipe) (func(), error) {
	return func(ctx context.Context, recipe nodescale.Recipe) (func(), error) {
		if r == nil || r.specs == nil {
			return nil, fmt.Errorf("%w: current home spending and image authority is unavailable", nodescale.ErrCapacityPending)
		}
		release := r.specs.holdLaunch()
		record, _, err := store.Load(ctx)
		if err != nil || record.Action == nil || record.Action.Kind != nodescale.Up || record.Recipe == nil ||
			record.Recipe.SHA256() != recipe.SHA256() || record.Reservation == nil {
			release()
			return nil, fmt.Errorf("%w: exact home receipt has not been persisted before OCI mutation", nodescale.ErrCapacityPending)
		}
		request, err := r.prepare(ctx, record.Action.ID, recipe, pool.CompartmentID())
		if err == nil {
			request.Receipt = record.Reservation
			_, err = r.request(ctx, "revalidate", request)
		}
		if err == nil {
			snapshot := leader.Current()
			if !snapshot.CanMutate() {
				err = authority.ErrNotLeader
			} else {
				err = leader.Guard(ctx, snapshot.Epoch)
			}
		}
		if err != nil {
			release()
			return nil, err
		}
		return release, nil
	}
}
