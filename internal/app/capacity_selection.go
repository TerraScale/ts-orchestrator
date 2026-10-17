package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (r *capacityReservations) imageInputs(ctx context.Context, role string) ([]nodescale.ImageQualification, error) {
	if r == nil || r.specs == nil {
		return nil, fmt.Errorf("%w: current image trust is unavailable", nodescale.ErrCapacityPending)
	}
	snapshot := r.specs.hostImageSnapshot()
	ociRegion, err := oci.Region(strings.ToUpper(r.cell)).OCIRegion()
	if err != nil {
		return nil, err
	}
	location, err := instancePrincipalChannel(ociRegion, strings.ToUpper(r.cell)).get(ctx)
	if err != nil {
		return nil, err
	}
	var images []cellspec.HostImage
	var discoveryErrors []error
	for _, architecture := range []string{"arm64", "amd64"} {
		current, found, err := releasechannel.ReadCurrentImage(ctx, location, snapshot.roots,
			releasechannel.CurrentImageExpectation{Cell: strings.ToUpper(r.cell), Environment: r.environment, Architecture: architecture, Role: role}, time.Now())
		if err != nil {
			discoveryErrors = append(discoveryErrors, fmt.Errorf("%w: current %s %s image discovery: %v", nodescale.ErrCapacityPending, role, architecture, err))
			continue
		}
		if found {
			images = append(images, cellspec.HostImage{Receipt: current.ReceiptWire, Delegation: current.DelegationWire})
		}
	}
	images = append(images, snapshot.images...)
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
	if len(inputs) == 0 {
		return nil, errors.Join(discoveryErrors...)
	}
	return inputs, nil
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
	store nodescale.RecordStore, architecture string,
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
	observed, err := pool.CapacityObservation(ctx)
	if err != nil {
		return nodescale.Recipe{}, err
	}
	if observed.GrantSHA256 != proof.GrantDigest() || observed.Generation != proof.Generation() || observed.WorkerCompartmentID != pool.CompartmentID() || !strings.EqualFold(observed.Cell, r.cell) {
		return nodescale.Recipe{}, fmt.Errorf("%w: native worker facts differ from the independently signed spending grant", nodescale.ErrCapacityPending)
	}
	expires := snapshot.ExpiresAt
	if observed.ExpiresAt.Before(expires) {
		expires = observed.ExpiresAt
	}
	var shapes []string
	pending := append([]string(nil), observed.Pending...)
	for _, candidate := range observed.Candidates {
		shapes = append(shapes, candidate.Shape)
	}
	prices, priceErr := reader.Prices(ctx, proof.Footprint(), shapes)
	if priceErr != nil {
		pending = append(pending, priceErr.Error())
	}
	headroom, err := budget.InfrastructureHeadroom(ctx, r.global.reader, proof, snapshot, "", time.Now())
	if err != nil {
		return nodescale.Recipe{}, fmt.Errorf("%w: authorized headroom: %v", nodescale.ErrCapacityPending, err)
	}
	selection := nodescale.CapacitySelection{}
	for _, fact := range observed.Candidates {
		if fact.Role != base.Capacity.Role || architecture != "" && fact.Architecture != architecture || fact.OCPUs != base.OCPUs || fact.MemoryGB != base.MemoryGB || fact.BootGB != nodescale.BootVolumeGB || !slices.Contains(base.AvailabilityDomains, fact.AvailabilityDomain) {
			continue
		}
		deadline := expires
		if fact.ExpiresAt.Before(deadline) {
			deadline = fact.ExpiresAt
		}
		if !time.Now().Before(deadline) {
			pending = append(pending, "native worker capacity or spending facts expired")
			continue
		}
		monthly, known := ocicost.NodeMonthlyCents(prices, fact.Shape, float64(fact.OCPUs), float64(fact.MemoryGB), float64(fact.BootGB))
		if !known {
			pending = append(pending, fmt.Sprintf("%s actual shape/boot volume price is unknown", fact.Shape))
			continue
		}
		if monthly > headroom {
			pending = append(pending, fmt.Sprintf("monthly node cost %d exceeds authorized headroom %d cents", monthly, headroom))
			continue
		}
		selection.Candidates = append(selection.Candidates, nodescale.CapacityCandidate{Capacity: nodescale.Capacity{Role: fact.Role, Architecture: fact.Architecture, Shape: fact.Shape}, ImageID: fact.ImageID, AvailabilityDomain: fact.AvailabilityDomain, RuntimeManifestDigest: fact.ImageSHA256, OCPUs: fact.OCPUs, MemoryGB: fact.MemoryGB, BootGB: fact.BootGB, FactsExpireAt: deadline, MonthlyCents: monthly})
	}
	nodescale.RankCapacityCandidates(selection.Candidates)
	if len(selection.Candidates) == 0 {
		return nodescale.Recipe{}, fmt.Errorf("%w: %s", nodescale.ErrCapacityPending, strings.Join(pending, "; "))
	}
	for _, chosen := range selection.Candidates {
		candidate := base
		candidate.Capacity, candidate.ImageID = chosen.Capacity, chosen.ImageID
		candidate.OCPUs, candidate.MemoryGB = chosen.OCPUs, chosen.MemoryGB
		candidate.AvailabilityDomains = []string{chosen.AvailabilityDomain}
		worker, err := r.authorizeWorker(ctx, candidate, pool.CompartmentID())
		if err == nil {
			err = sameWorkerSpendingGrant(worker, proof)
		}
		if err != nil {
			pending = append(pending, err.Error())
			continue
		}
		if !time.Now().Before(chosen.FactsExpireAt) {
			return nodescale.Recipe{}, fmt.Errorf("%w: native capacity or spending facts expired during worker authorization", nodescale.ErrCapacityPending)
		}
		return candidate, candidate.Validate()
	}
	return nodescale.Recipe{}, fmt.Errorf("%w: no current candidate matches independent worker authority: %s", nodescale.ErrCapacityPending, strings.Join(pending, "; "))
}

func (r *capacityReservations) prepare(ctx context.Context, operationID string, recipe nodescale.Recipe, compartment string) (capacityReservationRequest, error) {
	request := capacityReservationRequest{Recipe: recipe}
	worker, err := r.authorizeWorker(ctx, recipe, compartment)
	if err != nil {
		return request, err
	}
	reader, proof, snapshot, err := r.facts(ctx)
	if err != nil {
		return request, fmt.Errorf("%w: current complete spending facts: %v", nodescale.ErrCapacityPending, err)
	}
	if err := sameWorkerSpendingGrant(worker, proof); err != nil {
		return request, err
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
	inputs, err := r.imageInputs(ctx, recipe.Capacity.Role)
	if err != nil {
		return request, err
	}
	for _, input := range inputs {
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
		if deadline := worker.Profile().ExpiresAt(); deadline.Before(expires) {
			expires = deadline
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
		if err == nil {
			deadline := request.Request.FactsExpireAt
			if record.Reservation.LaunchExpiresAt.Before(deadline) {
				deadline = record.Reservation.LaunchExpiresAt
			}
			err = ociclient.LimitAdmission(ctx, deadline)
		}
		if err != nil {
			release()
			return nil, err
		}
		return release, nil
	}
}
