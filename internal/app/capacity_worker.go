package app

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

type capacityWorkerAuthority interface {
	WorkerRecipes(context.Context, string, string, []byte) ([]region.VerifiedWorkerRecipe, error)
	AuthorizeWorkerRecipe(context.Context, region.WorkerRecipe) (region.VerifiedWorkerRecipe, error)
}

func workerCandidate(recipe nodescale.Recipe, compartment, environment string) region.WorkerRecipe {
	return region.WorkerRecipe{Cell: recipe.Cell, Environment: environment, Role: recipe.Capacity.Role,
		Architecture: recipe.Capacity.Architecture, Shape: recipe.Capacity.Shape, ImageID: recipe.ImageID,
		CompartmentID: compartment, SubnetID: recipe.SubnetID, NSGIDs: recipe.NSGIDs, AvailabilityDomains: recipe.AvailabilityDomains,
		OCPUs: float64(recipe.OCPUs), MemoryGB: float64(recipe.MemoryGB), BootGB: nodescale.BootVolumeGB, Metadata: recipe.Metadata}
}

func (r *capacityReservations) authorizeWorker(ctx context.Context, recipe nodescale.Recipe, compartment string) (region.VerifiedWorkerRecipe, error) {
	if r == nil || r.workers == nil {
		return region.VerifiedWorkerRecipe{}, fmt.Errorf("%w: independently signed worker role and bootstrap authority is unavailable", nodescale.ErrCapacityPending)
	}
	verified, err := r.workers.AuthorizeWorkerRecipe(ctx, workerCandidate(recipe, compartment, r.environment))
	if err != nil {
		return region.VerifiedWorkerRecipe{}, fmt.Errorf("%w: independent worker recipe: %v", nodescale.ErrCapacityPending, err)
	}
	if err := verified.Match(workerCandidate(recipe, compartment, r.environment)); err != nil {
		return region.VerifiedWorkerRecipe{}, fmt.Errorf("%w: independent worker recipe: %v", nodescale.ErrCapacityPending, err)
	}
	if err := verified.Revalidate(ctx); err != nil {
		return region.VerifiedWorkerRecipe{}, err
	}
	return verified, nil
}

func sameWorkerSpendingGrant(worker region.VerifiedWorkerRecipe, spending region.VerifiedInfrastructureSpend) error {
	profile := worker.Profile()
	if !worker.IsVerified() || !spending.IsVerified() || profile.GrantDigest() != spending.GrantDigest() || profile.Generation() != spending.Generation() {
		return fmt.Errorf("%w: worker and spending authority differ from the same signed grant generation", nodescale.ErrCapacityPending)
	}
	return nil
}

func (r *capacityReservations) workerBase(ctx context.Context, role, architecture string) (nodescale.Recipe, string, error) {
	if r == nil || r.workers == nil {
		return nodescale.Recipe{}, "", fmt.Errorf("%w: independently signed worker profiles are unavailable", nodescale.ErrCapacityPending)
	}
	caWire, err := readBoundedConfigFile(r.caFile)
	if err != nil {
		return nodescale.Recipe{}, "", err
	}
	profiles, err := r.workers.WorkerRecipes(ctx, strings.ToUpper(r.cell), role, caWire)
	if err != nil {
		return nodescale.Recipe{}, "", err
	}
	var base nodescale.Recipe
	compartment := ""
	for _, profile := range profiles {
		if !profile.IsVerified() {
			return nodescale.Recipe{}, "", fmt.Errorf("%w: worker profile is unverified", nodescale.ErrCapacityPending)
		}
		worker := profile.Recipe()
		if architecture != "" && worker.Architecture != architecture {
			continue
		}
		if err := profile.Revalidate(ctx); err != nil {
			return nodescale.Recipe{}, "", err
		}
		if compartment == "" {
			base = nodescale.Recipe{Cell: worker.Cell, Capacity: nodescale.Capacity{Role: worker.Role, Architecture: worker.Architecture, Shape: worker.Shape},
				SubnetID: worker.SubnetID, NSGIDs: worker.NSGIDs, ImageID: worker.ImageID, OCPUs: float32(worker.OCPUs), MemoryGB: float32(worker.MemoryGB), Metadata: worker.Metadata}
			compartment = worker.CompartmentID
		} else if worker.CompartmentID != compartment || worker.SubnetID != base.SubnetID || worker.OCPUs != float64(base.OCPUs) ||
			worker.MemoryGB != float64(base.MemoryGB) || worker.BootGB != nodescale.BootVolumeGB || !maps.Equal(worker.Metadata, base.Metadata) ||
			!slices.Equal(slices.Sorted(slices.Values(worker.NSGIDs)), slices.Sorted(slices.Values(base.NSGIDs))) {
			return nodescale.Recipe{}, "", fmt.Errorf("%w: worker profiles disagree on regional placement", nodescale.ErrCapacityPending)
		}
		base.AvailabilityDomains = append(base.AvailabilityDomains, worker.AvailabilityDomains...)
	}
	if compartment == "" {
		return nodescale.Recipe{}, "", fmt.Errorf("%w: no qualified worker profile matches isolation role and architecture", nodescale.ErrCapacityPending)
	}
	base.AvailabilityDomains = slices.Compact(slices.Sorted(slices.Values(base.AvailabilityDomains)))
	return base, compartment, base.Validate()
}
