package app

import (
	"context"
	"fmt"

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
