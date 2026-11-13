package app

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/region"
)

type capacityWorkerAuthority interface {
	WorkerRecipes(context.Context, string, string, []byte) ([]region.VerifiedWorkerRecipe, error)
	AuthorizeWorkerRecipe(context.Context, region.WorkerRecipe) (region.VerifiedWorkerRecipe, error)
}
