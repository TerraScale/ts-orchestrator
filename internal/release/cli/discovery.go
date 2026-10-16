package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/atlas"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
)

func discoverServingCells(ctx context.Context) ([]string, error) {
	return atlas.DiscoverServingCells(ctx, http.DefaultClient)
}

func deploymentCells(ctx context.Context, cells []string, discover func(context.Context) ([]string, error)) ([]string, error) {
	if len(cells) == 0 {
		if discover == nil {
			return nil, errors.New("serving-region discovery is unavailable")
		}
		var err error
		cells, err = discover(ctx)
		if err != nil {
			return nil, fmt.Errorf("discover serving regions: %w", err)
		}
	}
	if len(cells) == 0 {
		return nil, errors.New("serving-region discovery returned no regions")
	}
	seen := make(map[string]bool, len(cells))
	for _, cell := range cells {
		if !validRegion(cell) || seen[cell] {
			return nil, fmt.Errorf("unsupported or duplicate cell %q", cell)
		}
		seen[cell] = true
	}
	return cells, nil
}

func deploymentScope(ctx context.Context, location releasechannel.Location, cell string) (releasechannel.Status, error) {
	scope, found, err := releasechannel.ReadStatus(ctx, location)
	if err != nil {
		return scope, fmt.Errorf("read deployment scope: %w", err)
	}
	if !found {
		return scope, errors.New("regional deployment scope is missing; deploy its producer before the discovery consumer")
	}
	return scope, scope.ValidateDeploymentScope(cell, time.Now().UTC())
}
