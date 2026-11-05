package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const membershipTimeout = 10 * time.Second

func discoverServingCells(ctx context.Context) ([]string, error) {
	return servingCells(ctx, membershipLocation, time.Now().UTC())
}

func servingCells(ctx context.Context, open func(context.Context, string) (releasechannel.Location, error), now time.Time) ([]string, error) {
	cells := make([]string, 0, catalog.MaxRegions)
	for _, entry := range catalog.Founded() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		probeCtx, cancel := context.WithTimeout(ctx, membershipTimeout)
		location, err := open(probeCtx, entry.Cell)
		found := false
		if err == nil {
			var status releasechannel.Status
			status, found, err = releasechannel.ReadStatus(probeCtx, location)
			if err == nil && found {
				err = status.ValidateDeploymentScope(entry.Cell, now)
			}
		}
		cancel()
		if err != nil {
			return nil, fmt.Errorf("discover %s membership: %w", entry.Cell, err)
		}
		if found {
			cells = append(cells, entry.Cell)
		}
	}
	if len(cells) == 0 {
		return nil, errors.New("serving-region discovery found no region reporting its own release status")
	}
	return cells, nil
}

func membershipLocation(ctx context.Context, cell string) (releasechannel.Location, error) {
	bucket, err := releasechannel.BucketName(cell)
	if err != nil {
		return releasechannel.Location{}, err
	}
	factory, err := ociclient.OperatorConfig(catalog.OCIRegion(cell))
	if err != nil {
		return releasechannel.Location{}, err
	}
	client, err := factory.ObjectStorage()
	if err != nil {
		return releasechannel.Location{}, err
	}
	response, err := client.GetNamespace(ctx, objectstorage.GetNamespaceRequest{})
	if err != nil || response.Value == nil || *response.Value == "" {
		return releasechannel.Location{}, fmt.Errorf("read the Object Storage namespace of %s: %w", cell, err)
	}
	return releasechannel.Location{Client: client, Namespace: *response.Value, Bucket: bucket}, nil
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
	slices.Sort(cells)
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
