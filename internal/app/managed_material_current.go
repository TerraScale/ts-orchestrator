//go:build linux

package app

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

type sdkManagedMaterialCurrent struct {
	client *rootoci.Client
}

func (reader sdkManagedMaterialCurrent) Current(ctx context.Context, database, partition string) (managedmaterial.PreparationReceipt, error) {
	if reader.client == nil || ctx == nil || ctx.Err() != nil {
		return managedmaterial.PreparationReceipt{}, rootoci.ErrUnauthorized
	}
	result, err := reader.client.ManagedMaterialCurrent(ctx, rootoci.ManagedMaterialCurrentRequest{DatabaseID: database, PartitionID: partition})
	if err != nil {
		return managedmaterial.PreparationReceipt{}, err
	}
	if ctx.Err() != nil || !time.Now().Before(result.ExpiresAt) || result.Preparation.Spec.PlacementDatabaseID != database ||
		result.Preparation.PartitionID != partition || result.Preparation.Spec.PartitionID != partition {
		return managedmaterial.PreparationReceipt{}, rootoci.ErrUnauthorized
	}
	return result.Preparation, nil
}
