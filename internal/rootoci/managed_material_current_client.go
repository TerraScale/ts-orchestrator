//go:build linux

package rootoci

import (
	"context"
	"encoding/json/v2"
	"time"
)

func (client *Client) ManagedMaterialCurrent(ctx context.Context, request ManagedMaterialCurrentRequest) (ManagedMaterialCurrentReceipt, error) {
	var result ManagedMaterialCurrentReceipt
	err := client.invoke(ctx, OperationManagedMaterialCurrent, request, &result)
	if err != nil {
		return ManagedMaterialCurrentReceipt{}, err
	}
	wire, err := json.Marshal(result)
	if err != nil || len(wire) > MaxManagedMaterialCurrentBytes || ctx.Err() != nil || !time.Now().Before(result.ExpiresAt) ||
		result.Preparation.Spec.PlacementDatabaseID != request.DatabaseID || result.Preparation.PartitionID != request.PartitionID ||
		result.Preparation.Spec.PartitionID != request.PartitionID || result.Preparation.Generation == 0 || result.Preparation.Signature == "" {
		return ManagedMaterialCurrentReceipt{}, ErrUnavailable
	}
	return result, nil
}
