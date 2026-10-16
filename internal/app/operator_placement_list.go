package app

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

type operatorPlacementListResult struct {
	Cell       string                      `json:"cell"`
	Count      int                         `json:"count"`
	Placements []operatorPlacementIdentity `json:"placements"`
}

// operatorPlacementIdentity contains only the identity fields needed to
// distinguish current admitted placements. The signed intent stays in R3.
type operatorPlacementIdentity struct {
	DatabaseID    string       `json:"databaseId"`
	PartitionID   string       `json:"partitionId"`
	SchemaVersion int          `json:"schemaVersion"`
	Generation    uint64       `json:"generation"`
	OperationID   string       `json:"operationId"`
	PayloadSHA256 string       `json:"payloadSha256"`
	ActiveRegions []oci.Region `json:"activeRegions"`
	ClusterID     string       `json:"clusterId,omitempty"`
	TenantID      string       `json:"tenantId,omitempty"`
	ShardID       uint64       `json:"shardId,omitzero"`
}

func operatorPlacementList(ctx context.Context, cfg Config, runtime *natscell.Runtime, output io.Writer) error {
	store, err := authority.OpenReader(ctx, runtime.JetStream(), cfg.NATS.Cell)
	if err != nil {
		return fmt.Errorf("open placement control log: %w", err)
	}
	reader := admittedPlacementReader{cell: cfg.NATS.Cell, store: store}
	return writeOperatorPlacementList(ctx, cfg.NATS.Cell, reader, output)
}

func writeOperatorPlacementList(ctx context.Context, cell string, reader admittedPlacementReader, output io.Writer) error {
	intents, err := reader.ListPlacementIntents(ctx, cell)
	if err != nil {
		return fmt.Errorf("list admitted placement intents: %w", err)
	}
	result := operatorPlacementListResult{Cell: cell, Count: len(intents),
		Placements: make([]operatorPlacementIdentity, 0, len(intents))}
	seen := make(map[string]struct{}, len(intents))
	for _, intent := range intents {
		key := intent.DatabaseID + "\x00" + intent.PartitionID
		if _, duplicate := seen[key]; duplicate {
			return errors.New("admitted placement list contains a repeated database and partition")
		}
		seen[key] = struct{}{}
		result.Placements = append(result.Placements, operatorPlacementIdentity{
			DatabaseID: intent.DatabaseID, PartitionID: intent.PartitionID,
			SchemaVersion: intent.SchemaVersion, Generation: intent.Generation,
			OperationID: intent.OperationID(), PayloadSHA256: intent.PayloadDigest(),
			ActiveRegions: intent.ActiveRegions,
			ClusterID:     intent.CanonicalRoster.ClusterID, TenantID: intent.CanonicalRoster.TenantID,
			ShardID: intent.CanonicalRoster.ShardID,
		})
	}
	slices.SortFunc(result.Placements, func(a, b operatorPlacementIdentity) int {
		return cmp.Or(cmp.Compare(a.DatabaseID, b.DatabaseID), cmp.Compare(a.PartitionID, b.PartitionID))
	})
	return printJSON(output, result)
}
