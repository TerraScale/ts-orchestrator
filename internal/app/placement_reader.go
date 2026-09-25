package app

import (
	"context"
	"errors"
	"fmt"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
)

type admittedPlacementReader struct {
	cell  string
	store authority.PlacementIntentStore
}

func (r admittedPlacementReader) ListPlacementIntents(ctx context.Context, cell string) ([]placement.Intent, error) {
	if cell != r.cell || r.store == nil {
		return nil, errors.New("placement reader is not bound to this cell")
	}
	entries, err := r.store.ListPlacementIntents(ctx)
	if err != nil {
		return nil, err
	}
	intents := make([]placement.Intent, 0, len(entries))
	for _, entry := range entries {
		if entry.Kind != authority.MutationPlacementIntent || entry.Sequence == 0 || entry.Epoch == 0 ||
			len(entry.Payload) == 0 || len(entry.Payload) > maxPlacementIntentBytes {
			return nil, errors.New("admitted placement log entry is invalid")
		}
		intent, err := placement.DecodeCommittedIntent(entry.Payload)
		if err != nil || intent.DatabaseID+"."+intent.PartitionID != entry.SubjectKey ||
			intent.OperationID() != entry.OperationID || !intentSelectsCell(intent, cell) {
			return nil, fmt.Errorf("invalid admitted placement intent for %q", entry.SubjectKey)
		}
		intents = append(intents, intent)
	}
	return intents, nil
}
