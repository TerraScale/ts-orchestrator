package app

import (
	"context"
	"encoding/json/v2"
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
		var intent placement.Intent
		if err := json.Unmarshal(entry.Payload, &intent, json.RejectUnknownMembers(true)); err != nil || intent.Validate() != nil ||
			intent.DatabaseID+"."+intent.PartitionID != entry.SubjectKey || placementOperationID(intent) != entry.OperationID || !intentSelectsCell(intent, cell) {
			return nil, fmt.Errorf("invalid admitted placement intent for %q", entry.SubjectKey)
		}
		intents = append(intents, intent)
	}
	return intents, nil
}
