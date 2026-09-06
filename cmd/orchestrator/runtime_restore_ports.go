package main

import (
	"context"
	"errors"
	"fmt"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

// productionAdmissionDatabaseLister is the read side of the restore bridge.
// It projects only durable, validated admission records; no creation timestamp
// or process-local inventory is treated as a serving database fact.
type productionAdmissionDatabaseLister struct {
	journal *databaseadmission.NATSJournal
}

func (l productionAdmissionDatabaseLister) ListDatabases(ctx context.Context) ([]restoredrill.Database, error) {
	if l.journal == nil {
		return nil, errors.New("restore database inventory: admission journal is unavailable")
	}
	records, err := l.journal.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("restore database inventory: %w", err)
	}
	result := make([]restoredrill.Database, 0, len(records))
	for _, record := range records {
		if databaseadmission.ValidateRecord(record) != nil {
			return nil, errors.New("restore database inventory: invalid admission record")
		}
		result = append(result, restoredrill.Database{ID: record.DatabaseID, Region: record.Request.Regions[0]})
	}
	return result, nil
}
