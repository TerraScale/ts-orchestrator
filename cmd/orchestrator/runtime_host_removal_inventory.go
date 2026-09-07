package main

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/v2"
	"slices"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

func removalInventoryRevision(records []databaseadmission.Record) (uint64, error) {
	// List is sorted by ScopeKey, but sort a copy of the canonical records by
	// database identity as an additional guard against provider ordering drift.
	canonical := slices.Clone(records)
	slices.SortFunc(canonical, func(a, b databaseadmission.Record) int { return cmp.Compare(a.DatabaseID, b.DatabaseID) })
	payload, err := json.Marshal(canonical)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256(payload)
	revision := binary.BigEndian.Uint64(sum[:8])
	if revision == 0 {
		revision = 1
	}
	return revision, nil
}
