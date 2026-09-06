package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
)

// productionHostRemovalInventory is the admission-backed inventory boundary.
// It fingerprints every valid accepted record, rather than only records
// currently assigned to the member, so a newly admitted database cannot race
// the fence unnoticed. Replacement proposals are deliberately supplied by the
// replacement planner and are passed through unchanged here.
type productionHostRemovalInventory struct {
	admission *databaseadmission.NATSJournal
	journal   *hostremoval.Journal
}

func newProductionHostRemovalInventory(admission *databaseadmission.NATSJournal, journal *hostremoval.Journal) (func(context.Context, hostremoval.RemovalRequest, []hostremoval.Replacement) (uint64, []hostremoval.Replacement, error), func(context.Context, string, string, uint64) error, error) {
	if admission == nil || journal == nil {
		return nil, nil, errors.New("runtime host removal: admission and removal journals are required")
	}
	provider := productionHostRemovalInventory{admission: admission, journal: journal}
	return provider.Capture, provider.Revalidate, nil
}

func (p productionHostRemovalInventory) Capture(ctx context.Context, request hostremoval.RemovalRequest, replacements []hostremoval.Replacement) (uint64, []hostremoval.Replacement, error) {
	if ctx == nil || request.OperationID == "" || request.Member.Identity == "" || request.Generation == 0 {
		return 0, nil, errors.New("runtime host removal: invalid inventory request")
	}
	records, err := p.admission.List(ctx)
	if err != nil {
		return 0, nil, err
	}
	if err := validateRemovalInventory(request, records); err != nil {
		return 0, nil, err
	}
	revision, err := removalInventoryRevision(records)
	if err != nil {
		return 0, nil, err
	}
	return revision, slices.Clone(replacements), nil
}

func (p productionHostRemovalInventory) Revalidate(ctx context.Context, operationID, member string, revision uint64) error {
	if ctx == nil || operationID == "" || member == "" || revision == 0 {
		return errors.New("runtime host removal: invalid inventory revalidation")
	}
	operation, err := p.journal.Load(ctx, operationID)
	if err != nil {
		return err
	}
	if operation.MemberIdentity != member {
		return errors.New("runtime host removal: operation member identity changed")
	}
	records, err := p.admission.List(ctx)
	if err != nil {
		return err
	}
	request := hostremoval.RemovalRequest{OperationID: operationID, Member: hostremoval.MemberObservation{Identity: member}, Generation: operation.Generation, Survivors: slices.Clone(operation.Survivors)}
	if err := validateRemovalInventory(request, records); err != nil {
		return err
	}
	current, err := removalInventoryRevision(records)
	if err != nil {
		return err
	}
	if current != revision {
		return fmt.Errorf("runtime host removal: admission inventory changed")
	}
	return nil
}

func validateRemovalInventory(request hostremoval.RemovalRequest, records []databaseadmission.Record) error {
	memberCount := 0
	assigned := make(map[string]bool, len(request.Survivors)+1)
	for _, record := range records {
		if err := databaseadmission.ValidateRecord(record); err != nil {
			return errors.New("runtime host removal: invalid admission record")
		}
		for _, target := range record.PlacementTargets {
			if target.ServerIdentity != request.Member.Identity || target.AcceptedGeneration == 0 {
				continue
			}
			if len(target.AcceptedReceipt) == 0 || target.AcceptedRevision == 0 || target.AcceptedEpoch == 0 {
				return errors.New("runtime host removal: member assignment lacks accepted receipt")
			}
			if target.AcceptedGeneration != request.Generation {
				return fmt.Errorf("runtime host removal: member holder generation changed")
			}
			if request.Member.Region != "" && target.Region != request.Member.Region {
				return errors.New("runtime host removal: member assignment region changed")
			}
			memberCount++
		}
		for _, survivor := range request.Survivors {
			for _, target := range record.PlacementTargets {
				if target.ServerIdentity != survivor.Identity || target.AcceptedGeneration == 0 {
					continue
				}
				if len(target.AcceptedReceipt) == 0 || target.AcceptedRevision == 0 || target.AcceptedEpoch == 0 || target.AcceptedGeneration != survivor.Generation || target.Region != survivor.Region {
					return errors.New("runtime host removal: survivor assignment changed")
				}
				assigned[survivor.Identity] = true
			}
		}
	}
	if memberCount == 0 {
		return errors.New("runtime host removal: member has no accepted database assignment")
	}
	for _, survivor := range request.Survivors {
		if survivor.Identity == "" || survivor.Region == "" || survivor.Generation == 0 || !assigned[survivor.Identity] {
			return errors.New("runtime host removal: survivor has no accepted database assignment")
		}
	}
	return nil
}

func removalInventoryRevision(records []databaseadmission.Record) (uint64, error) {
	// List is sorted by ScopeKey, but sort a copy of the canonical records by
	// database identity as an additional guard against provider ordering drift.
	canonical := slices.Clone(records)
	slices.SortFunc(canonical, func(a, b databaseadmission.Record) int {
		if a.DatabaseID < b.DatabaseID {
			return -1
		}
		if a.DatabaseID > b.DatabaseID {
			return 1
		}
		return 0
	})
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
