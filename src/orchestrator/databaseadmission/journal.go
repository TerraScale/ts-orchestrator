package databaseadmission

import (
	"encoding/json/v2"
	"math"
	"reflect"
	"slices"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

var (
	ErrJournalConflict    = authorityjournal.ErrConflict
	ErrJournalUnavailable = authorityjournal.ErrUnavailable
	ErrEpochFenced        = authorityjournal.ErrFenced
)

type journalState struct {
	Records   map[string]Record
	Lifecycle databaselifecycle.State
}

func newJournalState() journalState {
	return journalState{Records: map[string]Record{}, Lifecycle: databaselifecycle.NewState()}
}

func validateJournalState(state journalState) error {
	if state.Records == nil || databaselifecycle.Validate(state.Lifecycle) != nil {
		return ErrInvalid
	}
	operations := map[string]bool{}
	databases := map[string]bool{}
	for key, record := range state.Records {
		if key != ScopeKey(record.Request) || record.Revision == 0 || ValidateRecord(record) != nil || validateProgress(record) != nil {
			return ErrInvalid
		}
		operation := operationKey(record.Request)
		if operations[operation] || databases[record.DatabaseID] {
			return ErrInvalid
		}
		operations[operation] = true
		databases[record.DatabaseID] = true
	}
	return nil
}
func operationKey(request Request) string {
	data, _ := json.Marshal([]string{request.Environment, request.TenantID, request.ProjectID, request.OperationID})
	return string(data)
}
func validateProgress(record Record) error {
	rank := stateRank(record.State)
	if rank < 0 {
		return ErrInvalid
	}
	if rank == 0 && len(record.Wrapped) != 0 {
		return ErrInvalid
	}
	if rank > 0 && len(record.Wrapped) != len(record.Request.Regions) {
		return ErrInvalid
	}
	regions := map[string]bool{}
	for _, entry := range record.Wrapped {
		if regions[entry.Binding.Region] || len(entry.Ciphertext) == 0 || len(entry.Ciphertext) > 8192 || entry.Revoked {
			return ErrInvalid
		}
		regions[entry.Binding.Region] = true
		match := false
		for _, target := range record.Targets {
			p := target.Provision
			if entry.Binding == p.Binding && entry.CryptoEndpoint == p.CryptoEndpoint && entry.KEKID == p.KEKID && entry.KEKVersionID == p.KEKVersionID && entry.LeaseSeconds == p.LeaseSeconds && entry.NotAfter.Equal(p.NotAfter) {
				match = true
				break
			}
		}
		if !match {
			return ErrInvalid
		}
	}
	for _, target := range record.Targets {
		if target.Installed && rank < 1 || target.Proposed && (!target.Installed || rank < 2) || rank >= 2 && !target.Installed || rank == 3 && !target.Proposed {
			return ErrInvalid
		}
	}
	return nil
}
func stateRank(state string) int {
	return slices.Index([]string{"accepted", "keys_provisioned", "members_admitted", "placement_pending"}, state)
}

func saveRecord(state *journalState, key string, expected uint64, record Record) (uint64, error) {
	if key != ScopeKey(record.Request) || ValidateRecord(record) != nil || validateProgress(record) != nil || expected == math.MaxUint64 || record.Revision != expected {
		return 0, ErrInvalid
	}
	old, found := state.Records[key]
	if found {
		if old.Revision != expected {
			return 0, ErrJournalConflict
		}
		if !ImmutableEqual(old, record) || stateRank(record.State) < stateRank(old.State) || len(old.Wrapped) > 0 && !reflect.DeepEqual(old.Wrapped, record.Wrapped) {
			return 0, ErrConflict
		}
		for i, target := range old.Targets {
			if target.Installed && !record.Targets[i].Installed || target.Proposed && !record.Targets[i].Proposed {
				return 0, ErrConflict
			}
		}
	} else {
		if expected != 0 {
			return 0, ErrJournalConflict
		}
		if record.State != "accepted" || ValidateNewRecord(record) != nil {
			return 0, ErrInvalid
		}
		for _, other := range state.Records {
			if operationKey(other.Request) == operationKey(record.Request) || other.DatabaseID == record.DatabaseID {
				return 0, ErrConflict
			}
		}
	}
	if !found {
		if err := databaselifecycle.Apply(&state.Lifecycle, databaselifecycle.Event{OperationID: PlacementOperationID(record.Request), Kind: "create", Identity: databaselifecycle.Identity{Environment: record.Request.Environment, OrganizationID: record.Request.TenantID, ProjectID: record.Request.ProjectID, DatabaseID: record.DatabaseID}, At: record.CreatedAt, Regions: record.Request.Regions}); err != nil {
			return 0, err
		}
	}
	record.Revision = expected + 1
	state.Records[key] = record
	// Reserve the largest permitted ciphertext and progress before accepting any
	// effects. Later progress must still fit while other creates are accepted.
	reserved := journalState{Records: make(map[string]Record, len(state.Records)), Lifecycle: state.Lifecycle}
	for key, record := range state.Records {
		if len(record.Wrapped) == 0 {
			seen := map[string]bool{}
			for _, target := range record.Targets {
				p := target.Provision
				if seen[p.Binding.Region] {
					continue
				}
				seen[p.Binding.Region] = true
				record.Wrapped = append(record.Wrapped, keylease.Entry{Binding: p.Binding, CryptoEndpoint: p.CryptoEndpoint, KEKID: p.KEKID, KEKVersionID: p.KEKVersionID, Ciphertext: strings.Repeat("\x00", 8192), LeaseSeconds: p.LeaseSeconds, NotAfter: p.NotAfter})
			}
		}
		record.State = "placement_pending"
		record.Revision = math.MaxUint64
		reserved.Records[key] = record
	}
	encoded, err := json.Marshal(reserved)
	if err != nil || len(encoded) > authorityjournal.MaximumStateBytes {
		return 0, ErrJournalUnavailable
	}
	return record.Revision, nil
}
