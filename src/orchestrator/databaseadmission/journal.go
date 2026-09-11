package databaseadmission

import (
	"encoding/json/v2"
	"math"
	"reflect"
	"slices"
	"strings"
	"time"

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
	CanceledPlacementRelocations map[string]bool
	EmptyPlacementRelocations    map[string]EmptyPlacementRelocation
	UnusedHostRemovals           map[string]UnusedHostRemoval
	PlacementRelocationStarted   bool
	PlacementRelocation          string
	CurrentPlacements            map[string]Record
	CompletedRelocations         map[string]string
	Deletions                    map[string]Deletion
	Records                      map[string]Record
	Lifecycle                    databaselifecycle.State
}

func newJournalState() journalState {
	return journalState{Deletions: map[string]Deletion{}, Records: map[string]Record{}, Lifecycle: databaselifecycle.NewState()}
}

func validateJournalState(state journalState) error {
	if state.Records == nil || databaselifecycle.Validate(state.Lifecycle) != nil || validateAdmissionLifecycle(state) != nil {
		return ErrInvalid
	}
	if err := validateDeletions(state); err != nil {
		return err
	}
	if err := validateCurrentPlacements(state); err != nil {
		return err
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
	if record.Restore != nil && (len(record.RestoreReceipt) != 0 && rank < 3 || rank == 4 && len(record.RestoreReceipt) == 0) {
		return ErrInvalid
	}
	if rank < 0 {
		return ErrInvalid
	}
	if len(record.Wrapped) > len(record.Request.Regions)*len(databaseKeyPurposes) {
		return ErrInvalid
	}
	if rank > 0 && len(record.Wrapped) != len(record.Request.Regions)*len(databaseKeyPurposes) {
		return ErrInvalid
	}
	regions := map[string]bool{}
	for _, entry := range record.Wrapped {
		if regions[entry.Binding.Region+"/"+entry.Binding.Purpose] || len(entry.Ciphertext) == 0 || len(entry.Ciphertext) > 8192 || entry.Revoked {
			return ErrInvalid
		}
		regions[entry.Binding.Region+"/"+entry.Binding.Purpose] = true
		match := false
		for _, target := range record.Targets {
			p := target.Provision
			p.Binding.Purpose = entry.Binding.Purpose
			if !slices.Contains(databaseKeyPurposes[:], entry.Binding.Purpose) {
				return ErrInvalid
			}
			if entry.MatchesTarget(p) {
				match = true
				break
			}
		}
		if !match {
			return ErrInvalid
		}
	}
	for _, purpose := range databaseKeyPurposes {
		count := 0
		for _, entry := range record.Wrapped {
			if entry.Binding.Purpose == purpose {
				count++
			}
		}
		if count != 0 && count != len(record.Request.Regions) {
			return ErrInvalid
		}
	}
	for _, target := range record.Targets {
		if target.Installed && rank < 1 || rank >= 2 && !target.Installed {
			return ErrInvalid
		}
	}
	if rank == 4 {
		if validateReadinessSet(record, record.ReadyEvidence, record.ReadinessNonce, nil, time.Time{}) != nil {
			return ErrInvalid
		}
	} else if len(record.ReadyEvidence) != 0 || record.ReadinessNonce != "" {
		return ErrInvalid
	}
	if record.Request.ParentDatabaseID == "" || record.Restore != nil {
		if record.BranchSource != nil || len(record.BranchEvidence) != 0 || record.BranchNonce != "" {
			return ErrInvalid
		}
	} else if len(record.BranchEvidence) > 0 {
		if rank < 3 || validateBranchRestore(record, record.BranchEvidence, record.BranchNonce, nil, time.Time{}) != nil {
			return ErrInvalid
		}
	} else if rank == 4 || record.BranchNonce != "" {
		return ErrInvalid
	}
	for _, target := range record.PlacementTargets {
		if target.Proposed && rank < 2 || rank >= 3 && !target.Proposed {
			return ErrInvalid
		}
	}
	if record.BranchSource != nil {
		if rank < 3 {
			return ErrInvalid
		}
		if _, err := validateBranchSource(record, record.BranchSource, nil, time.Time{}); err != nil {
			return err
		}
	}
	return nil
}
func stateRank(state string) int {
	return slices.Index([]string{"accepted", "keys_provisioned", "members_admitted", "placement_pending", "ready"}, state)
}

func saveRecord(state *journalState, key string, expected uint64, record Record) (uint64, error) {
	if state.PlacementRelocation != "" {
		return 0, ErrConflict
	}
	if key != ScopeKey(record.Request) || ValidateRecord(record) != nil || validateProgress(record) != nil || expected == math.MaxUint64 || record.Revision != expected {
		return 0, ErrInvalid
	}
	old, found := state.Records[key]
	if found {
		if old.Revision != expected {
			return 0, ErrJournalConflict
		}
		if !ImmutableEqual(old, record) || stateRank(record.State) < stateRank(old.State) || !wrappedPreserved(old.Wrapped, record.Wrapped) {
			return 0, ErrConflict
		}
		if len(old.RestoreReceipt) != 0 && !slices.Equal(old.RestoreReceipt, record.RestoreReceipt) {
			return 0, ErrConflict
		}
		if old.BranchSource != nil && !reflect.DeepEqual(old.BranchSource, record.BranchSource) {
			return 0, ErrConflict
		}
		if old.State == "ready" && (!sameReadiness(old.ReadyEvidence, record.ReadyEvidence) || old.ReadinessNonce != record.ReadinessNonce) {
			return 0, ErrConflict
		}
		if len(old.BranchEvidence) > 0 && (!sameReadiness(old.BranchEvidence, record.BranchEvidence) || old.BranchNonce != record.BranchNonce) {
			return 0, ErrConflict
		}
		for i, target := range old.Targets {
			if target.Installed && !record.Targets[i].Installed {
				return 0, ErrConflict
			}
		}
		for i, target := range old.PlacementTargets {
			if target.Proposed && !record.PlacementTargets[i].Proposed {
				return 0, ErrConflict
			}
			if len(target.Receipt) != 0 && (!slices.Equal(target.Receipt, record.PlacementTargets[i].Receipt) || target.Revision != record.PlacementTargets[i].Revision) {
				return 0, ErrConflict
			}
			current := record.PlacementTargets[i]
			if len(target.AcceptedReceipt) != 0 && (!slices.Equal(target.AcceptedReceipt, current.AcceptedReceipt) || !slices.Equal(target.AcceptedProof, current.AcceptedProof) || target.AcceptedRevision != current.AcceptedRevision || target.AcceptedEpoch != current.AcceptedEpoch || target.AcceptedGeneration != current.AcceptedGeneration || target.AcceptedProofDigest != current.AcceptedProofDigest) {
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
			// Epoch uniqueness is checked inside the same fenced journal CAS
			// that reserves the target, across Pipeline instances.
			if record.Restore != nil && record.Request.RestoreEpoch <= other.Request.RestoreEpoch {
				return 0, ErrConflict
			}
			if operationKey(other.Request) == operationKey(record.Request) || other.DatabaseID == record.DatabaseID {
				return 0, ErrConflict
			}
		}
	}
	if !found {
		if deletionBlocksEvent(state, admissionLifecycleEvent(record)) {
			return 0, ErrConflict
		}
		if err := databaselifecycle.Apply(&state.Lifecycle, admissionLifecycleEvent(record)); err != nil {
			return 0, err
		}
	}
	record.Revision = expected + 1
	state.Records[key] = record
	if err := validateReservedCapacity(*state); err != nil {
		return 0, err
	}
	return record.Revision, nil
}
func validateReservedCapacity(state journalState) error {
	// Reserve the largest permitted ciphertext and progress before accepting any
	// effects. Later progress must still fit while other creates are accepted.
	reserved := state
	reserved.Records = make(map[string]Record, len(state.Records))
	for key, record := range state.Records {
		// Persisted wrapped entries are immutable. Reserve their actual size;
		// only unfinished key purposes can still grow to the maximum.
		record.Wrapped = slices.Clone(record.Wrapped)
		for _, purpose := range databaseKeyPurposes {
			for _, p := range purposeTargets(record, purpose) {
				if slices.ContainsFunc(record.Wrapped, func(entry keylease.Entry) bool { return entry.Binding == p.Binding }) {
					continue
				}
				record.Wrapped = append(record.Wrapped, keylease.Entry{Binding: p.Binding, CryptoEndpoint: p.CryptoEndpoint, KEKID: p.KEKID, KEKVersionID: p.KEKVersionID, Ciphertext: strings.Repeat("\x00", 8192), LeaseSeconds: p.LeaseSeconds, NotAfter: p.NotAfter})
			}
		}
		record.State = "placement_pending"
		if len(record.ReadyEvidence) == 0 {
			record.ReadinessNonce = strings.Repeat("f", 64)
			for range record.Targets {
				record.ReadyEvidence = append(record.ReadyEvidence, SignedReadiness{KeyID: strings.Repeat("k", 128), Payload: make([]byte, 32<<10), Signature: make([]byte, 64)})
			}
		}
		if record.Request.ParentDatabaseID != "" && len(record.BranchEvidence) == 0 {
			record.BranchNonce = strings.Repeat("f", 64)
			for range record.Targets {
				record.BranchEvidence = append(record.BranchEvidence, SignedReadiness{KeyID: strings.Repeat("k", 128), Payload: make([]byte, 32<<10), Signature: make([]byte, 64)})
			}
		}
		if record.Restore != nil && len(record.RestoreReceipt) == 0 {
			record.RestoreReceipt = make([]byte, 32<<10)
		}
		record.Revision = math.MaxUint64
		reserved.Records[key] = record
	}
	reserveLifecycleCapacity(&reserved)
	reserveDeletionCapacity(&reserved)
	encoded, err := json.Marshal(reserved)
	if err != nil || len(encoded) > authorityjournal.MaximumStateBytes {
		return ErrJournalUnavailable
	}
	return nil
}
