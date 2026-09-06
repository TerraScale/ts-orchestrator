// Package hostremoval persists the GRU-owned host removal workflow. It records
// the immutable admission inventory before any placement transition is sent,
// allowing a successor to resume the same operation after a restart.
package hostremoval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
)

var (
	ErrInvalid  = errors.New("host removal: invalid operation")
	ErrConflict = errors.New("host removal: immutable operation conflict")
	ErrMissing  = errors.New("host removal: operation missing")
)

type Stage string

const (
	StageInventoryCaptured Stage = "inventory-captured"
	StageReplacing         Stage = "replacing"
	StageFenced            Stage = "fenced"
	StageComplete          Stage = "complete"
)

// Replacement identifies one database's already-issued placement proposal.
// ProposalDigest binds the reference to the exact signed proposal retained by
// the placement issuer; this journal never manufactures a proposal.
type Replacement struct {
	DatabaseID        string `json:"database_id"`
	IssuerOperationID string `json:"issuer_operation_id"`
	ProposalDigest    string `json:"proposal_digest"`
}

type Operation struct {
	OperationID       string              `json:"operation_id"`
	MemberIdentity    string              `json:"member_identity"`
	Generation        uint64              `json:"generation"`
	InventoryRevision uint64              `json:"inventory_revision"`
	Replacements      []Replacement       `json:"replacements"`
	Survivors         []MemberObservation `json:"survivors"`
	Stage             Stage               `json:"stage"`
}

// RemovalRequest is the exact provider observation used for inventory
// selection. It is persisted with the operation so a retry cannot silently
// select against a different OCI membership view.
type RemovalRequest struct {
	OperationID string
	Member      MemberObservation
	Generation  uint64
	Survivors   []MemberObservation
}
type MemberObservation struct {
	Identity     string   `json:"identity"`
	Region       string   `json:"region"`
	Slot         int      `json:"slot"`
	Generation   uint64   `json:"generation"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type state struct {
	Operations map[string]Operation `json:"operations"`
}

type transaction interface {
	Transact(context.Context, bool, func(*state) error) error
}

type Journal struct{ journal transaction }

// Owner executes the durable removal stages. Callers provide the existing
// placement issuer and lifecycle/control proof providers; this type only
// advances the fenced journal and invokes OCI termination after all providers
// have returned success.
type Owner struct {
	Journal   *Journal
	Inventory func(context.Context, RemovalRequest, []Replacement) (uint64, []Replacement, error)
	Replace   func(context.Context, Replacement) error
	// Revalidate rereads the authoritative admission inventory and must reject
	// any revision change or newly assigned database before fencing.
	Revalidate func(context.Context, string, string, uint64) error
	Fence      func(context.Context, string, string, []Replacement) error
	Terminate  func(context.Context, string) error
}

func (o *Owner) RemoveMember(ctx context.Context, operationID string, member MemberObservation, generation uint64, survivors ...MemberObservation) error {
	if o == nil || o.Journal == nil || o.Inventory == nil || o.Replace == nil || o.Revalidate == nil || o.Fence == nil || o.Terminate == nil {
		return ErrInvalid
	}
	request := RemovalRequest{OperationID: operationID, Member: member, Generation: generation, Survivors: append([]MemberObservation(nil), survivors...)}
	revision, replacements, err := o.Inventory(ctx, request, nil)
	if err != nil {
		return err
	}
	current, err := o.Journal.Begin(ctx, operationID, member.Identity, generation, revision, replacements, request.Survivors)
	if err != nil {
		return err
	}
	if current.Stage == StageComplete {
		return nil
	}
	replacements = current.Replacements
	if current.Stage == StageInventoryCaptured {
		if _, err = o.Journal.Advance(ctx, operationID, StageReplacing); err != nil {
			return err
		}
	}
	for _, replacement := range replacements {
		if err := o.Replace(ctx, replacement); err != nil {
			return err
		}
	}
	if err := o.Revalidate(ctx, operationID, member.Identity, current.InventoryRevision); err != nil {
		return err
	}
	if err := o.Fence(ctx, operationID, member.Identity, replacements); err != nil {
		return err
	}
	if _, err := o.Journal.Advance(ctx, operationID, StageFenced); err != nil {
		return err
	}
	if err := o.Terminate(ctx, member.Identity); err != nil {
		return err
	}
	_, err = o.Journal.Advance(ctx, operationID, StageComplete)
	return err
}

func New(config authorityjournal.Config) (*Journal, error) {
	j, err := authorityjournal.New(config, func() map[string]Operation { return map[string]Operation{} }, validateMap)
	if err != nil {
		return nil, err
	}
	return &Journal{journal: &typedJournal{journal: j}}, nil
}

// typedJournal adapts authorityjournal's map payload to the bounded internal
// state while retaining its exact lease and stream CAS semantics.
type typedJournal struct {
	journal *authorityjournal.Journal[map[string]Operation]
}

func (j *typedJournal) Transact(ctx context.Context, write bool, change func(*state) error) error {
	return j.journal.Transact(ctx, write, func(value *map[string]Operation) error {
		m := *value
		if m == nil {
			m = make(map[string]Operation)
		}
		current := state{Operations: m}
		if err := change(&current); err != nil {
			return err
		}
		*value = current.Operations
		return nil
	})
}

func (j *Journal) Begin(ctx context.Context, operationID, member string, generation, inventoryRevision uint64, replacements []Replacement, survivors []MemberObservation) (Operation, error) {
	if j == nil || j.journal == nil || !token(operationID) || !token(member) || generation == 0 || inventoryRevision == 0 || validateReplacements(replacements) != nil {
		return Operation{}, ErrInvalid
	}
	want := Operation{OperationID: operationID, MemberIdentity: member, Generation: generation, InventoryRevision: inventoryRevision, Replacements: cloneReplacements(replacements), Survivors: append([]MemberObservation(nil), survivors...), Stage: StageInventoryCaptured}
	var result Operation
	err := j.journal.Transact(ctx, true, func(s *state) error {
		if old, ok := s.Operations[operationID]; ok {
			if !sameOperation(old, want) {
				return ErrConflict
			}
			result = old
			return nil
		}
		if s.Operations == nil {
			s.Operations = map[string]Operation{}
		}
		s.Operations[operationID] = want
		result = want
		return nil
	})
	return result, err
}

func (j *Journal) Advance(ctx context.Context, operationID string, stage Stage) (Operation, error) {
	if j == nil || j.journal == nil || !token(operationID) || !validStage(stage) {
		return Operation{}, ErrInvalid
	}
	var result Operation
	err := j.journal.Transact(ctx, true, func(s *state) error {
		current, ok := s.Operations[operationID]
		if !ok {
			return ErrMissing
		}
		if stageRank(stage) < stageRank(current.Stage) {
			return ErrConflict
		}
		current.Stage = stage
		s.Operations[operationID] = current
		result = current
		return nil
	})
	return result, err
}

func (j *Journal) Load(ctx context.Context, operationID string) (Operation, error) {
	if j == nil || j.journal == nil || !token(operationID) {
		return Operation{}, ErrInvalid
	}
	var result Operation
	err := j.journal.Transact(ctx, false, func(s *state) error {
		var ok bool
		result, ok = s.Operations[operationID]
		if !ok {
			return ErrMissing
		}
		return nil
	})
	return result, err
}

func validateMap(values map[string]Operation) error {
	if len(values) > 512 {
		return ErrInvalid
	}
	for key, operation := range values {
		if key != operation.OperationID || !token(key) || !token(operation.MemberIdentity) || operation.Generation == 0 || operation.InventoryRevision == 0 || !validStage(operation.Stage) || validateReplacements(operation.Replacements) != nil || validSurvivors(operation.MemberIdentity, operation.Survivors) != nil {
			return ErrInvalid
		}
	}
	return nil
}
func validSurvivors(member string, survivors []MemberObservation) error {
	seen := map[string]bool{}
	for _, survivor := range survivors {
		if !token(survivor.Identity) || survivor.Identity == member || survivor.Region == "" || survivor.Slot < 0 || survivor.Generation == 0 || seen[survivor.Identity] {
			return ErrInvalid
		}
		seen[survivor.Identity] = true
	}
	return nil
}

func validateReplacements(values []Replacement) error {
	seen := map[string]bool{}
	for _, value := range values {
		if !token(value.DatabaseID) || !token(value.IssuerOperationID) || !digest(value.ProposalDigest) || seen[value.DatabaseID] {
			return ErrInvalid
		}
		seen[value.DatabaseID] = true
	}
	return nil
}

func cloneReplacements(values []Replacement) []Replacement {
	return append([]Replacement(nil), values...)
}
func sameOperation(a, b Operation) bool {
	return a.OperationID == b.OperationID && a.MemberIdentity == b.MemberIdentity && a.Generation == b.Generation && a.InventoryRevision == b.InventoryRevision && jsonEqual(a.Replacements, b.Replacements) && jsonEqualMembers(a.Survivors, b.Survivors)
}
func jsonEqual(a, b []Replacement) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}
func jsonEqualMembers(a, b []MemberObservation) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}
func validStage(value Stage) bool {
	return value == StageInventoryCaptured || value == StageReplacing || value == StageFenced || value == StageComplete
}
func stageRank(value Stage) int {
	switch value {
	case StageInventoryCaptured:
		return 1
	case StageReplacing:
		return 2
	case StageFenced:
		return 3
	case StageComplete:
		return 4
	default:
		return 0
	}
}
func token(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}
func digest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}
