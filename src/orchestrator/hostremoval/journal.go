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
	"maps"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
)

var (
	ErrInvalid  = errors.New("host removal: invalid operation")
	ErrConflict = errors.New("host removal: immutable operation conflict")
	ErrMissing  = errors.New("host removal: operation missing")
	ErrPending  = errors.New("host removal: provider termination pending")
)

type Stage string

const (
	StageInventoryCaptured Stage = "inventory-captured"
	StageReplacing         Stage = "replacing"
	StageFenced            Stage = "fenced"
	StageComplete          Stage = "complete"
)

// Replacement identifies one database in a durably retained successor intent.
// ProposalDigest binds the exact placement request before final proof issuance;
// the relocation owner verifies the accepted proof against that same request.
type Replacement struct {
	DatabaseID        string `json:"database_id"`
	IssuerOperationID string `json:"issuer_operation_id"`
	ProposalDigest    string `json:"proposal_digest"`
}

type Operation struct {
	OperationID       string              `json:"operation_id"`
	ProviderETag      string              `json:"provider_etag"`
	ResourceID        string              `json:"resource_id"`
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
	ProviderETag string   `json:"provider_etag"`
	ResourceID   string   `json:"resource_id"`
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
type OperationJournal interface {
	Load(context.Context, string) (Operation, error)
	Begin(context.Context, string, MemberObservation, uint64, uint64, []Replacement, []MemberObservation) (Operation, error)
	Advance(context.Context, string, Stage) (Operation, error)
}

type Owner struct {
	Journal   OperationJournal
	Inventory func(context.Context, RemovalRequest, []Replacement) (uint64, []Replacement, error)
	Replace   func(context.Context, Replacement) error
	// Revalidate rereads the authoritative admission inventory and must reject
	// any revision change or newly assigned database before fencing.
	Revalidate func(context.Context, string, string, uint64) error
	Fence      func(context.Context, string, string, []Replacement) error
	// Observe rereads the exact provider identity after an unknown termination
	// outcome. A retry is allowed only while that member is still present.
	Observe              func(context.Context, string) (bool, error)
	ReconcileTermination func(context.Context, string) error
	Terminate            func(context.Context, string) error
}

func (o *Owner) RemoveMember(ctx context.Context, operationID string, member MemberObservation, generation uint64, survivors ...MemberObservation) error {
	if o == nil || o.Journal == nil || o.Inventory == nil || o.Replace == nil || o.Revalidate == nil || o.Fence == nil || o.Observe == nil || o.Terminate == nil || o.ReconcileTermination == nil {
		return ErrInvalid
	}
	if !token(member.ResourceID) || !token(member.ProviderETag) || member.Identity == "" || generation == 0 || member.Generation != generation {
		return ErrInvalid
	}
	current, err := o.Journal.Load(ctx, operationID)
	if errors.Is(err, ErrMissing) {
		request := RemovalRequest{OperationID: operationID, Member: member, Generation: generation, Survivors: append([]MemberObservation(nil), survivors...)}
		revision, replacements, inventoryErr := o.Inventory(ctx, request, nil)
		if inventoryErr != nil {
			return inventoryErr
		}
		current, err = o.Journal.Begin(ctx, operationID, member, generation, revision, replacements, request.Survivors)
	}
	if err != nil {
		return err
	}
	if current.ResourceID != member.ResourceID || current.MemberIdentity != member.Identity || current.Generation != generation || current.ProviderETag != member.ProviderETag {
		return ErrConflict
	}
	if current.Stage == StageComplete {
		return nil
	}
	if current.Stage != StageFenced {
		if current.Stage == StageInventoryCaptured {
			if _, err = o.Journal.Advance(ctx, operationID, StageReplacing); err != nil {
				return err
			}
		}
		for _, replacement := range current.Replacements {
			if err := o.Replace(ctx, replacement); err != nil {
				return err
			}
		}
		if err := o.Revalidate(ctx, operationID, member.Identity, current.InventoryRevision); err != nil {
			return err
		}
		if err := o.Fence(ctx, operationID, member.Identity, current.Replacements); err != nil {
			return err
		}
		if _, err := o.Journal.Advance(ctx, operationID, StageFenced); err != nil {
			return err
		}
	}
	present, err := o.Observe(ctx, member.Identity)
	if err != nil {
		return err
	}
	if !present {
		// Observe may report absence only from an authoritative terminal read
		// bound to the retained resource, never from an unavailable lookup.
		if err := o.ReconcileTermination(ctx, member.Identity); err != nil {
			return err
		}
		_, err = o.Journal.Advance(ctx, operationID, StageComplete)
		return err
	}
	if err := o.Terminate(ctx, member.Identity); err != nil {
		return err
	}
	present, err = o.Observe(ctx, member.Identity)
	if err != nil {
		return err
	}
	if present {
		return ErrPending
	}
	if err := o.ReconcileTermination(ctx, member.Identity); err != nil {
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

func (j *Journal) Begin(ctx context.Context, operationID string, member MemberObservation, generation, inventoryRevision uint64, replacements []Replacement, survivors []MemberObservation) (Operation, error) {
	return j.begin(ctx, true, operationID, member, generation, inventoryRevision, replacements, survivors)
}

// CheckBegin verifies that the exact inventory can be retained without writing
// an operation. Callers must recheck under their exclusive admission freeze;
// this read alone does not reserve capacity against another concurrent writer.
func (j *Journal) CheckBegin(ctx context.Context, operationID string, member MemberObservation, generation, inventoryRevision uint64, replacements []Replacement, survivors []MemberObservation) error {
	_, err := j.begin(ctx, false, operationID, member, generation, inventoryRevision, replacements, survivors)
	return err
}

func (j *Journal) begin(ctx context.Context, write bool, operationID string, member MemberObservation, generation, inventoryRevision uint64, replacements []Replacement, survivors []MemberObservation) (Operation, error) {
	if j == nil || j.journal == nil || !token(operationID) || !token(member.Identity) || !token(member.ResourceID) || !token(member.ProviderETag) || generation == 0 || inventoryRevision == 0 || validateReplacements(replacements) != nil {
		return Operation{}, ErrInvalid
	}
	want := Operation{OperationID: operationID, MemberIdentity: member.Identity, ResourceID: member.ResourceID, ProviderETag: member.ProviderETag, Generation: generation, InventoryRevision: inventoryRevision, Replacements: cloneReplacements(replacements), Survivors: append([]MemberObservation(nil), survivors...), Stage: StageInventoryCaptured}
	var result Operation
	err := j.journal.Transact(ctx, write, func(s *state) error {
		if old, ok := s.Operations[operationID]; ok {
			if !sameOperation(old, want) {
				return ErrConflict
			}
			result = old
			return nil
		}
		candidate := maps.Clone(s.Operations)
		if candidate == nil {
			candidate = map[string]Operation{}
		}
		candidate[operationID] = want
		if err := validateMap(candidate); err != nil {
			return err
		}
		encoded, err := json.Marshal(candidate)
		if err != nil || len(encoded) > authorityjournal.MaximumStateBytes {
			return ErrInvalid
		}
		if write {
			s.Operations = candidate
		}
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
		if stageRank(stage) < stageRank(current.Stage) || stageRank(stage) > stageRank(current.Stage)+1 {
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
		if key != operation.OperationID || !token(key) || !token(operation.MemberIdentity) || !token(operation.ResourceID) || !token(operation.ProviderETag) || operation.Generation == 0 || operation.InventoryRevision == 0 || !validStage(operation.Stage) || validateReplacements(operation.Replacements) != nil || validSurvivors(operation.MemberIdentity, operation.Survivors) != nil {
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
	return a.OperationID == b.OperationID && a.MemberIdentity == b.MemberIdentity && a.ResourceID == b.ResourceID && a.ProviderETag == b.ProviderETag && a.Generation == b.Generation && a.InventoryRevision == b.InventoryRevision && jsonEqual(a.Replacements, b.Replacements) && jsonEqualMembers(a.Survivors, b.Survivors)
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
