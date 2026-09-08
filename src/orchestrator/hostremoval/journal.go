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
	ErrInvalid   = errors.New("host removal: invalid operation")
	ErrConflict  = errors.New("host removal: immutable operation conflict")
	ErrCancelled = errors.New("host removal: cancelled before effects")
	ErrMissing   = errors.New("host removal: operation missing")
	ErrPending   = errors.New("host removal: provider termination pending")
)

type Stage string

const (
	StageInventoryPending  Stage = "inventory-pending"
	StageInventoryCaptured Stage = "inventory-captured"
	StageReplacing         Stage = "replacing"
	StageFenced            Stage = "fenced"
	StageComplete          Stage = "complete"
	StageCancelled         Stage = "cancelled"
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
	PendingRequest    *RemovalRequest     `json:"pending_request,omitempty"`
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
	Reserve(context.Context, string, MemberObservation, uint64, []MemberObservation) (Operation, error)
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
		current, err = o.Journal.Reserve(ctx, operationID, member, generation, survivors)
	}
	if err != nil {
		return err
	}
	if current.ResourceID != member.ResourceID || current.MemberIdentity != member.Identity || current.Generation != generation || current.ProviderETag != member.ProviderETag {
		return ErrConflict
	}
	if current.Stage == StageCancelled {
		return ErrCancelled
	}
	if current.Stage == StageInventoryPending {
		if current.PendingRequest == nil {
			return ErrInvalid
		}
		request := *current.PendingRequest
		revision, replacements, inventoryErr := o.Inventory(ctx, request, nil)
		if inventoryErr != nil {
			return inventoryErr
		}
		current, err = o.Journal.Begin(ctx, operationID, request.Member, generation, revision, replacements, request.Survivors)
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

// Reserve durably owns the remaining inventory capacity before Capture can
// freeze admission. Only one pending reservation may exist; unrelated Begin
// and Reserve calls cannot consume its capacity. Existing stages may advance,
// with their maximum future encoded growth accounted for by capacityFits.
func (j *Journal) Reserve(ctx context.Context, operationID string, member MemberObservation, generation uint64, survivors []MemberObservation) (Operation, error) {
	if j == nil || j.journal == nil || !token(operationID) || !token(member.Identity) || !token(member.ResourceID) || !token(member.ProviderETag) || generation == 0 || member.Generation != generation || validSurvivors(member.Identity, survivors) != nil {
		return Operation{}, ErrInvalid
	}
	request := RemovalRequest{OperationID: operationID, Member: cloneObservation(member), Generation: generation, Survivors: cloneObservations(survivors)}
	want := Operation{OperationID: operationID, MemberIdentity: member.Identity, ResourceID: member.ResourceID, ProviderETag: member.ProviderETag, Generation: generation, Survivors: cloneObservations(survivors), Stage: StageInventoryPending, PendingRequest: &request}
	var out Operation
	err := j.journal.Transact(ctx, true, func(s *state) error {
		if old, found := s.Operations[operationID]; found {
			if !sameIdentity(old, want) {
				return ErrConflict
			}
			if (old.Stage == StageInventoryPending || old.Stage == StageCancelled) && !sameRequest(old.PendingRequest, &request) {
				return ErrConflict
			}
			out = cloneOperation(old)
			return nil
		}
		if pendingOther(s.Operations, operationID) {
			return ErrConflict
		}
		candidate := maps.Clone(s.Operations)
		if candidate == nil {
			candidate = map[string]Operation{}
		}
		candidate[operationID] = want
		if err := capacityFits(candidate); err != nil {
			return err
		}
		s.Operations = candidate
		out = cloneOperation(want)
		return nil
	})
	return out, err
}

// CancelPending releases exclusive inventory capacity only after the caller
// verifies a permanent authoritative cancellation that prevents this operation
// ever acquiring an admission freeze, plus absence of its placement plan. The
// confirmation must be read-only and safe to retry after a journal CAS conflict.
// A terminal tombstone preserves identity across unknown cancellation writes.
func (j *Journal) CancelPending(ctx context.Context, request RemovalRequest, confirm func(context.Context, RemovalRequest) error) (Operation, error) {
	if j == nil || j.journal == nil || ctx == nil || !token(request.OperationID) || confirm == nil {
		return Operation{}, ErrInvalid
	}
	var result Operation
	err := j.journal.Transact(ctx, true, func(s *state) error {
		current, found := s.Operations[request.OperationID]
		if !found {
			return ErrMissing
		}
		if !sameRequest(current.PendingRequest, &request) {
			return ErrConflict
		}
		if current.Stage == StageCancelled {
			result = cloneOperation(current)
			return nil
		}
		if current.Stage != StageInventoryPending {
			return ErrConflict
		}
		if err := confirm(ctx, request); err != nil {
			return err
		}
		current.Stage = StageCancelled
		s.Operations[request.OperationID] = current
		result = cloneOperation(current)
		return nil
	})
	return result, err
}

// CheckFill validates exact facts against a durable reservation before Capture
// freezes admission. It never reserves capacity itself: an existing pending
// request must own that capacity, so concurrent writers cannot invalidate it.
func (j *Journal) CheckFill(ctx context.Context, operationID string, member MemberObservation, generation, inventoryRevision uint64, replacements []Replacement, survivors []MemberObservation) error {
	_, err := j.fill(ctx, false, operationID, member, generation, inventoryRevision, replacements, survivors)
	return err
}

func (j *Journal) Begin(ctx context.Context, operationID string, member MemberObservation, generation, inventoryRevision uint64, replacements []Replacement, survivors []MemberObservation) (Operation, error) {
	return j.fill(ctx, true, operationID, member, generation, inventoryRevision, replacements, survivors)
}

func (j *Journal) fill(ctx context.Context, write bool, operationID string, member MemberObservation, generation, inventoryRevision uint64, replacements []Replacement, survivors []MemberObservation) (Operation, error) {
	if j == nil || j.journal == nil || !token(operationID) || !token(member.Identity) || !token(member.ResourceID) || !token(member.ProviderETag) || generation == 0 || inventoryRevision == 0 || validateReplacements(replacements) != nil {
		return Operation{}, ErrInvalid
	}
	want := Operation{OperationID: operationID, MemberIdentity: member.Identity, ResourceID: member.ResourceID, ProviderETag: member.ProviderETag, Generation: generation, InventoryRevision: inventoryRevision, Replacements: cloneReplacements(replacements), Survivors: cloneObservations(survivors), Stage: StageInventoryCaptured}
	var out Operation
	err := j.journal.Transact(ctx, write, func(s *state) error {
		old, found := s.Operations[operationID]
		if !found {
			return ErrMissing
		}
		if old.Stage != StageInventoryPending {
			if !sameOperation(old, want) {
				return ErrConflict
			}
			out = cloneOperation(old)
			return nil
		}
		if !sameIdentity(old, want) || old.PendingRequest == nil || !sameRequest(old.PendingRequest, &RemovalRequest{OperationID: operationID, Member: member, Generation: generation, Survivors: survivors}) {
			return ErrConflict
		}
		if pendingOther(s.Operations, operationID) {
			return ErrConflict
		}
		candidate := maps.Clone(s.Operations)
		candidate[operationID] = want
		if err := capacityFits(candidate); err != nil {
			return err
		}
		if write {
			s.Operations = candidate
		}
		out = cloneOperation(want)
		return nil
	})
	return out, err
}

func pendingOther(operations map[string]Operation, id string) bool {
	for key, operation := range operations {
		if key != id && operation.Stage == StageInventoryPending {
			return true
		}
	}
	return false
}
func sameIdentity(a, b Operation) bool {
	return a.OperationID == b.OperationID && a.MemberIdentity == b.MemberIdentity && a.ResourceID == b.ResourceID && a.ProviderETag == b.ProviderETag && a.Generation == b.Generation && jsonEqualMembers(a.Survivors, b.Survivors)
}
func sameRequest(a, b *RemovalRequest) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}
func cloneObservation(member MemberObservation) MemberObservation {
	member.EvidenceRefs = append([]string(nil), member.EvidenceRefs...)
	return member
}
func cloneObservations(members []MemberObservation) []MemberObservation {
	if members == nil {
		return nil
	}
	result := make([]MemberObservation, len(members))
	for n, member := range members {
		result[n] = cloneObservation(member)
	}
	return result
}
func cloneOperation(operation Operation) Operation {
	operation.Survivors = cloneObservations(operation.Survivors)
	operation.Replacements = cloneReplacements(operation.Replacements)
	if operation.PendingRequest != nil {
		r := *operation.PendingRequest
		r.Member = cloneObservation(r.Member)
		r.Survivors = cloneObservations(r.Survivors)
		operation.PendingRequest = &r
	}
	return operation
}

// The authority journal permits 480 KiB for each of previous and next state,
// leaving over 64 KiB for its 1 MiB envelope metadata. Replacements and identity
// are immutable after fill. The only later growth is fenced -> complete (+2).
func capacityFits(operations map[string]Operation) error {
	if err := validateMap(operations); err != nil {
		return err
	}
	encoded, err := json.Marshal(operations)
	if err != nil {
		return ErrInvalid
	}
	reserve := len(encoded)
	for _, operation := range operations {
		if operation.Stage == StageFenced {
			reserve += len(StageComplete) - len(StageFenced)
		}
	}
	if reserve > authorityjournal.MaximumStateBytes {
		return ErrInvalid
	}
	return nil
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
		if current.Stage == StageInventoryPending || stage == StageInventoryPending || current.Stage == StageCancelled || stage == StageCancelled {
			return ErrConflict
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
	pending := 0
	for key, operation := range values {
		if key != operation.OperationID || !token(key) || !token(operation.MemberIdentity) || !token(operation.ResourceID) || !token(operation.ProviderETag) || operation.Generation == 0 || !validStage(operation.Stage) || validateReplacements(operation.Replacements) != nil || validSurvivors(operation.MemberIdentity, operation.Survivors) != nil {
			return ErrInvalid
		}
		if operation.Stage == StageInventoryPending || operation.Stage == StageCancelled {
			if operation.Stage == StageInventoryPending {
				pending++
			}
			r := operation.PendingRequest
			if operation.InventoryRevision != 0 || len(operation.Replacements) != 0 || r == nil || r.OperationID != key || r.Generation != operation.Generation || r.Member.Generation != operation.Generation || r.Member.Identity != operation.MemberIdentity || r.Member.ResourceID != operation.ResourceID || r.Member.ProviderETag != operation.ProviderETag || !jsonEqualMembers(r.Survivors, operation.Survivors) {
				return ErrInvalid
			}
		} else if operation.PendingRequest != nil || operation.InventoryRevision == 0 {
			return ErrInvalid
		}
	}
	if pending > 1 {
		return ErrInvalid
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
	return value == StageInventoryPending || value == StageInventoryCaptured || value == StageReplacing || value == StageFenced || value == StageComplete || value == StageCancelled
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
