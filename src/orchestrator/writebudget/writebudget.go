// Package writebudget allocates bounded, pre-reserved write units to regional
// writers. Its state is intended to be persisted by authorityjournal, whose
// transaction fence prevents a retired GRU authority from committing grants.
package writebudget

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"math"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

var (
	ErrInvalid     = errors.New("writebudget: invalid request or state")
	ErrExhausted   = errors.New("writebudget: allowance or cap exhausted")
	ErrConflict    = errors.New("writebudget: operation conflicts with an existing grant")
	ErrNotFound    = errors.New("writebudget: grant not found")
	ErrPending     = errors.New("writebudget: revocation pending holder fence or expiry")
	ErrUnavailable = errors.New("writebudget: persistence unavailable")
)

// Policy is the billing-cycle policy in integer write units and integer minor
// currency units. Branches deliberately have no separate allowance.
type Policy struct {
	OrganizationID string
	CycleID        string
	PolicyEpoch    uint64
	ConsentEpoch   uint64
	WriterEpoch    uint64
	WriterEpochs   map[string]uint64
	Units          int64
	CostMinor      int64
	UnitCostMinor  int64
	// RateNanoDollar is the exact rate per write. When set, it is authoritative
	// and avoids fractional-cent rounding at grant boundaries.
	AllowanceNanoDollar int64
	RateNanoDollar      int64
	DatabaseCaps        map[string]int64
}

// VerifyAllocation checks the detached TSCS command signature over the exact
// domain-separated payload and returns the decoded envelope.
func VerifyAllocation(publicSPKI []byte, signed SignedAllocation) (AllocationEnvelope, error) {
	var envelope AllocationEnvelope
	if len(publicSPKI) == 0 || len(signed.Payload) == 0 || len(signed.Signature) == 0 {
		return envelope, ErrInvalid
	}
	key, err := x509.ParsePKIXPublicKey(publicSPKI)
	if err != nil {
		return envelope, ErrInvalid
	}
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return envelope, ErrInvalid
	}
	opaque, ok := protocol.OpaqueSignatureTryCopyFrom(signed.Signature)
	if !ok {
		return envelope, ErrInvalid
	}
	id, _, signature, ok := security.DecodeCommandSignature(opaque)
	if !ok || id != signed.KeyID {
		return envelope, ErrInvalid
	}
	digest := sha256.Sum256(append([]byte(allocationSigningDomain), signed.Payload...))
	if !ecdsa.VerifyASN1(ecdsaKey, digest[:], signature) {
		return envelope, ErrInvalid
	}
	if err := json.Unmarshal(signed.Payload, &envelope); err != nil || envelope.SchemaVersion != 1 {
		return envelope, ErrInvalid
	}
	return envelope, nil
}

// Request reserves Units logical writes for one holder across Regions. Region
// multiplication is performed exactly once by Allocate before state mutation.
type Request struct {
	OperationID    string
	OrganizationID string
	DatabaseID     string
	BranchID       string
	HolderID       string
	Regions        []string
	Units          int64
	PolicyEpoch    uint64
	ConsentEpoch   uint64
	WriterEpoch    uint64
	ExpiresAt      time.Time
}

// Grant is the bounded reservation delivered to a regional writer. Units is
// the already multiplied chargeable amount; it must not be multiplied again by
// a regional consumer.
type Grant struct {
	CycleID        string    `json:"cycle_id"`
	RateNanoDollar int64     `json:"rate_nano_dollar"`
	OperationID    string    `json:"operation_id"`
	OrganizationID string    `json:"organization_id"`
	DatabaseID     string    `json:"database_id"`
	BranchID       string    `json:"branch_id"`
	HolderID       string    `json:"holder_id"`
	RequestedUnits int64     `json:"requested_units"`
	IncludedUnits  int64     `json:"included_units"`
	PaidUnits      int64     `json:"paid_units"`
	Regions        []string  `json:"regions"`
	Units          int64     `json:"units"`
	CostMinor      int64     `json:"cost_minor"`
	CostNanoDollar int64     `json:"cost_nano_dollar"`
	PolicyEpoch    uint64    `json:"policy_epoch"`
	ConsentEpoch   uint64    `json:"consent_epoch"`
	WriterEpoch    uint64    `json:"writer_epoch"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Revoked        bool      `json:"revoked,omitzero"`
	Fenced         bool      `json:"fenced,omitzero"`
}

// AllocationEnvelope is the signed regional delivery document. Placement and
// billing identity are inside the signed bytes, so a writer cannot retarget or
// enlarge a grant by editing transport metadata.
type AllocationEnvelope struct {
	SchemaVersion  int    `json:"schema_version"`
	Grant          Grant  `json:"grant"`
	CycleID        string `json:"cycle_id"`
	RateNanoDollar int64  `json:"rate_nano_dollar"`
	Placement      string `json:"placement"`
}

type SignedAllocation struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
	KeyID     string `json:"key_id"`
}

const allocationSigningDomain = "terrascale.write-budget.allocation.v1\x00"

func SignAllocation(signer *security.CommandSignatureSigner, grant Grant, cycleID string, rateNanoDollar int64, placement string) (SignedAllocation, error) {
	if signer == nil || cycleID == "" || placement == "" || rateNanoDollar < 0 || grant.OperationID == "" || grant.Revoked || grant.Fenced {
		return SignedAllocation{}, ErrInvalid
	}
	envelope := AllocationEnvelope{SchemaVersion: 1, Grant: grant, CycleID: cycleID, RateNanoDollar: rateNanoDollar, Placement: placement}
	payload, err := json.Marshal(envelope)
	if err != nil || len(payload) > 64<<10 {
		return SignedAllocation{}, ErrInvalid
	}
	signature, err := signer.SignCanonicalMaterial(append([]byte(allocationSigningDomain), payload...))
	if err != nil {
		return SignedAllocation{}, ErrUnavailable
	}
	return SignedAllocation{Payload: payload, Signature: signature.Bytes(), KeyID: signer.PublicKeyID()}, nil
}

// State is the authorityjournal payload. UsedUnits and UsedCostMinor include
// every live or unreconciled grant, while DatabaseUnits aggregates all
// branches belonging to a database.
type State struct {
	ActivePolicy     Policy               `json:"active_policy"`
	AccountRevision  string               `json:"account_revision"`
	RevisionSequence uint64               `json:"revision_sequence"`
	PolicyChecksum   string               `json:"policy_checksum"`
	CycleID          string               `json:"cycle_id"`
	PolicyEpoch      uint64               `json:"policy_epoch"`
	ConsentEpoch     uint64               `json:"consent_epoch"`
	UsedUnits        int64                `json:"used_units"`
	UsedCostMinor    int64                `json:"used_cost_minor"`
	UsedNanoDollar   int64                `json:"used_nano_dollar"`
	DatabaseUnits    map[string]int64     `json:"database_units"`
	Grants           map[string]Grant     `json:"grants"`
	PendingPolicy    bool                 `json:"pending_policy,omitzero"`
	PendingGrants    map[string]time.Time `json:"pending_grants,omitempty"`
}

// ApplyPolicy atomically installs a new billing policy. Existing reservations
// remain accounted for; the new epoch fences all newly issued old-policy
// grants while their expiry/holder acknowledgements are observed separately.
func (a *Authority) ApplyPolicy(ctx context.Context, revision, checksum string, next Policy) error {
	if revision == "" || checksum == "" || next.OrganizationID != a.policy.OrganizationID || next.CycleID == "" || next.WriterEpoch == 0 || next.Units <= 0 || next.CostMinor < 0 || next.UnitCostMinor < 0 || next.RateNanoDollar < 0 {
		return ErrInvalid
	}
	return a.persist.TransactRevision(ctx, true, func(state *State, _ uint64) error {
		if err := a.validateState(state); err != nil {
			return err
		}
		if state.AccountRevision == revision && state.PolicyChecksum == checksum && next.CycleID == state.ActivePolicy.CycleID {
			return nil
		}
		if state.AccountRevision != "" && state.AccountRevision == revision {
			return ErrConflict
		}
		if state.RevisionSequence == math.MaxUint64 {
			return ErrConflict
		}
		state.RevisionSequence++
		// Restrictive caps are valid: existing reservations remain accounted for,
		// while the allocation checks below expose zero available capacity.
		next.PolicyEpoch, next.ConsentEpoch = state.ActivePolicy.PolicyEpoch+1, state.ActivePolicy.ConsentEpoch+1
		state.ActivePolicy, state.AccountRevision, state.PolicyChecksum = next, revision, checksum
		state.CycleID, state.PolicyEpoch, state.ConsentEpoch = next.CycleID, next.PolicyEpoch, next.ConsentEpoch
		state.PendingGrants = make(map[string]time.Time)
		now := a.now().UTC()
		for id, grant := range state.Grants {
			if grant.ExpiresAt.After(now) {
				grant.Revoked = true
				state.Grants[id] = grant
				state.PendingGrants[id] = grant.ExpiresAt
			}
		}
		state.PendingPolicy = len(state.PendingGrants) != 0
		return nil
	})
}

func (a *Authority) PolicyPending(ctx context.Context) (bool, error) {
	var pending bool
	err := a.persist.TransactRevision(ctx, true, func(state *State, _ uint64) error {
		if err := a.validateState(state); err != nil {
			return err
		}
		now := a.now().UTC()
		for id, deadline := range state.PendingGrants {
			if !deadline.After(now) {
				delete(state.PendingGrants, id)
			}
		}
		state.PendingPolicy = len(state.PendingGrants) != 0
		pending = state.PendingPolicy
		return nil
	})
	return pending, err
}

type Persister interface {
	TransactRevision(context.Context, bool, func(*State, uint64) error) error
}

// Authority performs bounded allocation against a fenced journal.
type Authority struct {
	persist Persister
	policy  Policy
	now     func() time.Time
}

func New(persist Persister, policy Policy) (*Authority, error) {
	if persist == nil || policy.OrganizationID == "" || policy.CycleID == "" || policy.PolicyEpoch == 0 || policy.ConsentEpoch == 0 || policy.WriterEpoch == 0 || policy.Units <= 0 || policy.CostMinor < 0 || policy.UnitCostMinor < 0 {
		return nil, ErrInvalid
	}
	if policy.RateNanoDollar < 0 || policy.AllowanceNanoDollar < 0 || policy.RateNanoDollar > 0 && policy.AllowanceNanoDollar == 0 {
		return nil, ErrInvalid
	}
	for database, cap := range policy.DatabaseCaps {
		if database == "" || cap <= 0 {
			return nil, ErrInvalid
		}
	}
	if len(policy.WriterEpochs) == 0 {
		return nil, ErrInvalid
	}
	for holder, epoch := range policy.WriterEpochs {
		if holder == "" || epoch == 0 {
			return nil, ErrInvalid
		}
	}
	return &Authority{persist: persist, policy: policy, now: time.Now}, nil
}

// NewJournalAuthority makes the production persistence boundary explicit. The
// supplied journal must have been constructed from the current GRU lease;
// every mutation then uses TransactRevision's exact live-lease fence and CAS.
func NewJournalAuthority(journal *authorityjournal.Journal[State], policy Policy) (*Authority, error) {
	return New(journal, policy)
}

func (a *Authority) Allocate(ctx context.Context, request Request) (Grant, error) {
	var result Grant
	err := a.persist.TransactRevision(ctx, true, func(state *State, _ uint64) error {
		if err := a.validateState(state); err != nil {
			return err
		}
		policy := state.ActivePolicy
		if err := validateRequest(request, policy, a.now()); err != nil {
			return err
		}
		if old, ok := state.Grants[request.OperationID]; ok {
			if sameRequest(old, request) {
				result = old
				return nil
			}
			return ErrConflict
		}
		units, ok := multiply(request.Units, int64(len(request.Regions)))
		if !ok {
			return ErrInvalid
		}
		cost, ok := multiply(units, policy.UnitCostMinor)
		if !ok {
			return ErrInvalid
		}
		nanoCost, ok := multiply(units, policy.RateNanoDollar)
		if policy.RateNanoDollar > 0 && (!ok || state.UsedNanoDollar > policy.AllowanceNanoDollar-nanoCost) {
			return ErrExhausted
		}
		if state.UsedUnits > policy.Units-units || state.UsedCostMinor > policy.CostMinor-cost {
			return ErrExhausted
		}
		cap, capped := policy.DatabaseCaps[request.DatabaseID]
		if capped && state.DatabaseUnits[request.DatabaseID] > cap-units {
			return ErrExhausted
		}
		writerEpoch, admitted := policy.WriterEpochs[request.HolderID]
		if !admitted || writerEpoch == 0 {
			return ErrInvalid
		}
		grant := Grant{CycleID: policy.CycleID, RateNanoDollar: policy.RateNanoDollar, OperationID: request.OperationID, OrganizationID: request.OrganizationID, DatabaseID: request.DatabaseID, BranchID: request.BranchID, HolderID: request.HolderID, Units: units, IncludedUnits: 0, PaidUnits: units, CostMinor: cost, CostNanoDollar: nanoCost, PolicyEpoch: request.PolicyEpoch, ConsentEpoch: request.ConsentEpoch, WriterEpoch: writerEpoch, IssuedAt: a.now().UTC(), ExpiresAt: request.ExpiresAt.UTC()}
		grant.RequestedUnits, grant.Regions = request.Units, append([]string(nil), request.Regions...)
		state.Grants[grant.OperationID] = grant
		state.UsedUnits += units
		state.UsedCostMinor += cost
		state.UsedNanoDollar += nanoCost
		state.DatabaseUnits[grant.DatabaseID] += units
		result = grant
		return nil
	})
	return result, err
}

// Revoke marks a grant revoked. Completion is reported only after its holder
// has been fenced or the grant has expired; pending state remains persisted
// and discoverable through Lookup.
func (a *Authority) Revoke(ctx context.Context, operationID string) error {
	pending := false
	err := a.persist.TransactRevision(ctx, true, func(state *State, _ uint64) error {
		if err := a.validateState(state); err != nil {
			return err
		}
		grant, ok := state.Grants[operationID]
		if !ok {
			return ErrNotFound
		}
		if grant.Revoked && (grant.Fenced || !a.now().Before(grant.ExpiresAt)) {
			return nil
		}
		grant.Revoked = true
		if !grant.Fenced && a.now().Before(grant.ExpiresAt) {
			state.Grants[operationID] = grant
			pending = true
			return nil
		}
		grant.Fenced = true
		state.Grants[operationID] = grant
		return nil
	})
	if err != nil {
		return err
	}
	if pending {
		return ErrPending
	}
	return nil
}

func (a *Authority) Fence(ctx context.Context, operationID string) error {
	return a.persist.TransactRevision(ctx, true, func(state *State, _ uint64) error {
		if err := a.validateState(state); err != nil {
			return err
		}
		grant, ok := state.Grants[operationID]
		if !ok {
			return ErrNotFound
		}
		grant.Fenced = true
		grant.Revoked = true
		state.Grants[operationID] = grant
		delete(state.PendingGrants, operationID)
		state.PendingPolicy = len(state.PendingGrants) != 0
		return nil
	})
}

func (a *Authority) Lookup(ctx context.Context, operationID string) (Grant, bool, error) {
	var result Grant
	var found bool
	err := a.persist.TransactRevision(ctx, false, func(state *State, _ uint64) error {
		if err := a.validateState(state); err != nil {
			return err
		}
		result, found = state.Grants[operationID]
		return nil
	})
	return result, found, err
}

func (a *Authority) validateState(state *State) error {
	if state == nil {
		return ErrInvalid
	}
	if state.Grants == nil {
		state.Grants = map[string]Grant{}
	}
	if state.DatabaseUnits == nil {
		state.DatabaseUnits = map[string]int64{}
	}
	if state.CycleID == "" {
		state.CycleID, state.PolicyEpoch, state.ConsentEpoch = a.policy.CycleID, a.policy.PolicyEpoch, a.policy.ConsentEpoch
	}
	if state.ActivePolicy.OrganizationID == "" {
		state.ActivePolicy = a.policy
	}
	if state.ActivePolicy.OrganizationID != a.policy.OrganizationID {
		return ErrInvalid
	}
	policy := state.ActivePolicy
	if state.CycleID != policy.CycleID || state.PolicyEpoch != policy.PolicyEpoch || state.ConsentEpoch != policy.ConsentEpoch || state.UsedUnits < 0 || state.UsedCostMinor < 0 || state.UsedNanoDollar < 0 {
		return ErrInvalid
	}
	var units, cost, nanoCost int64
	databaseUnits := make(map[string]int64, len(state.DatabaseUnits))
	for operationID, grant := range state.Grants {
		expectedWriterEpoch, admitted := policy.WriterEpochs[grant.HolderID]
		if !admitted || expectedWriterEpoch == 0 {
			return ErrInvalid
		}
		if operationID == "" || grant.OperationID != operationID || grant.OrganizationID != policy.OrganizationID || grant.CycleID == "" || grant.RateNanoDollar < 0 || grant.DatabaseID == "" || grant.HolderID == "" || grant.RequestedUnits <= 0 || grant.Units <= 0 || grant.IncludedUnits < 0 || grant.PaidUnits < 0 || grant.IncludedUnits > math.MaxInt64-grant.PaidUnits || grant.IncludedUnits+grant.PaidUnits != grant.Units || !grant.Revoked && grant.WriterEpoch != expectedWriterEpoch || grant.ExpiresAt.IsZero() || grant.IssuedAt.IsZero() || len(grant.Regions) == 0 {
			return ErrInvalid
		}
		multiplied, ok := multiply(grant.RequestedUnits, int64(len(grant.Regions)))
		if !ok || multiplied != grant.Units {
			return ErrInvalid
		}
		includedTotal, totalOK := add(grant.IncludedUnits, grant.PaidUnits)
		if grant.IncludedUnits < 0 || grant.PaidUnits < 0 || !totalOK || includedTotal != grant.Units {
			return ErrInvalid
		}
		expectedPaid, ok := multiply(grant.PaidUnits, grant.RateNanoDollar)
		if !ok || expectedPaid != grant.CostNanoDollar {
			return ErrInvalid
		}
		expectedCost, ok := multiply(grant.Units, policy.UnitCostMinor)
		if !ok || expectedCost != grant.CostMinor {
			return ErrInvalid
		}
		expectedNano, ok := multiply(grant.Units, grant.RateNanoDollar)
		if !ok || expectedNano != grant.CostNanoDollar {
			return ErrInvalid
		}
		units, ok = add(units, grant.Units)
		if !ok {
			return ErrInvalid
		}
		cost, ok = add(cost, grant.CostMinor)
		if !ok {
			return ErrInvalid
		}
		nanoCost, ok = add(nanoCost, grant.CostNanoDollar)
		if !ok {
			return ErrInvalid
		}
		databaseUnits[grant.DatabaseID], ok = add(databaseUnits[grant.DatabaseID], grant.Units)
		if !ok {
			return ErrInvalid
		}
	}
	if units != state.UsedUnits || cost != state.UsedCostMinor || nanoCost != state.UsedNanoDollar || len(databaseUnits) != len(state.DatabaseUnits) {
		return ErrInvalid
	}
	for database, used := range databaseUnits {
		if state.DatabaseUnits[database] != used {
			return ErrInvalid
		}
	}
	return nil
}

func validateRequest(r Request, p Policy, now time.Time) error {
	if r.OperationID == "" || r.OrganizationID != p.OrganizationID || r.DatabaseID == "" || r.HolderID == "" || len(r.Regions) == 0 || r.Units <= 0 || r.PolicyEpoch != p.PolicyEpoch || r.ConsentEpoch != p.ConsentEpoch || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(now) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, region := range r.Regions {
		if region == "" || seen[region] {
			return ErrInvalid
		}
		seen[region] = true
	}
	return nil
}

func sameRequest(g Grant, r Request) bool {
	if g.OrganizationID != r.OrganizationID || g.DatabaseID != r.DatabaseID || g.BranchID != r.BranchID || g.HolderID != r.HolderID || g.RequestedUnits != r.Units || g.PolicyEpoch != r.PolicyEpoch || g.ConsentEpoch != r.ConsentEpoch || !g.ExpiresAt.Equal(r.ExpiresAt.UTC()) || len(g.Regions) != len(r.Regions) {
		return false
	}
	for i := range r.Regions {
		if g.Regions[i] != r.Regions[i] {
			return false
		}
	}
	return true
}
func multiply(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || (right != 0 && left > math.MaxInt64/right) {
		return 0, false
	}
	return left * right, true
}

func add(left, right int64) (int64, bool) {
	if right > 0 && left > math.MaxInt64-right {
		return 0, false
	}
	return left + right, true
}

// MemoryPersister is a deterministic test persister. Production callers pass
// *authorityjournal.Journal[State].
type MemoryPersister struct {
	mutex sync.Mutex
	state State
}

func NewMemoryPersister() *MemoryPersister { return &MemoryPersister{} }
func (p *MemoryPersister) TransactRevision(ctx context.Context, write bool, change func(*State, uint64) error) error {
	if ctx == nil || change == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if err := change(&p.state, 1); err != nil {
		return err
	}
	return nil
}
