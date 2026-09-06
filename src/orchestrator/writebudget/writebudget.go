// Package writebudget allocates bounded, pre-reserved write units to regional
// writers. Its state is intended to be persisted by authorityjournal, whose
// transaction fence prevents a retired GRU authority from committing grants.
package writebudget

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
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
	Units          int64
	CostMinor      int64
	UnitCostMinor  int64
	DatabaseCaps   map[string]int64
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
	ExpiresAt      time.Time
}

// Grant is the bounded reservation delivered to a regional writer. Units is
// the already multiplied chargeable amount; it must not be multiplied again by
// a regional consumer.
type Grant struct {
	OperationID    string    `json:"operation_id"`
	OrganizationID string    `json:"organization_id"`
	DatabaseID     string    `json:"database_id"`
	BranchID       string    `json:"branch_id"`
	HolderID       string    `json:"holder_id"`
	RequestedUnits int64     `json:"requested_units"`
	Regions        []string  `json:"regions"`
	Units          int64     `json:"units"`
	CostMinor      int64     `json:"cost_minor"`
	PolicyEpoch    uint64    `json:"policy_epoch"`
	ConsentEpoch   uint64    `json:"consent_epoch"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Revoked        bool      `json:"revoked,omitzero"`
	Fenced         bool      `json:"fenced,omitzero"`
}

// State is the authorityjournal payload. UsedUnits and UsedCostMinor include
// every live or unreconciled grant, while DatabaseUnits aggregates all
// branches belonging to a database.
type State struct {
	CycleID       string           `json:"cycle_id"`
	PolicyEpoch   uint64           `json:"policy_epoch"`
	ConsentEpoch  uint64           `json:"consent_epoch"`
	UsedUnits     int64            `json:"used_units"`
	UsedCostMinor int64            `json:"used_cost_minor"`
	DatabaseUnits map[string]int64 `json:"database_units"`
	Grants        map[string]Grant `json:"grants"`
}

type Persister interface {
	Transact(context.Context, bool, func(*State) error) error
}

// Authority performs bounded allocation against a fenced journal.
type Authority struct {
	persist Persister
	policy  Policy
	now     func() time.Time
}

func New(persist Persister, policy Policy) (*Authority, error) {
	if persist == nil || policy.OrganizationID == "" || policy.CycleID == "" || policy.PolicyEpoch == 0 || policy.ConsentEpoch == 0 || policy.Units <= 0 || policy.CostMinor < 0 || policy.UnitCostMinor < 0 {
		return nil, ErrInvalid
	}
	for database, cap := range policy.DatabaseCaps {
		if database == "" || cap <= 0 {
			return nil, ErrInvalid
		}
	}
	return &Authority{persist: persist, policy: policy, now: time.Now}, nil
}

func (a *Authority) Allocate(ctx context.Context, request Request) (Grant, error) {
	var result Grant
	err := a.persist.Transact(ctx, true, func(state *State) error {
		if err := a.validateState(state); err != nil {
			return err
		}
		if err := validateRequest(request, a.policy, a.now()); err != nil {
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
		cost, ok := multiply(units, a.policy.UnitCostMinor)
		if !ok {
			return ErrInvalid
		}
		if state.UsedUnits > a.policy.Units-units || state.UsedCostMinor > a.policy.CostMinor-cost {
			return ErrExhausted
		}
		cap, capped := a.policy.DatabaseCaps[request.DatabaseID]
		if capped && state.DatabaseUnits[request.DatabaseID] > cap-units {
			return ErrExhausted
		}
		grant := Grant{OperationID: request.OperationID, OrganizationID: request.OrganizationID, DatabaseID: request.DatabaseID, BranchID: request.BranchID, HolderID: request.HolderID, Units: units, CostMinor: cost, PolicyEpoch: request.PolicyEpoch, ConsentEpoch: request.ConsentEpoch, IssuedAt: a.now().UTC(), ExpiresAt: request.ExpiresAt.UTC()}
		grant.RequestedUnits, grant.Regions = request.Units, append([]string(nil), request.Regions...)
		state.Grants[grant.OperationID] = grant
		state.UsedUnits += units
		state.UsedCostMinor += cost
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
	err := a.persist.Transact(ctx, true, func(state *State) error {
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
	return a.persist.Transact(ctx, true, func(state *State) error {
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
		return nil
	})
}

func (a *Authority) Lookup(ctx context.Context, operationID string) (Grant, bool, error) {
	var result Grant
	var found bool
	err := a.persist.Transact(ctx, false, func(state *State) error {
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
	if state.CycleID != a.policy.CycleID || state.PolicyEpoch != a.policy.PolicyEpoch || state.ConsentEpoch != a.policy.ConsentEpoch || state.UsedUnits < 0 || state.UsedCostMinor < 0 {
		return ErrInvalid
	}
	var units, cost int64
	databaseUnits := make(map[string]int64, len(state.DatabaseUnits))
	for operationID, grant := range state.Grants {
		if operationID == "" || grant.OperationID != operationID || grant.OrganizationID != a.policy.OrganizationID || grant.DatabaseID == "" || grant.HolderID == "" || grant.RequestedUnits <= 0 || grant.Units <= 0 || grant.PolicyEpoch != a.policy.PolicyEpoch || grant.ConsentEpoch != a.policy.ConsentEpoch || grant.ExpiresAt.IsZero() || grant.IssuedAt.IsZero() || len(grant.Regions) == 0 {
			return ErrInvalid
		}
		multiplied, ok := multiply(grant.RequestedUnits, int64(len(grant.Regions)))
		if !ok || multiplied != grant.Units {
			return ErrInvalid
		}
		expectedCost, ok := multiply(grant.Units, a.policy.UnitCostMinor)
		if !ok || expectedCost != grant.CostMinor {
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
		databaseUnits[grant.DatabaseID], ok = add(databaseUnits[grant.DatabaseID], grant.Units)
		if !ok {
			return ErrInvalid
		}
	}
	if units != state.UsedUnits || cost != state.UsedCostMinor || len(databaseUnits) != len(state.DatabaseUnits) {
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
func (p *MemoryPersister) Transact(ctx context.Context, write bool, change func(*State) error) error {
	if ctx == nil || change == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if err := change(&p.state); err != nil {
		return err
	}
	return nil
}
