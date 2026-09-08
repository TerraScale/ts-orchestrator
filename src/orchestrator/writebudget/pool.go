package writebudget

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// PoolRefillRequest asks GRU to reserve a bounded local credit tranche for an
// admitted writer. The request is authenticated by the host-control transport;
// the holder and placement fields are checked against that authenticated
// identity before this request reaches ReservePool.
type PoolRefillRequest struct {
	RefillOperationID string    `json:"refill_operation_id"`
	PoolID            string    `json:"pool_id"`
	OrganizationID    string    `json:"organization_id"`
	DatabaseID        string    `json:"database_id"`
	BranchID          string    `json:"branch_id"`
	HolderID          string    `json:"holder_id"`
	Region            string    `json:"region"`
	Regions           []string  `json:"selected_regions"`
	Placement         string    `json:"placement"`
	Units             int64     `json:"requested_local_units"`
	AvailableLocal    int64     `json:"available_local_units"`
	MaxPoolUnits      int64     `json:"pool_max_local_units"`
	LowWaterUnits     int64     `json:"low_water_local_units"`
	PolicyEpoch       uint64    `json:"policy_epoch"`
	ConsentEpoch      uint64    `json:"consent_epoch"`
	WriterEpoch       uint64    `json:"writer_epoch"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// PoolGrant is the schema-2 signed refill payload. Units are local credits;
// AggregateUnits is the single Region-multiplied reservation at GRU.
type PoolGrant struct {
	SchemaVersion     int       `json:"schema_version"`
	Kind              string    `json:"kind"`
	RefillOperationID string    `json:"refill_operation_id"`
	PoolID            string    `json:"pool_id"`
	CycleID           string    `json:"cycle_id"`
	RateNanoDollar    int64     `json:"rate_nano_dollar"`
	OrganizationID    string    `json:"organization_id"`
	DatabaseID        string    `json:"database_id"`
	BranchID          string    `json:"branch_id"`
	HolderID          string    `json:"holder_id"`
	Region            string    `json:"region"`
	Regions           []string  `json:"selected_regions"`
	Placement         string    `json:"placement"`
	LocalUnits        int64     `json:"local_units"`
	AggregateUnits    int64     `json:"aggregate_units"`
	IncludedLocal     int64     `json:"included_local_units"`
	PaidLocal         int64     `json:"paid_local_units"`
	IncludedAggregate int64     `json:"included_aggregate_units"`
	PaidAggregate     int64     `json:"paid_aggregate_units"`
	PoolSequence      uint64    `json:"pool_sequence"`
	PolicyEpoch       uint64    `json:"policy_epoch"`
	ConsentEpoch      uint64    `json:"consent_epoch"`
	WriterEpoch       uint64    `json:"writer_epoch"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// PoolRefill records a GRU reservation and its still-unconsumed local credits.
// It is deliberately distinct from a customer operation grant.
type PoolRefill struct {
	Grant             PoolGrant         `json:"grant"`
	Request           PoolRefillRequest `json:"request"`
	RemainingLocal    int64             `json:"remaining_local"`
	RemainingIncluded int64             `json:"remaining_included"`
	RemainingPaid     int64             `json:"remaining_paid"`
	Reclaimed         bool              `json:"reclaimed,omitzero"`
}

// PoolOperation is the durable idempotency record for one customer operation.
type PoolOperation struct {
	OperationID       string `json:"operation_id"`
	RefillOperationID string `json:"refill_operation_id"`
	PoolID            string `json:"pool_id"`
	DatabaseID        string `json:"database_id"`
	BodyDigest        string `json:"body_digest"`
	LocalUnits        int64  `json:"local_units"`
	Aggregate         int64  `json:"aggregate_units"`
	IncludedAggregate int64  `json:"included_aggregate_units"`
	PaidAggregate     int64  `json:"paid_aggregate_units"`
	CostNanoDollar    int64  `json:"cost_nano_dollar"`
}

type PoolState struct {
	PoolID         string   `json:"pool_id"`
	OrganizationID string   `json:"organization_id"`
	DatabaseID     string   `json:"database_id"`
	HolderID       string   `json:"holder_id"`
	Region         string   `json:"region"`
	Regions        []string `json:"regions"`
	Placement      string   `json:"placement"`
	WriterEpoch    uint64   `json:"writer_epoch"`
	NextSequence   uint64   `json:"next_sequence"`
	AvailableLocal int64    `json:"available_local"`
	MaxLocal       int64    `json:"max_local"`
}

// AllocationEnvelopeV2 is signed as a pool refill. It is intentionally a new
// type: schema-1 operation-specific readers must be removed with migration.
type AllocationEnvelopeV2 struct {
	SchemaVersion int       `json:"schema_version"`
	Grant         PoolGrant `json:"grant"`
}

type SignedPoolAllocation struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
	KeyID     string `json:"key_id"`
}

const poolRefillSigningDomain = "terrascale.write-budget.pool-refill.v2\x00"

func SignPoolRefill(signer *security.CommandSignatureSigner, grant PoolGrant) (SignedPoolAllocation, error) {
	if signer == nil || grant.SchemaVersion != 2 || grant.Kind != "regional_write_pool_refill" || grant.RefillOperationID == "" || grant.PoolID == "" || grant.Placement == "" || grant.LocalUnits <= 0 || grant.AggregateUnits <= 0 || grant.Revoked() {
		return SignedPoolAllocation{}, ErrInvalid
	}
	payload, err := json.Marshal(AllocationEnvelopeV2{SchemaVersion: 2, Grant: grant})
	if err != nil || len(payload) > 64<<10 {
		return SignedPoolAllocation{}, ErrInvalid
	}
	signature, err := signer.SignCanonicalMaterial(append([]byte(poolRefillSigningDomain), payload...))
	if err != nil {
		return SignedPoolAllocation{}, ErrUnavailable
	}
	return SignedPoolAllocation{Payload: payload, Signature: signature.Bytes(), KeyID: signer.PublicKeyID()}, nil
}

// Revoked is reserved for schema parity with the old grant envelope. Pool
// refills are fenced by expiry/epoch and never carry a mutable revoke bit.
func (g PoolGrant) Revoked() bool { return g.ExpiresAt.IsZero() || g.ExpiresAt.Before(g.IssuedAt) }

func validatePoolRequest(r PoolRefillRequest, p Policy, now time.Time) error {
	if r.RefillOperationID == "" || r.PoolID == "" || r.OrganizationID != p.OrganizationID || r.DatabaseID == "" || r.HolderID == "" || r.Region == "" || r.Placement == "" || r.Units <= 0 || r.MaxPoolUnits <= 0 || r.LowWaterUnits < 0 || r.LowWaterUnits >= r.MaxPoolUnits || r.PolicyEpoch != p.PolicyEpoch || r.ConsentEpoch != p.ConsentEpoch || r.ExpiresAt.IsZero() || !r.ExpiresAt.After(now) || r.Units > r.MaxPoolUnits || r.MaxPoolUnits > 1024 || r.AvailableLocal < 0 || r.AvailableLocal > r.LowWaterUnits || r.Units > r.MaxPoolUnits-r.AvailableLocal {
		return ErrInvalid
	}
	if !slices.IsSorted(r.Regions) || len(r.Regions) == 0 || slices.Contains(r.Regions[1:], r.Regions[0]) || !slices.Contains(r.Regions, r.Region) {
		return ErrInvalid
	}
	for i, region := range r.Regions {
		if strings.TrimSpace(region) != region || region == "" || (i > 0 && region == r.Regions[i-1]) {
			return ErrInvalid
		}
	}
	if epoch := p.WriterEpochs[r.HolderID]; epoch == 0 || epoch != r.WriterEpoch {
		return ErrInvalid
	}
	return nil
}

func (a *Authority) ReservePool(ctx context.Context, request PoolRefillRequest) (PoolGrant, error) {
	var result PoolGrant
	err := a.persist.TransactRevision(ctx, true, func(state *State, _ uint64) error {
		if err := a.validateState(state); err != nil {
			return err
		}
		now := a.now().UTC()
		policy := state.ActivePolicy
		if prior, ok := state.PoolRefills[request.RefillOperationID]; ok {
			left, _ := json.Marshal(prior.Request)
			right, _ := json.Marshal(request)
			if string(left) != string(right) {
				return ErrConflict
			}
			result = prior.Grant
			return nil
		}
		if request.ExpiresAt.After(now.Add(poolReservationMaxLifetime)) {
			return ErrInvalid
		}
		if err := validatePoolRequest(request, policy, now); err != nil {
			return err
		}

		pool := state.Pools[request.PoolID]
		if pool.PoolID != "" && (pool.OrganizationID != request.OrganizationID || pool.DatabaseID != request.DatabaseID || pool.HolderID != request.HolderID || pool.Region != request.Region || pool.Placement != request.Placement || pool.WriterEpoch != request.WriterEpoch || !slices.Equal(pool.Regions, request.Regions)) {
			return ErrConflict
		}
		current := pool.AvailableLocal
		if pool.PoolID == "" {
			pool = PoolState{PoolID: request.PoolID, OrganizationID: request.OrganizationID, DatabaseID: request.DatabaseID, HolderID: request.HolderID, Region: request.Region, Regions: slices.Clone(request.Regions), Placement: request.Placement, WriterEpoch: request.WriterEpoch, MaxLocal: request.MaxPoolUnits}
		}
		if pool.MaxLocal != request.MaxPoolUnits {
			return ErrConflict
		}
		if current > pool.MaxLocal-request.Units {
			return ErrExhausted
		}
		aggregate, ok := multiply(request.Units, int64(len(request.Regions)))
		if !ok {
			return ErrInvalid
		}
		remainingAllowance := policy.IncludedAllowanceUnits - state.UsedIncluded - state.ReservedIncluded
		if remainingAllowance < 0 {
			remainingAllowance = 0
		}
		includedLocal := min(request.Units, remainingAllowance/int64(len(request.Regions)))
		paidLocal := request.Units - includedLocal
		paidAggregate, ok := multiply(paidLocal, int64(len(request.Regions)))
		if !ok || paidAggregate > 0 && !policy.PaidExcessEnabled {
			return ErrExhausted
		}
		paidNano, ok := multiply(paidAggregate, policy.RateNanoDollar)
		if !ok {
			return ErrInvalid
		}
		reservedNano, ok := add(state.ReservedPaidNano, paidNano)
		if !ok {
			return ErrInvalid
		}
		databaseReservedNano, ok := add(state.DatabaseReservedPaidNano[request.DatabaseID], paidNano)
		if !ok {
			return ErrInvalid
		}
		if paidAggregate > 0 && policy.OrganizationSpendCap != nil && !withinCap(*policy.OrganizationSpendCap, policy.AccruedNonWriteNano, state.UsedNanoDollar, reservedNano) {
			return ErrExhausted
		}
		if paidAggregate > 0 {
			if cap, present := policy.DatabaseSpendCaps[request.DatabaseID]; present && cap != nil && !withinCap(*cap, policy.DatabaseAccruedNonWriteNano[request.DatabaseID], state.DatabaseSpendNano[request.DatabaseID], databaseReservedNano) {
				return ErrExhausted
			}
		}
		if pool.NextSequence == ^uint64(0) {
			return ErrInvalid
		}
		pool.NextSequence++
		grant := PoolGrant{SchemaVersion: 2, Kind: "regional_write_pool_refill", RefillOperationID: request.RefillOperationID, PoolID: request.PoolID, CycleID: policy.CycleID, RateNanoDollar: policy.RateNanoDollar, OrganizationID: request.OrganizationID, DatabaseID: request.DatabaseID, BranchID: request.BranchID, HolderID: request.HolderID, Region: request.Region, Regions: slices.Clone(request.Regions), Placement: request.Placement, LocalUnits: request.Units, AggregateUnits: aggregate, IncludedLocal: includedLocal, PaidLocal: paidLocal, PolicyEpoch: request.PolicyEpoch, ConsentEpoch: request.ConsentEpoch, WriterEpoch: request.WriterEpoch, PoolSequence: pool.NextSequence, IssuedAt: now, ExpiresAt: request.ExpiresAt.UTC()}
		grant.IncludedAggregate, _ = multiply(includedLocal, int64(len(request.Regions)))
		grant.PaidAggregate = paidAggregate
		state.PoolRefills[request.RefillOperationID] = PoolRefill{Grant: grant, Request: request, RemainingLocal: request.Units, RemainingIncluded: includedLocal, RemainingPaid: paidLocal}
		pool.AvailableLocal += request.Units
		pool.MaxLocal = request.MaxPoolUnits
		state.Pools[request.PoolID] = pool
		state.ReservedUnits, _ = add(state.ReservedUnits, aggregate)
		state.ReservedIncluded, _ = add(state.ReservedIncluded, grant.IncludedAggregate)
		state.ReservedPaidNano = reservedNano
		state.DatabaseReservedUnits[request.DatabaseID], _ = add(state.DatabaseReservedUnits[request.DatabaseID], aggregate)
		state.DatabaseReservedPaidNano[request.DatabaseID] = databaseReservedNano
		result = grant
		return nil
	})
	return result, err
}

var poolReservationMaxLifetime = 15 * time.Minute

// PoolConsumption is submitted after a member's local durable origin commit.
type PoolConsumption struct {
	Sequence          uint64 `json:"sequence"`
	OperationID       string `json:"operation_id"`
	PoolID            string `json:"pool_id"`
	RefillOperationID string `json:"refill_operation_id"`
	DatabaseID        string `json:"database_id"`
	BodyDigest        string `json:"body_digest"`
	LocalUnits        int64  `json:"local_units"`
}

func (a *Authority) RecordPoolConsumption(ctx context.Context, consumption PoolConsumption) (PoolOperation, error) {
	var result PoolOperation
	err := a.persist.TransactRevision(ctx, true, func(state *State, _ uint64) error {
		if err := a.validateState(state); err != nil || consumption.OperationID == "" || consumption.PoolID == "" || consumption.DatabaseID == "" || consumption.BodyDigest == "" || consumption.LocalUnits <= 0 {
			return ErrInvalid
		}
		if prior, ok := state.PoolOperations[consumption.OperationID]; ok {
			if prior.RefillOperationID == consumption.RefillOperationID && prior.PoolID == consumption.PoolID && prior.DatabaseID == consumption.DatabaseID && prior.BodyDigest == consumption.BodyDigest && prior.LocalUnits == consumption.LocalUnits {
				result = prior
				return nil
			}
			return ErrConflict
		}
		pool := state.Pools[consumption.PoolID]
		if pool.PoolID == "" || pool.DatabaseID != consumption.DatabaseID || pool.AvailableLocal < consumption.LocalUnits {
			return ErrExhausted
		}
		refill, ok := state.PoolRefills[consumption.RefillOperationID]
		if !ok || refill.Reclaimed || refill.Grant.PoolID != consumption.PoolID || refill.Grant.DatabaseID != consumption.DatabaseID || refill.RemainingLocal < consumption.LocalUnits {
			return ErrExhausted
		}
		includedLocal := min(consumption.LocalUnits, refill.RemainingIncluded)
		paidLocal := consumption.LocalUnits - includedLocal
		refill.RemainingLocal -= consumption.LocalUnits
		refill.RemainingIncluded -= includedLocal
		refill.RemainingPaid -= paidLocal
		state.PoolRefills[consumption.RefillOperationID] = refill

		aggregate, ok := multiply(consumption.LocalUnits, int64(len(pool.Regions)))
		if !ok {
			return ErrInvalid
		}
		pool.AvailableLocal -= consumption.LocalUnits
		state.Pools[consumption.PoolID] = pool
		state.ReservedUnits -= aggregate
		includedAggregate, _ := multiply(includedLocal, int64(len(pool.Regions)))
		paidAggregate, _ := multiply(paidLocal, int64(len(pool.Regions)))
		cost, _ := multiply(paidAggregate, refill.Grant.RateNanoDollar)
		state.ReservedIncluded -= includedAggregate
		state.ReservedPaidNano -= cost
		state.DatabaseReservedUnits[consumption.DatabaseID] -= aggregate
		state.DatabaseReservedPaidNano[consumption.DatabaseID] -= cost
		state.UsedUnits, _ = add(state.UsedUnits, aggregate)
		state.UsedIncluded, _ = add(state.UsedIncluded, includedAggregate)
		state.UsedPaid, _ = add(state.UsedPaid, paidAggregate)
		state.UsedNanoDollar, _ = add(state.UsedNanoDollar, cost)
		state.DatabaseUnits[consumption.DatabaseID], _ = add(state.DatabaseUnits[consumption.DatabaseID], aggregate)
		state.DatabaseSpendNano[consumption.DatabaseID], _ = add(state.DatabaseSpendNano[consumption.DatabaseID], cost)
		state.PoolOperations[consumption.OperationID] = PoolOperation{OperationID: consumption.OperationID, RefillOperationID: consumption.RefillOperationID, PoolID: consumption.PoolID, DatabaseID: consumption.DatabaseID, BodyDigest: consumption.BodyDigest, LocalUnits: consumption.LocalUnits, Aggregate: aggregate, IncludedAggregate: includedAggregate, PaidAggregate: paidAggregate, CostNanoDollar: cost}
		result = state.PoolOperations[consumption.OperationID]
		return nil
	})
	return result, err
}

func poolBodyDigest(body []byte) string { return stringHex(sha256.Sum256(body)) }

func stringHex(sum [32]byte) string {
	const hex = "0123456789abcdef"
	var out [64]byte
	for i, b := range sum {
		out[i*2], out[i*2+1] = hex[b>>4], hex[b&15]
	}
	return string(out[:])
}

var errPoolContract = errors.New("writebudget: pool contract unavailable")

// LookupState is a read-only evidence hook for composition and recovery
// checks. It returns the journal state only after the same invariant validation
// used by mutations.
func (a *Authority) LookupState(ctx context.Context) (State, bool, error) {
	var result State
	var found bool
	if a == nil || a.persist == nil {
		return result, false, errPoolContract
	}
	err := a.persist.TransactRevision(ctx, false, func(state *State, _ uint64) error {
		if err := a.validateState(state); err != nil {
			return err
		}
		result = *state
		found = true
		return nil
	})
	return result, found, err
}
