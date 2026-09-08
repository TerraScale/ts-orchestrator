package writebudget

import (
	"errors"
	"math"
	"strconv"
	"sync"
	"testing"
)

func TestAllocationOverflowLeavesLedgerUsable(t *testing.T) {
	for _, rate := range []int64{1, 2} {
		t.Run(strconv.FormatInt(rate, 10), func(t *testing.T) {
			policy := fundingPolicy("cycle")
			policy.OrganizationSpendCap = nil
			policy.RateNanoDollar = rate
			persist := NewMemoryPersister()
			authority, err := New(persist, policy)
			if err != nil {
				t.Fatal(err)
			}
			first := fundingRequest("first", "cycle", 1, math.MaxInt64/rate)
			grant, err := authority.Allocate(t.Context(), first)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authority.Allocate(t.Context(), fundingRequest("overflow", "cycle", 1, 1)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("overflow error = %v", err)
			}
			if retained, found, err := authority.Lookup(t.Context(), "first"); err != nil || !found || retained.Units != grant.Units {
				t.Fatalf("ledger damaged: grant=%+v found=%v err=%v", retained, found, err)
			}
			if _, found, err := authority.Lookup(t.Context(), "overflow"); err != nil || found {
				t.Fatalf("overflow grant persisted: found=%v err=%v", found, err)
			}
		})
	}
}

func TestPolicyEpochOverflowDoesNotRetireCurrentRevision(t *testing.T) {
	for _, field := range []string{"policy", "consent"} {
		t.Run(field, func(t *testing.T) {
			policy := fundingPolicy("cycle")
			if field == "policy" {
				policy.PolicyEpoch = math.MaxUint64
			} else {
				policy.ConsentEpoch = math.MaxUint64
			}
			persist := NewMemoryPersister()
			authority, err := New(persist, policy)
			if err != nil {
				t.Fatal(err)
			}
			if err := authority.ApplyPolicy(t.Context(), "next", "checksum", 1, fundingPolicy("next-cycle")); !errors.Is(err, ErrConflict) {
				t.Fatalf("epoch overflow error = %v", err)
			}
			if persist.state.CycleID != "cycle" || persist.state.AccountRevision != "" || persist.state.RevisionSequence != 0 || len(persist.state.ClosedCycles) != 0 {
				t.Fatalf("overflow changed policy: %+v", persist.state)
			}
		})
	}
}

func TestPolicyUpdateDoesNotAwaitAlreadyFencedGrant(t *testing.T) {
	authority, err := New(NewMemoryPersister(), fundingPolicy("cycle"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Allocate(t.Context(), fundingRequest("grant", "cycle", 1, 1)); err != nil {
		t.Fatal(err)
	}
	if err := authority.Fence(t.Context(), "grant"); err != nil {
		t.Fatal(err)
	}
	if err := authority.ApplyPolicy(t.Context(), "next", "checksum", 1, fundingPolicy("cycle")); err != nil {
		t.Fatal(err)
	}
	if pending, err := authority.PolicyPending(t.Context()); err != nil || pending {
		t.Fatalf("fenced holder became pending: pending=%v err=%v", pending, err)
	}
}

func TestConcurrentRegionalReservationsRespectBothCapScopesAndReplay(t *testing.T) {
	policy := fundingPolicy("cycle")
	policy.OrganizationSpendCap = new(int64(12000))
	policy.DatabaseSpendCaps = map[string]*int64{"db-a": new(int64(6000)), "db-b": new(int64(6000))}
	persist := NewMemoryPersister()
	authority, err := New(persist, policy)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			request := fundingRequest("concurrent-"+strconv.Itoa(i), "cycle", 1, 1)
			request.DatabaseID = []string{"db-a", "db-b"}[i%2]
			request.BranchID = "branch-" + strconv.Itoa(i)
			request.Regions = []string{"fra", "gru", "sfo"}
			grant, err := authority.Allocate(t.Context(), request)
			if errors.Is(err, ErrExhausted) {
				return
			}
			if err != nil {
				t.Errorf("allocation: %v", err)
				return
			}
			replay, err := authority.Allocate(t.Context(), request)
			if err != nil || replay.CostNanoDollar != grant.CostNanoDollar || replay.Units != 3 || !replay.IssuedAt.Equal(grant.IssuedAt) {
				t.Errorf("replay=%+v err=%v", replay, err)
			}
		})
	}
	wg.Wait()
	if persist.state.UsedNanoDollar != 12000 || persist.state.UsedUnits != 12 || len(persist.state.Grants) != 4 || persist.state.DatabaseSpendNano["db-a"] != 6000 || persist.state.DatabaseSpendNano["db-b"] != 6000 {
		t.Fatalf("concurrent cap ledger = %+v", persist.state)
	}
}
