package writebudget

import (
	"errors"
	"math"
	"testing"
)

func TestAccruedNonWriteSpendConsumesBothCapsWithoutRegionRemultiplication(t *testing.T) {
	p := fundingPolicy("cycle")
	p.IncludedAllowanceUnits = 0
	p.OrganizationSpendCap = new(int64(10_000))
	p.DatabaseSpendCaps = map[string]*int64{"db": new(int64(9_000))}
	p.AccruedNonWriteNano = 7_000
	p.DatabaseAccruedNonWriteNano = map[string]int64{"db": 4_000, "other": 2_000}
	a, err := New(NewMemoryPersister(), p)
	if err != nil {
		t.Fatal(err)
	}
	r := fundingRequest("first", "cycle", 1, 1)
	r.PolicyEpoch, r.ConsentEpoch = p.PolicyEpoch, p.ConsentEpoch
	r.Regions = []string{"GRU", "SFO", "FRA"}
	if g, err := a.Allocate(t.Context(), r); err != nil || g.CostNanoDollar != 3_000 {
		t.Fatalf("grant=%+v err=%v", g, err)
	}
	r.OperationID, r.DatabaseID, r.Regions = "second", "other", []string{"GRU"}
	if _, err := a.Allocate(t.Context(), r); !errors.Is(err, ErrExhausted) {
		t.Fatalf("organization cap bypass: %v", err)
	}
}

func TestAccrualUpdatesSameAccountRevisionRetainHistoryAndRejectReplay(t *testing.T) {
	p := fundingPolicy("cycle")
	persist := NewMemoryPersister()
	a, err := New(persist, p)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ApplyPolicy(t.Context(), "uuid-a", "first", 1, p); err != nil {
		t.Fatal(err)
	}
	p.AccruedNonWriteNano = 500
	if err := a.ApplyPolicy(t.Context(), "uuid-a", "accrual", 2, p); err != nil {
		t.Fatal(err)
	}
	if err := a.ApplyPolicy(t.Context(), "uuid-a", "first", 1, p); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale generation: %v", err)
	}
	p.AccruedNonWriteNano = 0
	if err := a.ApplyPolicy(t.Context(), "uuid-a", "reset", 3, p); !errors.Is(err, ErrConflict) {
		t.Fatalf("accrual reset: %v", err)
	}
	p.CycleID = "next"
	if err := a.ApplyPolicy(t.Context(), "uuid-b", "renewal", 3, p); err != nil {
		t.Fatal(err)
	}
	if persist.state.ClosedCycles["cycle"].Policy.AccruedNonWriteNano != 500 {
		t.Fatal("closed cycle accrual lost")
	}
	if err := a.ApplyPolicy(t.Context(), "uuid-a", "retired-account", 4, p); !errors.Is(err, ErrConflict) {
		t.Fatalf("retired UUID accepted: %v", err)
	}
	p.CycleID = "cycle"
	if err := a.ApplyPolicy(t.Context(), "uuid-b", "retired-cycle", 4, p); !errors.Is(err, ErrConflict) {
		t.Fatalf("retired cycle accepted: %v", err)
	}
}

func TestAccruedSpendCapArithmeticCannotOverflow(t *testing.T) {
	if withinCap(math.MaxInt64, math.MaxInt64-1, 1, 1) {
		t.Fatal("overflow created headroom")
	}
	if !withinCap(math.MaxInt64, math.MaxInt64-1, 0, 1) {
		t.Fatal("exact limit denied")
	}
	if withinCap(0, 1, 0, 0) {
		t.Fatal("retained storage above cap creates headroom")
	}
}

func TestAccruedStoragePreservesIncludedWritesAndOptionalCapSemantics(t *testing.T) {
	for _, scope := range []string{"uncapped", "organization-zero", "database-zero"} {
		t.Run(scope, func(t *testing.T) {
			p := fundingPolicy("cycle")
			p.OrganizationSpendCap = nil
			p.IncludedAllowanceUnits = 1
			p.AccruedNonWriteNano = 5000
			p.DatabaseAccruedNonWriteNano = map[string]int64{"db": 5000}
			if scope == "organization-zero" {
				p.OrganizationSpendCap = new(int64(0))
			}
			if scope == "database-zero" {
				p.DatabaseSpendCaps = map[string]*int64{"db": new(int64(0))}
			}
			a, err := New(NewMemoryPersister(), p)
			if err != nil {
				t.Fatal(err)
			}
			r := fundingRequest("included", "cycle", 1, 1)
			if g, err := a.Allocate(t.Context(), r); err != nil || g.PaidUnits != 0 {
				t.Fatalf("included write denied: %+v %v", g, err)
			}
			r.OperationID = "paid"
			_, err = a.Allocate(t.Context(), r)
			if scope == "uncapped" && err != nil {
				t.Fatal(err)
			}
			if scope != "uncapped" && !errors.Is(err, ErrExhausted) {
				t.Fatalf("zero cap bypass: %v", err)
			}
			if scope == "database-zero" {
				r.OperationID, r.DatabaseID = "other-db", "other"
				if _, err := a.Allocate(t.Context(), r); err != nil {
					t.Fatalf("database cap restricted other database: %v", err)
				}
			}
		})
	}
}
