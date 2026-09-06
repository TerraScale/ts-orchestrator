package writebudget

import (
	"errors"
	"testing"
	"time"
)

func fundingPolicy(cycle string) Policy {
	return Policy{
		OrganizationID:         "org",
		CycleID:                cycle,
		PolicyEpoch:            1,
		ConsentEpoch:           1,
		WriterEpoch:            1,
		WriterEpochs:           map[string]uint64{"holder": 1},
		IncludedAllowanceUnits: 0,
		PaidExcessEnabled:      true,
		RateNanoDollar:         1000,
		AllowanceNanoDollar:    1_000_000_000,
	}
}

func fundingRequest(id, cycle string, epoch uint64, units int64) Request {
	return Request{OperationID: id, OrganizationID: "org", DatabaseID: "db", BranchID: "main", HolderID: "holder", Regions: []string{"gru"}, Units: units, PolicyEpoch: epoch, ConsentEpoch: epoch, WriterEpoch: 1, ExpiresAt: time.Now().Add(time.Hour)}
}

func TestFundingDatabaseDollarCapAllowsMillionPaidUnitsThenExhausts(t *testing.T) {
	cap := int64(1_000_000_000)
	policy := fundingPolicy("cycle")
	policy.AllowanceNanoDollar = 2_000_000_000
	policy.DatabaseSpendCaps = map[string]*int64{"db": &cap}
	authority, err := New(NewMemoryPersister(), policy)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := authority.Allocate(t.Context(), fundingRequest("million", "cycle", 1, 1_000_000))
	if err != nil || grant.PaidUnits != 1_000_000 || grant.CostNanoDollar != cap {
		t.Fatalf("million-unit allocation = %+v, err=%v", grant, err)
	}
	other := fundingRequest("other-db", "cycle", 1, 1)
	other.DatabaseID = "dbB"
	if _, err := authority.Allocate(t.Context(), other); err != nil {
		t.Fatalf("uncapped second database allocation error = %v", err)
	}
	if _, err := authority.Allocate(t.Context(), fundingRequest("one-more", "cycle", 1, 1)); !errors.Is(err, ErrExhausted) {
		t.Fatalf("allocation beyond one-dollar database cap error = %v", err)
	}
}

func TestFundingZeroCapsAllowIncludedButDenyPaidAndNilIsUncapped(t *testing.T) {
	zero := int64(0)
	policy := fundingPolicy("cycle")
	policy.IncludedAllowanceUnits = 1
	policy.DatabaseSpendCaps = map[string]*int64{"db": &zero}
	authority, err := New(NewMemoryPersister(), policy)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := authority.Allocate(t.Context(), fundingRequest("free", "cycle", 1, 1))
	if err != nil || grant.IncludedUnits != 1 || grant.PaidUnits != 0 {
		t.Fatalf("free allowance allocation = %+v, err=%v", grant, err)
	}
	if _, err := authority.Allocate(t.Context(), fundingRequest("paid", "cycle", 1, 1)); !errors.Is(err, ErrExhausted) {
		t.Fatalf("paid allocation under zero cap error = %v", err)
	}
	uncapped := fundingPolicy("uncapped")
	uncapped.DatabaseSpendCaps = map[string]*int64{"other": &zero}
	uncappedAuthority, err := New(NewMemoryPersister(), uncapped)
	if err != nil {
		t.Fatal(err)
	}
	if grant, err := uncappedAuthority.Allocate(t.Context(), fundingRequest("nil-cap", "uncapped", 1, 1)); err != nil || grant.PaidUnits != 1 {
		t.Fatalf("nil database cap allocation = %+v, err=%v", grant, err)
	}
}

func TestFundingCycleRolloverResetsAllowanceButRetainsOutstandingGrant(t *testing.T) {
	persist := NewMemoryPersister()
	authority, err := New(persist, fundingPolicy("old"))
	if err != nil {
		t.Fatal(err)
	}
	old, err := authority.Allocate(t.Context(), fundingRequest("old-grant", "old", 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.ApplyPolicy(t.Context(), "rev-2", "sum-2", 2, fundingPolicy("new")); err != nil {
		t.Fatal(err)
	}
	newGrant, err := authority.Allocate(t.Context(), fundingRequest("new-grant", "new", 2, 1))
	if err != nil || newGrant.CycleID != "new" {
		t.Fatalf("new-cycle allocation = %+v, err=%v", newGrant, err)
	}
	if err := persist.TransactRevision(t.Context(), false, func(state *State, _ uint64) error {
		if state.UsedUnits != 1 || state.UsedNanoDollar != 1000 || state.UsedPaid != 1 || state.DatabaseUnits["db"] != 1 || state.DatabaseSpendNano["db"] != 1000 {
			t.Fatalf("new-cycle counters = units %d cost %d paid %d db units %d db cost %d", state.UsedUnits, state.UsedNanoDollar, state.UsedPaid, state.DatabaseUnits["db"], state.DatabaseSpendNano["db"])
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	last := fundingRequest("new-capacity", "new", 2, 999_999)
	if _, err := authority.Allocate(t.Context(), last); err != nil {
		t.Fatalf("fresh cycle allowance allocation error = %v", err)
	}
	if _, err := authority.Allocate(t.Context(), fundingRequest("over-capacity", "new", 2, 1)); !errors.Is(err, ErrExhausted) {
		t.Fatalf("allocation beyond fresh cycle allowance error = %v", err)
	}
	retained, found, err := authority.Lookup(t.Context(), old.OperationID)
	if err != nil || !found || retained.OperationID != old.OperationID || !retained.Revoked {
		t.Fatalf("old outstanding grant = %+v, found=%v, err=%v", retained, found, err)
	}
}

func TestFundingValidationIgnoresExpiredRevokedAndPriorCycleHolders(t *testing.T) {
	persist := NewMemoryPersister()
	policy := fundingPolicy("current")
	authority, err := New(persist, policy)
	if err != nil {
		t.Fatal(err)
	}
	base := Grant{OrganizationID: "org", DatabaseID: "db", HolderID: "retired", RequestedUnits: 1, Units: 1, IncludedUnits: 0, PaidUnits: 1, RateNanoDollar: 1000, CostNanoDollar: 1000, Regions: []string{"gru"}, IssuedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour)}
	if err := persist.TransactRevision(t.Context(), true, func(state *State, _ uint64) error {
		state.Grants = make(map[string]Grant)
		state.Grants["expired"] = Grant{CycleID: "current", OperationID: "expired", OrganizationID: "org", DatabaseID: "db", HolderID: "retired", RequestedUnits: 1, Units: 1, PaidUnits: 1, RateNanoDollar: 1000, CostNanoDollar: 1000, Regions: []string{"gru"}, IssuedAt: base.IssuedAt, ExpiresAt: time.Now().Add(-time.Minute)}
		state.Grants["revoked"] = Grant{CycleID: "current", OperationID: "revoked", OrganizationID: "org", DatabaseID: "db", HolderID: "retired", RequestedUnits: 1, Units: 1, PaidUnits: 1, RateNanoDollar: 1000, CostNanoDollar: 1000, Regions: []string{"gru"}, IssuedAt: base.IssuedAt, ExpiresAt: time.Now().Add(time.Hour), Revoked: true}
		state.Grants["prior"] = Grant{CycleID: "old", OperationID: "prior", OrganizationID: "org", DatabaseID: "db", HolderID: "retired", RequestedUnits: 1, Units: 1, PaidUnits: 1, RateNanoDollar: 1000, CostNanoDollar: 1000, Regions: []string{"gru"}, IssuedAt: base.IssuedAt, ExpiresAt: time.Now().Add(time.Hour)}
		state.UsedUnits, state.UsedNanoDollar, state.UsedPaid = 2, 2000, 2
		state.DatabaseUnits, state.DatabaseSpendNano = map[string]int64{"db": 2}, map[string]int64{"db": 2000}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := authority.Lookup(t.Context(), "expired"); err != nil {
		t.Fatalf("expired holder validation error = %v", err)
	}
	if _, _, err := authority.Lookup(t.Context(), "revoked"); err != nil {
		t.Fatalf("revoked holder validation error = %v", err)
	}
	if _, _, err := authority.Lookup(t.Context(), "prior"); err != nil {
		t.Fatalf("prior-cycle holder validation error = %v", err)
	}
	if err := persist.TransactRevision(t.Context(), true, func(state *State, _ uint64) error {
		state.Grants["active"] = Grant{CycleID: "current", OperationID: "active", OrganizationID: "org", DatabaseID: "db", HolderID: "retired", RequestedUnits: 1, Units: 1, PaidUnits: 1, RateNanoDollar: 1000, CostNanoDollar: 1000, Regions: []string{"gru"}, IssuedAt: base.IssuedAt, ExpiresAt: time.Now().Add(time.Hour)}
		state.UsedUnits, state.UsedNanoDollar, state.UsedPaid = 3, 3000, 3
		state.DatabaseUnits["db"], state.DatabaseSpendNano["db"] = 3, 3000
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := authority.Lookup(t.Context(), "active"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("active missing-holder validation error = %v", err)
	}
}

func TestFundingValidationRejectsCorruptCountersAndHistoricalCost(t *testing.T) {
	for name, mutate := range map[string]func(*State){
		"paid-counter": func(state *State) { state.UsedPaid = 1 },
		"database-cost-counter": func(state *State) {
			state.Grants = map[string]Grant{"grant": {OperationID: "grant", OrganizationID: "org", CycleID: "current", DatabaseID: "db", HolderID: "holder", RequestedUnits: 1, Units: 1, PaidUnits: 1, RateNanoDollar: 1000, CostNanoDollar: 1000, Regions: []string{"gru"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}}
			state.UsedUnits, state.UsedNanoDollar, state.UsedPaid = 1, 1000, 1
			state.DatabaseUnits, state.DatabaseSpendNano = map[string]int64{"db": 1}, map[string]int64{"db": 0}
		},
		"historical-cost": func(state *State) {
			state.Grants = make(map[string]Grant)
			state.Grants["grant"] = Grant{OperationID: "grant", OrganizationID: "org", CycleID: "old", DatabaseID: "db", HolderID: "retired", RequestedUnits: 1, Units: 1, IncludedUnits: 0, PaidUnits: 1, RateNanoDollar: 1000, CostNanoDollar: 999, Regions: []string{"gru"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			persist := NewMemoryPersister()
			authority, err := New(persist, fundingPolicy("current"))
			if err != nil {
				t.Fatal(err)
			}
			if err := persist.TransactRevision(t.Context(), true, func(state *State, _ uint64) error { mutate(state); return nil }); err != nil {
				t.Fatal(err)
			}
			if _, _, err := authority.Lookup(t.Context(), "grant"); !errors.Is(err, ErrInvalid) {
				t.Fatalf("corrupt state validation error = %v", err)
			}
		})
	}
}
