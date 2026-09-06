package writebudget

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func testAuthority(t *testing.T) (*Authority, *MemoryPersister) {
	t.Helper()
	persist := NewMemoryPersister()
	authority, err := New(persist, Policy{OrganizationID: "org", CycleID: "cycle", PolicyEpoch: 3, ConsentEpoch: 4, Units: 10, CostMinor: 1000, UnitCostMinor: 2, DatabaseCaps: map[string]int64{"db": 8}})
	if err != nil {
		t.Fatal(err)
	}
	return authority, persist
}

func request(id, db, branch string, units int64, expiry time.Time) Request {
	return Request{OperationID: id, OrganizationID: "org", DatabaseID: db, BranchID: branch, HolderID: "writer-" + id, Regions: []string{"gru", "sfo"}, Units: units, PolicyEpoch: 3, ConsentEpoch: 4, ExpiresAt: expiry}
}

func TestAllocateMultipliesRegionsOnceAndBranchesShareCaps(t *testing.T) {
	authority, _ := testAuthority(t)
	expires := time.Now().Add(time.Hour)
	grant, err := authority.Allocate(t.Context(), request("one", "db", "main", 3, expires))
	if err != nil {
		t.Fatal(err)
	}
	if grant.Units != 6 || grant.CostMinor != 12 {
		t.Fatalf("grant = %+v", grant)
	}
	if _, err := authority.Allocate(t.Context(), request("two", "db", "branch", 2, expires)); !errors.Is(err, ErrExhausted) {
		t.Fatalf("second branch allocation error = %v, want exhausted database cap", err)
	}
}

func TestAllocateRetryReconcilesExactOperation(t *testing.T) {
	authority, _ := testAuthority(t)
	r := request("same", "db", "main", 1, time.Now().Add(time.Hour))
	first, err := authority.Allocate(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := authority.Allocate(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(retry, first) {
		t.Fatalf("retry = %+v, first = %+v", retry, first)
	}
	changed := r
	changed.Units = 2
	if _, err := authority.Allocate(t.Context(), changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed retry error = %v", err)
	}
}

func TestRevocationRemainsPendingUntilFence(t *testing.T) {
	authority, _ := testAuthority(t)
	grant, err := authority.Allocate(t.Context(), request("revoke", "db", "main", 1, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Revoke(t.Context(), grant.OperationID); !errors.Is(err, ErrPending) {
		t.Fatalf("revoke error = %v", err)
	}
	pending, found, err := authority.Lookup(t.Context(), grant.OperationID)
	if err != nil || !found || !pending.Revoked || pending.Fenced {
		t.Fatalf("pending = %+v found=%v err=%v", pending, found, err)
	}
	if err := authority.Fence(t.Context(), grant.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := authority.Revoke(t.Context(), grant.OperationID); err != nil {
		t.Fatal(err)
	}
}

func TestEpochAndExpiryFenceRequest(t *testing.T) {
	authority, _ := testAuthority(t)
	r := request("bad", "db", "main", 1, time.Now().Add(time.Hour))
	r.PolicyEpoch++
	if _, err := authority.Allocate(t.Context(), r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("epoch error = %v", err)
	}
	r = request("expired", "db", "main", 1, time.Now().Add(-time.Second))
	if _, err := authority.Allocate(t.Context(), r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expiry error = %v", err)
	}
}
