package writebudget

import (
	"errors"
	"testing"
	"time"
)

func poolRequest(id string, units int64) PoolRefillRequest {
	return PoolRefillRequest{
		RefillOperationID: id,
		PoolID:            "pool-db-holder",
		OrganizationID:    "org",
		DatabaseID:        "db",
		HolderID:          "holder",
		Region:            "gru",
		Regions:           []string{"gru", "sfo"},
		Placement:         "placement",
		Units:             units,
		MaxPoolUnits:      100,
		LowWaterUnits:     10,
		PolicyEpoch:       2,
		ConsentEpoch:      2,
		WriterEpoch:       3,
		ExpiresAt:         time.Now().Add(10 * time.Minute),
	}
}

func TestReservePoolDoesNotBillUnusedCredits(t *testing.T) {
	authority, err := New(NewMemoryPersister(), Policy{
		OrganizationID: "org", CycleID: "cycle", PolicyEpoch: 2, ConsentEpoch: 2,
		WriterEpoch: 1, WriterEpochs: map[string]uint64{"holder": 3},
		IncludedAllowanceUnits: 100, PaidExcessEnabled: true, RateNanoDollar: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := authority.ReservePool(t.Context(), poolRequest("refill-1", 20))
	if err != nil {
		t.Fatal(err)
	}
	if grant.LocalUnits != 20 || grant.AggregateUnits != 40 || grant.IncludedAggregate != 40 {
		t.Fatalf("grant=%+v", grant)
	}
	state, ok, err := authority.LookupState(t.Context())
	if err != nil || !ok {
		t.Fatalf("state=%+v ok=%v err=%v", state, ok, err)
	}
	if state.UsedUnits != 0 || state.UsedNanoDollar != 0 || state.ReservedUnits != 40 {
		t.Fatalf("unused refill billed or reservation missing: %+v", state)
	}

	operation, err := authority.RecordPoolConsumption(t.Context(), PoolConsumption{RefillOperationID: "refill-1", OperationID: "write-1", PoolID: "pool-db-holder", DatabaseID: "db", BodyDigest: "digest", LocalUnits: 3})
	if err != nil {
		t.Fatal(err)
	}
	if operation.Aggregate != 6 {
		t.Fatalf("operation=%+v", operation)
	}
	state, _, err = authority.LookupState(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if state.UsedUnits != 6 || state.UsedNanoDollar != 0 || state.ReservedUnits != 34 {
		t.Fatalf("consumption accounting=%+v", state)
	}
}

func TestReservePoolReplayAndConflict(t *testing.T) {
	authority, err := New(NewMemoryPersister(), Policy{
		OrganizationID: "org", CycleID: "cycle", PolicyEpoch: 2, ConsentEpoch: 2,
		WriterEpoch: 1, WriterEpochs: map[string]uint64{"holder": 3},
		IncludedAllowanceUnits: 100, PaidExcessEnabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := poolRequest("same", 2)
	first, err := authority.ReservePool(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := authority.ReservePool(t.Context(), request)
	if err != nil || replay.PoolSequence != first.PoolSequence {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	request.Units++
	if _, err := authority.ReservePool(t.Context(), request); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed refill identity error=%v", err)
	}
	if _, err := authority.RecordPoolConsumption(t.Context(), PoolConsumption{RefillOperationID: "same", OperationID: "write", PoolID: "pool-db-holder", DatabaseID: "db", BodyDigest: "digest", LocalUnits: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RecordPoolConsumption(t.Context(), PoolConsumption{RefillOperationID: "same", OperationID: "write", PoolID: "pool-db-holder", DatabaseID: "db", BodyDigest: "different", LocalUnits: 1}); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed operation identity error=%v", err)
	}
}
