package writebudget

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAllowanceCutoffFencesConcurrentRegionsAndStalePolicy(t *testing.T) {
	cutoff := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	policy := fundingPolicy("cycle")
	policy.IncludedAllowanceUnits = 3
	policy.IncludedAllowanceEndsAt = cutoff
	persist := NewMemoryPersister()
	authority, err := New(persist, policy)
	if err != nil {
		t.Fatal(err)
	}
	now := cutoff.Add(-time.Second)
	authority.now = func() time.Time { return now }
	request := fundingRequest("first", "cycle", 1, 1)
	request.Regions = []string{"gru", "sfo", "fra"}
	request.ExpiresAt = cutoff.Add(time.Hour)
	grant, err := authority.Allocate(t.Context(), request)
	if err != nil || !grant.ExpiresAt.Equal(cutoff) || grant.IncludedUnits != 3 {
		t.Fatalf("pre-cutoff grant = %+v, %v", grant, err)
	}
	retry, err := authority.Allocate(t.Context(), request)
	if err != nil || !retry.ExpiresAt.Equal(grant.ExpiresAt) {
		t.Fatalf("bounded retry = %+v, %v", retry, err)
	}
	request.OperationID = "paid"
	paid, err := authority.Allocate(t.Context(), request)
	if err != nil || !paid.ExpiresAt.Equal(cutoff) || paid.PaidUnits != 3 {
		t.Fatalf("pre-cutoff paid grant = %+v, %v", paid, err)
	}
	now = cutoff
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Go(func() {
			concurrent := request
			concurrent.OperationID = fmt.Sprintf("after-%d", i)
			if _, err := authority.Allocate(t.Context(), concurrent); !errors.Is(err, ErrExhausted) {
				t.Errorf("post-cutoff allocation = %v", err)
			}
		})
	}
	wg.Wait()
	request.OperationID = "first"
	if _, err := authority.Allocate(t.Context(), request); !errors.Is(err, ErrExhausted) {
		t.Fatalf("expired replay = %v", err)
	}
	if err := authority.ApplyPolicy(t.Context(), "stale", "stale", 1, policy); err != nil {
		t.Fatal(err)
	}
	request.PolicyEpoch, request.ConsentEpoch = 2, 2
	request.OperationID = "stale-envelope"
	if _, err := authority.Allocate(t.Context(), request); !errors.Is(err, ErrExhausted) {
		t.Fatalf("stale envelope reopened allowance: %v", err)
	}
	if persist.state.UsedIncluded != 3 || persist.state.UsedPaid != 3 {
		t.Fatalf("denied writes changed spend: %+v", persist.state)
	}
}
