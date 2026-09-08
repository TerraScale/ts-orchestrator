package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

func TestProductionPoolAdmissionReplayAfterRestartBillsUsageOnce(t *testing.T) {
	persist := writebudget.NewMemoryPersister()
	policy := writebudget.Policy{
		OrganizationID:         "org",
		CycleID:                "cycle",
		PolicyEpoch:            2,
		ConsentEpoch:           2,
		WriterEpoch:            3,
		WriterEpochs:           map[string]uint64{"holder": 3},
		IncludedAllowanceUnits: 0,
		PaidExcessEnabled:      true,
		RateNanoDollar:         1000,
	}
	authority, err := writebudget.New(persist, policy)
	if err != nil {
		t.Fatal(err)
	}
	request := writebudget.PoolRefillRequest{
		RefillOperationID: "refill-production-replay",
		PoolID:            "pool-db-holder",
		OrganizationID:    "org",
		DatabaseID:        "db",
		HolderID:          "holder",
		Region:            "gru",
		Regions:           []string{"gru", "sfo"},
		Placement:         "accepted-placement",
		Units:             4,
		MaxPoolUnits:      100,
		LowWaterUnits:     10,
		PolicyEpoch:       2,
		ConsentEpoch:      2,
		WriterEpoch:       3,
		ExpiresAt:         time.Now().Add(10 * time.Minute),
	}
	if _, err := authority.ReservePool(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	target := databaseadmission.Target{
		ServerIdentity: "spiffe://terrascale.tech/production/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FAD/01ARZ3NDEKTSV4RRFFQ69G5FAE",
		MemberID:       request.HolderID,
		Region:         request.Region,
	}
	workRequest := request
	workRequest.Units = 0
	work := databaseadmission.PoolWork{
		Request: workRequest,
		Consumptions: []writebudget.PoolConsumption{{
			RefillOperationID: request.RefillOperationID,
			OperationID:       "write-production-replay",
			PoolID:            request.PoolID,
			DatabaseID:        request.DatabaseID,
			BodyDigest:        "body-digest",
			LocalUnits:        2,
		}},
	}
	newRuntime := func() (*runtimeWriteBudget, error) {
		runtimeAuthority, err := writebudget.New(persist, policy)
		if err != nil {
			return nil, err
		}
		return &runtimeWriteBudget{
			authority: runtimeAuthority,
			policy:    policy,
			poolTarget: func(context.Context, writebudget.AllocationEnvelope) (databaseadmission.Target, error) {
				return target, nil
			},
		}, nil
	}
	subject, err := databaseadmission.PoolSubject(target.ServerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	firstRuntime, err := newRuntime()
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstRuntime.HandlePoolWork(t.Context(), subject, work)
	if err != nil || first.State != "reported" {
		t.Fatalf("first admission=%+v err=%v", first, err)
	}
	// A process restart must replay the durable operation without applying its
	// usage debit a second time.
	restarted, err := newRuntime()
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.HandlePoolWork(t.Context(), subject, work)
	if err != nil || replay.State != "reported" {
		t.Fatalf("replayed admission=%+v err=%v", replay, err)
	}
	state, _, err := restarted.authority.LookupState(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if state.UsedUnits != 4 || state.UsedPaid != 4 || state.UsedNanoDollar != 4000 || state.DatabaseUnits[request.DatabaseID] != 4 || state.DatabaseSpendNano[request.DatabaseID] != 4000 {
		t.Fatalf("replay double-billed usage: %+v", state)
	}
	changed := work
	changed.Consumptions = []writebudget.PoolConsumption{{
		RefillOperationID: request.RefillOperationID,
		OperationID:       "write-production-replay",
		PoolID:            request.PoolID,
		DatabaseID:        request.DatabaseID,
		BodyDigest:        "changed-body",
		LocalUnits:        2,
	}}
	if _, err := restarted.HandlePoolWork(t.Context(), subject, changed); !errors.Is(err, writebudget.ErrConflict) {
		t.Fatalf("changed replay error=%v, want conflict", err)
	}
}
