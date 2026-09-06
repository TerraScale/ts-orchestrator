package main

import (
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

func testWriteBudgetExpiry() time.Time { return time.Now().Add(time.Hour) }

func TestRuntimeWriteBudgetDecodesDollarDatabaseCapAsNanoDollars(t *testing.T) {
	policy := writebudget.Policy{
		OrganizationID: "org", CycleID: "old", PolicyEpoch: 1, ConsentEpoch: 1, WriterEpoch: 1,
		WriterEpochs: map[string]uint64{"holder": 1}, PaidExcessEnabled: true,
		RateNanoDollar: 1000, AllowanceNanoDollar: 1 << 62,
	}
	persist := writebudget.NewMemoryPersister()
	authority, err := writebudget.New(persist, policy)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &runtimeWriteBudget{authority: authority, policy: policy}
	_, err = runtime.ApplyPolicy(t.Context(), writebudget.PolicyEnvelope{
		SchemaVersion: 1, OrganizationID: "org", CycleID: "new", AccountRevision: "rev", PolicyGeneration: 2, Checksum: "sum",
		Policy: map[string]any{
			"organizationId": "org", "cycleId": "new", "includedWriteUnits": "0", "paidExcessEnabled": true,
			"rateNanoDollar": int64(1000), "databaseSpendCapsCents": map[string]int64{"db": 100},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := writebudget.Request{OperationID: "million", OrganizationID: "org", DatabaseID: "db", BranchID: "main", HolderID: "holder", Regions: []string{"gru"}, Units: 1_000_000, PolicyEpoch: 2, ConsentEpoch: 2, WriterEpoch: 1, ExpiresAt: testWriteBudgetExpiry()}
	grant, err := authority.Allocate(t.Context(), request)
	if err != nil || grant.CostNanoDollar != 1_000_000_000 {
		t.Fatalf("decoded cap allocation = %+v, err=%v", grant, err)
	}
	request.OperationID = "one-more"
	request.Units = 1
	if _, err := authority.Allocate(t.Context(), request); !errors.Is(err, writebudget.ErrExhausted) {
		t.Fatalf("allocation over decoded cap error = %v", err)
	}
}

func TestRuntimeWriteBudgetDecodesZeroAndNilDatabaseCaps(t *testing.T) {
	for name, caps := range map[string]map[string]int64{
		"zero": {"db": 0},
		"nil":  nil,
	} {
		t.Run(name, func(t *testing.T) {
			policy := writebudget.Policy{OrganizationID: "org", CycleID: "old", PolicyEpoch: 1, ConsentEpoch: 1, WriterEpoch: 1, WriterEpochs: map[string]uint64{"holder": 1}, PaidExcessEnabled: true, RateNanoDollar: 1000, AllowanceNanoDollar: 1 << 62}
			authority, err := writebudget.New(writebudget.NewMemoryPersister(), policy)
			if err != nil {
				t.Fatal(err)
			}
			runtime := &runtimeWriteBudget{authority: authority, policy: policy}
			_, err = runtime.ApplyPolicy(t.Context(), writebudget.PolicyEnvelope{SchemaVersion: 1, OrganizationID: "org", CycleID: "new", AccountRevision: "rev", PolicyGeneration: 2, Checksum: "sum", Policy: map[string]any{"organizationId": "org", "cycleId": "new", "includedWriteUnits": "0", "paidExcessEnabled": true, "rateNanoDollar": int64(1000), "databaseSpendCapsCents": caps}})
			if err != nil {
				t.Fatal(err)
			}
			request := writebudget.Request{OperationID: "write", OrganizationID: "org", DatabaseID: "db", BranchID: "main", HolderID: "holder", Regions: []string{"gru"}, Units: 1, PolicyEpoch: 2, ConsentEpoch: 2, WriterEpoch: 1, ExpiresAt: testWriteBudgetExpiry()}
			_, err = authority.Allocate(t.Context(), request)
			if name == "zero" && !errors.Is(err, writebudget.ErrExhausted) {
				t.Fatalf("zero cap allocation error = %v", err)
			}
			if name == "nil" && err != nil {
				t.Fatalf("nil cap allocation error = %v", err)
			}
		})
	}
}
