package main

import (
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

func TestRuntimeWriteBudgetAllowanceDeadline(t *testing.T) {
	for _, deadline := range []string{"2030-01-01T00:00:00.000Z", "2000-01-01T00:00:00Z", "", "bad", "null", "2030-01-01T00:00:00+01:00"} {
		t.Run(deadline, func(t *testing.T) {
			policy := writebudget.Policy{OrganizationID: "org", CycleID: "old", PolicyEpoch: 1, ConsentEpoch: 1, WriterEpoch: 1, WriterEpochs: map[string]uint64{"holder": 1}, RateNanoDollar: 1000}
			authority, err := writebudget.New(writebudget.NewMemoryPersister(), policy)
			if err != nil {
				t.Fatal(err)
			}
			runtime := &runtimeWriteBudget{authority: authority, policy: policy}
			envelope := writebudget.PolicyEnvelope{SchemaVersion: 1, OrganizationID: "org", CycleID: "new", AccountRevision: "rev", PolicyGeneration: 2, Checksum: "sum", Policy: map[string]any{"organizationId": "org", "cycleId": "new", "includedWriteUnits": "100", "paidExcessEnabled": true, "rateNanoDollar": int64(1000), "includedAllowanceEndsAt": deadline}}
			if deadline == "null" {
				envelope.Policy["includedAllowanceEndsAt"] = nil
			}
			_, err = runtime.ApplyPolicy(t.Context(), envelope)
			valid := deadline == "2030-01-01T00:00:00.000Z" || deadline == "2000-01-01T00:00:00Z"
			if !valid {
				if err == nil {
					t.Fatal("invalid deadline accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// A duplicate stale envelope must not extend its original eligibility.
			if _, err := runtime.ApplyPolicy(t.Context(), envelope); err != nil {
				t.Fatal(err)
			}
			request := writebudget.Request{OperationID: "write", OrganizationID: "org", DatabaseID: "db", HolderID: "holder", Regions: []string{"gru", "sfo", "fra"}, Units: 1, PolicyEpoch: 2, ConsentEpoch: 2, WriterEpoch: 1, ExpiresAt: time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)}
			grant, err := authority.Allocate(t.Context(), request)
			if deadline == "2000-01-01T00:00:00Z" {
				if !errors.Is(err, writebudget.ErrExhausted) {
					t.Fatalf("expired policy allocation: %+v, %v", grant, err)
				}
			} else if err != nil || !grant.ExpiresAt.Equal(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)) {
				t.Fatalf("grant deadline = %+v, %v", grant, err)
			}
		})
	}
}
