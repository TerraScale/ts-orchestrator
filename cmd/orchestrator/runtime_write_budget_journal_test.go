package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

type budgetTestDelivery func(context.Context, writebudget.SignedAllocation) error

func (f budgetTestDelivery) SendAllocation(ctx context.Context, allocation writebudget.SignedAllocation) error {
	return f(ctx, allocation)
}

func TestRuntimeBudgetJournalRetainsInitialRevisionAndExactAllocation(t *testing.T) {
	cluster := newRotationStateCluster(t)
	connection := cluster.connect(t)
	store := openRotationTestLeaseStore(t, t.Context(), connection, true)
	lease := rotationTestLease(1, "global-controller-gru-budget")
	putRotationTestLease(t, t.Context(), store, lease)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	policy := writebudget.Policy{OrganizationID: "org", CycleID: "cycle", PolicyEpoch: 1, ConsentEpoch: 1, WriterEpoch: 1, WriterEpochs: map[string]uint64{"holder": 1}, IncludedAllowanceUnits: 1, RateNanoDollar: 1000}
	initial := writebudget.PolicyEnvelope{SchemaVersion: 1, OrganizationID: "org", CycleID: "cycle", AccountRevision: "revision", PolicyGeneration: 9, Checksum: "checksum", Policy: map[string]any{"organizationId": "org", "cycleId": "cycle", "includedWriteUnits": "1", "rateNanoDollar": 1000}}
	var delivered []writebudget.SignedAllocation
	config := runtimeWriteBudgetConfig{Policy: policy, InitialPolicy: initial, StateKey: "test-budget", Signer: signer, Placement: "accepted-proof", ValidateRequest: func(context.Context, writebudget.Request) error { return nil }, Delivery: budgetTestDelivery(func(_ context.Context, signed writebudget.SignedAllocation) error {
		delivered = append(delivered, signed)
		return nil
	})}
	session := globalWorkerSession{Connection: connection, Lease: lease}
	runtime, err := newRuntimeWriteBudget(session, config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.ApplyPolicy(t.Context(), initial)
	if err != nil || result.Status != "accepted" {
		t.Fatalf("initial replay=%+v err=%v", result, err)
	}
	request := writebudget.Request{OperationID: "operation", OrganizationID: "org", DatabaseID: "db", HolderID: "holder", Regions: []string{"GRU"}, Units: 1, PolicyEpoch: 1, ConsentEpoch: 1, ExpiresAt: time.Now().Add(time.Hour)}
	first, err := runtime.Allocate(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newRuntimeWriteBudget(session, config)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := restarted.Allocate(t.Context(), request)
	if err != nil || !retry.IssuedAt.Equal(first.IssuedAt) || len(delivered) != 2 || string(delivered[0].Payload) != string(delivered[1].Payload) {
		t.Fatalf("retry=%+v delivered=%d err=%v", retry, len(delivered), err)
	}
	request.OperationID = "second"
	if _, err := restarted.Allocate(t.Context(), request); !errors.Is(err, writebudget.ErrExhausted) {
		t.Fatalf("restart reset allowance: %v", err)
	}
	putRotationTestLease(t, t.Context(), store, rotationTestLease(2, "global-controller-gru-successor"))
	if _, err := restarted.Allocate(t.Context(), request); !errors.Is(err, authorityjournal.ErrFenced) {
		t.Fatalf("retired authority allocation: %v", err)
	}
}
