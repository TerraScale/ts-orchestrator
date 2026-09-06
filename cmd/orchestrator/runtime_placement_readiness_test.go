package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
)

type readinessCollectorTarget struct {
	identity string
	request  *pb.PlacementControlServiceReadinessRequest
	failure  error
	calls    int
}

func (t *readinessCollectorTarget) Principal() string {
	return "spiffe://terrascale.tech/production/orchestrator/a"
}
func (t *readinessCollectorTarget) ServerIdentity() string { return t.identity }
func (t *readinessCollectorTarget) Readiness(_ context.Context, request *pb.PlacementControlServiceReadinessRequest) (*pb.PlacementControlServiceReadinessResponse, error) {
	t.calls++
	t.request = request
	if t.failure != nil {
		return nil, t.failure
	}
	raw, _ := json.Marshal(databaseadmission.SignedReadiness{KeyID: "key", Payload: []byte(`{"actual":"raw producer evidence"}`), Signature: make([]byte, 64)})
	return &pb.PlacementControlServiceReadinessResponse{SignedReceipt: raw}, nil
}
func TestReadinessCollectorDiscardsPartialAndPreservesChallenge(t *testing.T) {
	a := &readinessCollectorTarget{identity: "spiffe://terrascale.tech/production/terrabase/a"}
	b := &readinessCollectorTarget{identity: "spiffe://terrascale.tech/production/terrabase/b", failure: errors.New("physical follower not caught up")}
	collector := collectProductionReadiness(map[string]placementpublisher.ReadinessTarget{a.identity: a, b.identity: b}, func(context.Context) error { return nil })
	record := databaseadmission.Record{Request: databaseadmission.Request{Environment: "production", TenantID: "tenant", ProjectID: "project", OperationID: "create-op"}, DatabaseID: "database", Targets: []databaseadmission.Target{{ServerIdentity: a.identity, Installed: true}, {ServerIdentity: b.identity, Installed: true}}}
	record.PlacementTargets = []databaseadmission.PlacementTarget{{ServerIdentity: a.identity, Proposed: true}, {ServerIdentity: b.identity, Proposed: true}}
	nonce := strings.Repeat("a", 64)
	if receipts, err := collector(t.Context(), record, nonce); err == nil || receipts != nil {
		t.Fatal("partial member evidence exposed as successful collection")
	}
	b.failure = nil
	receipts, err := collector(t.Context(), record, nonce)
	if err != nil || len(receipts) != 2 {
		t.Fatalf("collection=%v error=%v", receipts, err)
	}
	for _, target := range []*readinessCollectorTarget{a, b} {
		request := target.request
		if request.Tenant != record.Request.TenantID || request.Project != record.Request.ProjectID || request.Database != record.DatabaseID || request.OperationId != databaseadmission.PlacementOperationID(record.Request) || request.Nonce != nonce {
			t.Fatal("collector changed durable database binding or challenge")
		}
	}
	fenced := collectProductionReadiness(map[string]placementpublisher.ReadinessTarget{a.identity: a, b.identity: b}, func(context.Context) error { return errors.New("lease lost") })
	calls := a.calls + b.calls
	if _, err := fenced(t.Context(), record, nonce); err == nil || a.calls+b.calls != calls {
		t.Fatal("fenced collector reached member")
	}
}
