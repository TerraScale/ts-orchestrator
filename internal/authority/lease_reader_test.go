package authority

import (
	"context"
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestReadLeaseAdmissionPinsRenewalAndRejectsSuccessor(t *testing.T) {
	js := newAuthorityTestJetStream(t)
	runtime, err := Start(t.Context(), js, Config{Scope: "gru", DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		CandidateID: "0000000000C66H81REBS854264", Replicas: 1, LeaseDuration: 30 * time.Second, RenewInterval: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	reader, err := OpenReader(t.Context(), js, "gru")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	admitted, err := reader.AdmitCurrentLease(ctx, runtime.config.DeploymentID, runtime.config.CandidateID, runtime.Current().Epoch)
	if err != nil {
		t.Fatal(err)
	}
	original := admitted.Deadline()
	if err := runtime.Guard(t.Context(), admitted.Epoch()); err != nil {
		t.Fatal(err)
	}
	if err := admitted.Guard(t.Context()); err != nil || !admitted.Deadline().Equal(original) {
		t.Fatal("renewal changed the original read admission", err)
	}
	if _, err := reader.AdmitCurrentLease(t.Context(), runtime.config.DeploymentID, entityid.New(), admitted.Epoch()); err == nil {
		t.Fatal("read admission accepted another candidate")
	}
	cancel()
	if err := admitted.Guard(t.Context()); err == nil {
		t.Fatal("read admission survived original caller cancellation")
	}
	admitted, err = reader.AdmitCurrentLease(t.Context(), runtime.config.DeploymentID, runtime.config.CandidateID, runtime.Current().Epoch)
	if err != nil {
		t.Fatal(err)
	}
	successor := admitted.lease
	successor.OwnerID, successor.TransitionID, successor.Epoch = entityid.New(), entityid.New(), successor.Epoch+1
	wire, err := json.Marshal(successor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(t.Context(), runtime.leaseSub, wire); err != nil {
		t.Fatal(err)
	}
	if err := admitted.Guard(t.Context()); err == nil {
		t.Fatal("read admission followed a successor owner and epoch")
	}
}
