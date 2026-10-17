package swarmruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

func TestFounderGenesisGuardPrecedesPersistentAdmission(t *testing.T) {
	cfg := serviceConfig(t, "ts-gru-1", "manager")
	revoked := errors.New("protected original creation is unavailable")
	cfg.guardGenesis = func(context.Context) error { return revoked }
	if _, err := StartNode(t.Context(), cfg, serviceExecutor{}); !errors.Is(err, revoked) {
		t.Fatalf("founder escaped protected creation refusal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "admission.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused genesis wrote durable admission: %v", err)
	}
}

func TestRuntimeGenesisRequiresOriginalProcessAndCompleteHistory(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	if err := (VerifiedRuntimeGenesis{}).Revalidate(ctx); err == nil {
		t.Fatal("zero runtime genesis proof was admitted")
	}
	cfg := serviceConfig(t, "ts-gru-1", "manager")
	node := serviceStart(t, ctx, cfg)
	proof, err := node.RuntimeGenesis(ctx)
	if err != nil {
		t.Fatal(err)
	}
	info := proof.Info()
	if info.NodeID != node.ID() || info.ClusterID == "" || len(info.RootCASHA256) != 64 || info.StartedAt.IsZero() || info.Version == 0 || info.Term == 0 || info.Leader == 0 {
		t.Fatalf("actual genesis identity is incomplete: %+v", info)
	}
	if err := proof.Revalidate(ctx); err != nil {
		t.Fatal(err)
	}
	original, revoke := context.WithTimeout(ctx, 20*time.Second)
	defer revoke()
	bound, err := node.RuntimeGenesis(original)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := original.Deadline()
	if !bound.ExpiresAt().Equal(deadline) {
		t.Fatal("runtime genesis extended the original caller deadline")
	}
	revoke()
	if err := bound.Revalidate(ctx); err == nil {
		t.Fatal("background revalidation survived original caller cancellation")
	}
	client, err := node.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: api.Annotations{Name: "prior-runtime-evidence"}, Data: []byte("retained history")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.Revalidate(ctx); err == nil {
		t.Fatal("runtime writes did not invalidate empty-genesis proof")
	}
	if _, err := client.RemoveConfig(ctx, &api.RemoveConfigRequest{ConfigID: created.Config.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := node.RuntimeGenesis(ctx); err == nil {
		t.Fatal("deleting prior evidence restored runtime genesis eligibility")
	}
	stop, done := context.WithTimeout(context.Background(), 15*time.Second)
	defer done()
	if err := node.Stop(stop); err != nil {
		t.Fatal(err)
	}
	if err := proof.Revalidate(ctx); err == nil {
		t.Fatal("stopped founder process retained genesis authority")
	}
	restored := serviceStart(t, ctx, cfg)
	if _, err := restored.RuntimeGenesis(ctx); err == nil {
		t.Fatal("restored empty snapshot manufactured first-process genesis")
	}
}
