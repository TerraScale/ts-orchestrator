package swarmruntime

import (
	"context"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

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
