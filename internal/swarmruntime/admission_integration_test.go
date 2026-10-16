package swarmruntime

import (
	"context"
	"testing"
	"time"

	"github.com/moby/swarmkit/v2/api"
)

func TestNodeAdmissionIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	client, cfg, worker := serviceCluster(t, ctx)
	node, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: worker.ID()})
	if err != nil {
		t.Fatal(err)
	}
	if node.Node.Spec.Membership != api.NodeMembershipAccepted || node.Node.Spec.Annotations.Name != cfg.Admission.HostID || node.Node.Spec.Annotations.Labels[LabelHostRole] != "container" || node.Node.Spec.Annotations.Labels[LabelInstanceID] != cfg.Admission.InstanceID || node.Node.Spec.Annotations.Labels[LabelRegion] != "sa-saopaulo-1" || node.Node.Spec.Annotations.Labels[LabelExecutionScope] != "platform" {
		t.Fatalf("missing manager-owned placement admission: %+v", node.Node.Spec)
	}
	if _, err := worker.ControlClient(ctx); err == nil {
		t.Fatal("worker received manager control privileges")
	}
	for _, alter := range []func(*Admission){func(a *Admission) { a.Role = "manager" }, func(a *Admission) { a.Role = "wasm" }, func(a *Admission) { a.HostID = "ts-gru-99" }, func(a *Admission) { a.InstanceID = "another-instance" }, func(a *Admission) { a.Region = "eu-frankfurt-1" }} {
		forged := cfg.Admission
		alter(&forged)
		if _, err := AdmitNode(ctx, client, worker.ID(), forged); err == nil {
			t.Fatalf("changed trusted admission: %+v", forged)
		}
	}
	replayed, err := AdmitNode(ctx, client, worker.ID(), cfg.Admission)
	if err != nil || replayed.Meta.Version.Index != node.Node.Meta.Version.Index {
		t.Fatalf("admission not idempotent: %+v %v", replayed, err)
	}
}
