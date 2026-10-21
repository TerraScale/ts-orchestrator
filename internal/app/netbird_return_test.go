package app

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNetBirdBootstrapReturnRetainsWorkloadAndBackendHealthGates(t *testing.T) {
	ops, balancer, instances := newNodeOpsTest(t)
	n := netbirdRollout{fence: ops.fence}
	spec, addresses := ops.fence.spec()
	if err := ops.fence.fence(t.Context(), balancer, 3, *spec, "gru-1-ctl-2", addresses["gru-1-ctl-2"], 0, netbirdHold); err != nil {
		t.Fatal(err)
	}
	instances.hosts.states["gru-1-ctl-2/terrabase"] = "failed"
	if err := n.returnNode(t.Context(), 3, "gru-1-ctl-2"); err == nil || !strings.Contains(err.Error(), "node roles are not ready") {
		t.Fatalf("bootstrap return ignored failed workload: %v", err)
	}
	if _, held, err := ops.fence.record(t.Context(), "gru-1-ctl-2"); err != nil || !held {
		t.Fatalf("failed workload released its fence: held=%t error=%v", held, err)
	}
	instances.hosts.states["gru-1-ctl-2/terrabase"] = "running"
	balancer.down[addresses["gru-1-ctl-2"]+":9465"] = true
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	err := n.returnNode(ctx, 3, "gru-1-ctl-2")
	cancel()
	if err == nil {
		t.Fatal("bootstrap return ignored unhealthy LB backend")
	}
	if _, held, err := ops.fence.record(t.Context(), "gru-1-ctl-2"); err != nil || !held {
		t.Fatalf("failed backend health released its fence: held=%t error=%v", held, err)
	}
	balancer.down[addresses["gru-1-ctl-2"]+":9465"] = false
	if err := n.returnNode(t.Context(), 3, "gru-1-ctl-2"); err != nil {
		t.Fatal(err)
	}
	if _, held, err := ops.fence.record(t.Context(), "gru-1-ctl-2"); err != nil || held {
		t.Fatalf("healthy bootstrap recovery retained its fence: held=%t error=%v", held, err)
	}
}
