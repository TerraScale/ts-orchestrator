package app

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

func TestNetBirdRemoteControllersBootstrapBeforeLeader(t *testing.T) {
	leader, _ := netbirdRecoveryControllers(t)
	leader.nodes = &nodeOps{controllers: func(node string) bool { return strings.HasPrefix(node, "node-") }}
	got := leader.orderNodes([]string{"node-a", "workload", "node-b"})
	if !slices.Equal(got, []string{"node-b", "workload", "node-a"}) {
		t.Fatalf("remote controller must install before leader: %v", got)
	}
}

func TestNetBirdLeaderSkipsMissingPeerAndChecksAlternative(t *testing.T) {
	leader, _ := netbirdRecoveryControllers(t)
	leader.fence.kv = fenceKV(t)
	for node, status := range map[string]network.Status{
		"node-b": {Missing: true, ObservedAt: time.Now()},
		"node-c": {Version: "0.80.0", ObservedAt: time.Now()},
	} {
		if err := leader.saveAt(t.Context(), 3, "netbird.status."+node, status); err != nil {
			t.Fatal(err)
		}
	}
	err := leader.healthyRemotePeer(t.Context(), []string{"node-b", "node-c"})
	if err == nil || !strings.Contains(err.Error(), "node-c: NetBird management") {
		t.Fatalf("missing peer masked installed alternative: %v", err)
	}
}

func TestNetBirdUnchangedLeaderAllowsFirstRemoteBootstrapWithoutSkippingMeshProbes(t *testing.T) {
	leader, _ := netbirdRecoveryControllers(t)
	leader.fence.kv = fenceKV(t)
	leader.nodes = &nodeOps{controllers: func(string) bool { return true }}
	if err := leader.saveAt(t.Context(), 3, "netbird.status.node-b", network.Status{Missing: true, ObservedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	status := network.Status{Connected: true, IP: "10.200.1.2", DNS: "node-a.nb.ts.internal"}
	if err := leader.healthy(t.Context(), "node-a", status, time.Time{}); err == nil || !strings.Contains(err.Error(), "healthy controller peer") {
		t.Fatalf("leader confirmation skipped its independent peer: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := leader.healthyMesh(ctx, "node-a", status, time.Time{}, false); err == nil || !strings.Contains(err.Error(), "DNS answer") {
		t.Fatalf("unchanged leader still required a missing peer or skipped DNS: %v", err)
	}
}
