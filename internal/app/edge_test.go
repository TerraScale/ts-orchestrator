package app

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

// newEdgeTest owns both sets: terrabase and ts-auth run on ctl-1..3.
func newEdgeTest(t *testing.T) (*edgeReconciler, *nodeOps, *fenceLB, *nodeInstances) {
	t.Helper()
	ops, balancer, instances := newNodeOpsTest(t)
	spec := &cellspec.ReleaseFence{LoadBalancerID: "ocid1.loadbalancer.oc1..x", BackendSets: []cellspec.FencedSet{
		{Name: "terrabase", Port: 9465, Role: "terrabase"}, {Name: "ts-auth", Port: 8080, Role: "ts-auth"}}}
	ops.fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return spec, fenceAddresses }
	edge := newEdgeReconciler("gru", ops.fence)
	edge.ops, edge.downFor = ops, 0
	return edge, ops, balancer, instances
}

func (e *edgeReconciler) passes(t *testing.T, n int) {
	t.Helper()
	for range n {
		if err := e.pass(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

func backendOf(balancer *fenceLB, set, name string) (lb.Backend, bool) {
	balancer.mu.Lock()
	defer balancer.mu.Unlock()
	index := slices.IndexFunc(balancer.sets[set], func(b lb.Backend) bool { return b.Name() == name })
	if index < 0 {
		return lb.Backend{}, false
	}
	return balancer.sets[set][index], true
}

// A set that matches its replicas, all serving, is left alone.
func TestEdgeLeavesAServingSetAlone(t *testing.T) {
	edge, _, balancer, _ := newEdgeTest(t)
	edge.passes(t, 3)
	if len(balancer.log) != 0 || len(edge.alerted) != 0 {
		t.Fatalf("load balancer %q, alerts %v", balancer.log, edge.alerted)
	}
}

// A replica without a backend gets one out of rotation, which joins once
// its node serves.
func TestEdgeAddsAMissingReplicaOutOfRotation(t *testing.T) {
	edge, _, balancer, _ := newEdgeTest(t)
	balancer.sets["ts-auth"] = balancer.sets["ts-auth"][:2]
	edge.fence.hosts.(*nodeHosts).states["ctl-3/ts-auth"] = "starting"
	edge.passes(t, 2)
	if backend, ok := backendOf(balancer, "ts-auth", "10.0.0.13:8080"); !ok || backend.Serving() {
		t.Fatalf("added %+v %v", backend, ok)
	}
	edge.fence.hosts.(*nodeHosts).states["ctl-3/ts-auth"] = ""
	edge.passes(t, 1)
	if backend, _ := backendOf(balancer, "ts-auth", "10.0.0.13:8080"); !backend.Serving() {
		t.Fatalf("a serving replica stayed out: %q", balancer.log)
	}
	if _, found, _ := edge.fence.record(t.Context(), "ctl-3"); found {
		t.Fatal("the health hold was left")
	}
}

// A replica that reports starting is taken out of its own set only, and
// returns once it serves.
func TestEdgeTakesANonServingReplicaOutAndBack(t *testing.T) {
	edge, _, balancer, _ := newEdgeTest(t)
	edge.fence.hosts.(*nodeHosts).states["ctl-2/ts-auth"] = "failed"
	edge.passes(t, 2)
	if backend, _ := backendOf(balancer, "ts-auth", "10.0.0.12:8080"); backend.Serving() {
		t.Fatalf("a failed replica serves: %q", balancer.log)
	}
	if backend, _ := backendOf(balancer, "terrabase", "10.0.0.12:9465"); !backend.Serving() {
		t.Fatal("the node's other set was fenced")
	}
	edge.fence.hosts.(*nodeHosts).states["ctl-2/ts-auth"] = ""
	edge.passes(t, 1)
	if backend, _ := backendOf(balancer, "ts-auth", "10.0.0.12:8080"); !backend.Serving() {
		t.Fatalf("a recovered replica stayed out: %q", balancer.log)
	}
}

// Hand edits are undone: a drained node's backend put back by hand goes
// out again, a backend drained by hand returns once its node serves, and a
// backup becomes a plain backend.
func TestEdgeUndoesHandEdits(t *testing.T) {
	edge, ops, balancer, _ := newEdgeTest(t)
	ctx := t.Context()
	if _, err := ops.submit(ctx, 3, "mariogk", "0000000000M44BFMMJRNPNN6BB", nodeOpRequest{Node: "ctl-1", Op: nodeOpDrain}); err != nil {
		t.Fatal(err)
	}
	if err := ops.pass(ctx); err != nil {
		t.Fatal(err)
	}
	balancer.mu.Lock()
	balancer.sets["terrabase"][0] = lb.Backend{IP: "10.0.0.11", Port: 9465}
	balancer.sets["ts-auth"][1] = balancer.sets["ts-auth"][1].Fenced(true, true)
	balancer.sets["ts-auth"][2] = lb.Backend{IP: "10.0.0.13", Port: 8080}.Shaped(1, true)
	balancer.mu.Unlock()
	edge.passes(t, 1)
	if backend, _ := backendOf(balancer, "terrabase", "10.0.0.11:9465"); backend.Serving() {
		t.Fatal("a drained node serves again")
	}
	if backend, _ := backendOf(balancer, "ts-auth", "10.0.0.13:8080"); func() bool { _, backup := backend.Shape(); return backup }() {
		t.Fatal("a backup stayed a backup")
	}
	edge.passes(t, 1)
	if backend, _ := backendOf(balancer, "ts-auth", "10.0.0.12:8080"); !backend.Serving() {
		t.Fatalf("a hand-drained serving node stayed out: %q", balancer.log)
	}
	if backend, _ := backendOf(balancer, "terrabase", "10.0.0.11:9465"); backend.Serving() {
		t.Fatal("the drained node returned")
	}
}

// A node without a replica loses its backend once it serves nothing; a
// backend that is no node of the cell, a node that serves without a
// replica and a renamed instance are left alone and reported once.
func TestEdgeRemovesUnallocatedAndReportsAmbiguous(t *testing.T) {
	edge, _, balancer, instances := newEdgeTest(t)
	addresses := maps.Clone(fenceAddresses)
	addresses["ctl-4"], addresses["ctl-5"] = "10.0.0.14", "10.0.0.15"
	spec, _ := edge.fence.spec()
	edge.fence.spec = func() (*cellspec.ReleaseFence, map[string]string) { return spec, addresses }
	balancer.mu.Lock()
	balancer.sets["ts-auth"] = append(balancer.sets["ts-auth"], lb.Backend{IP: "10.0.0.14", Port: 8080},
		lb.Backend{IP: "10.0.0.15", Port: 8080}, lb.Backend{IP: "10.9.9.9", Port: 8080})
	balancer.down["10.0.0.14:8080"] = true
	balancer.mu.Unlock()
	instances.names = map[string]string{"ctl-2": "gru-1-ctl-2"}
	edge.passes(t, 2)
	if _, ok := backendOf(balancer, "ts-auth", "10.0.0.14:8080"); ok {
		t.Fatal("an unallocated backend that serves nothing was kept")
	}
	for _, name := range []string{"10.0.0.15:8080", "10.9.9.9:8080"} {
		if _, ok := backendOf(balancer, "ts-auth", name); !ok {
			t.Fatalf("removed %s", name)
		}
	}
	alerts := strings.Join(slices.Sorted(maps.Keys(edge.alerted)), "\n")
	for _, want := range []string{"10.9.9.9:8080 is no node", "ctl-5 serves without a ts-auth replica", "0 instances are named ctl-2",
		"0 instances are named ctl-4"} {
		if !strings.Contains(alerts, want) {
			t.Errorf("alerts miss %q:\n%s", want, alerts)
		}
	}
}
